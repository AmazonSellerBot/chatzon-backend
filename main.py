import os
import json
import uuid
import hmac
import hashlib
import datetime
import requests
from fastapi import FastAPI, Query
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()

# === Models ===
class ListingUpdateRequest(BaseModel):
    asin: str
    sku: str
    field: str
    value: str | float | list[str]

class PriceUpdateFastRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

# === Environment ===
def get_env(var):
    value = os.getenv(var)
    if not value:
        raise EnvironmentError(f"Missing env var: {var}")
    return value

ENV = {
    "REFRESH_TOKEN": get_env("SPAPI_REFRESH_TOKEN"),
    "CLIENT_ID": get_env("SPAPI_LWA_CLIENT_ID"),
    "CLIENT_SECRET": get_env("SPAPI_LWA_CLIENT_SECRET"),
    "ROLE_ARN": get_env("SPAPI_ROLE_ARN"),
    "AWS_ACCESS_KEY": get_env("SPAPI_AWS_ACCESS_KEY_ID"),
    "AWS_SECRET_KEY": get_env("SPAPI_AWS_SECRET_ACCESS_KEY"),
    "SELLER_ID": get_env("SPAPI_SELLER_ID"),
    "MARKETPLACE_ID": get_env("SPAPI_MARKETPLACE_ID"),
}

# === Auth ===
def get_access_token():
    res = requests.post(
        "https://api.amazon.com/auth/o2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": ENV["REFRESH_TOKEN"],
            "client_id": ENV["CLIENT_ID"],
            "client_secret": ENV["CLIENT_SECRET"]
        }
    )
    res.raise_for_status()
    return res.json()["access_token"]

# === Signing ===
def sign_request(method, endpoint, body, access_token, region="us-east-1", service="execute-api"):
    host = "sellingpartnerapi-na.amazon.com"
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-access-token:{access_token}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"
    canonical_request = (
        f"{method}\n{endpoint}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + ENV["AWS_SECRET_KEY"]).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={ENV['AWS_ACCESS_KEY']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Content-Type": "application/json",
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Access-Token": access_token,
        "Authorization": auth_header,
    }

# === Utility: Build attributes for listing feed ===
def build_listing_attributes(field, value):
    attributes = {}
    if field == "title":
        attributes["item_name"] = {"value": value}
    elif field == "bullet_points":
        attributes["bullet_point"] = [{"value": bp} for bp in value]
    elif field == "price":
        attributes["price"] = {"currency": "USD", "amount": str(value)}
    elif field == "search_terms":
        attributes["generic_keyword"] = [{"value": term} for term in value]
    else:
        raise ValueError(f"Unsupported field: {field}")
    return attributes

# === Route: /update-listing ===
@app.post("/update-listing")
def update_listing(req: ListingUpdateRequest):
    try:
        access_token = get_access_token()

        doc_body = {"contentType": "application/json; charset=UTF-8"}
        doc_headers = sign_request("POST", "/feeds/2021-06-30/documents", json.dumps(doc_body), access_token)
        doc_res = requests.post("https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/documents", headers=doc_headers, json=doc_body)
        doc_res.raise_for_status()
        doc_json = doc_res.json()
        document_id = doc_json["feedDocumentId"]
        upload_url = doc_json["url"]

        attributes = build_listing_attributes(req.field, req.value)
        feed_data = [{
            "sku": req.sku,
            "productType": "PRODUCT",
            "attributes": {
                "standard_product_id": {
                    "value": req.asin,
                    "type": "ASIN"
                },
                "condition_type": {
                    "value": "new_new"
                },
                **attributes
            }
        }]

        upload_res = requests.put(upload_url, headers={"Content-Type": "application/json; charset=UTF-8"}, data=json.dumps(feed_data))
        upload_res.raise_for_status()

        feed_body = {
            "feedType": "JSON_LISTINGS_FEED",
            "marketplaceIds": [ENV["MARKETPLACE_ID"]],
            "inputFeedDocumentId": document_id
        }
        feed_headers = sign_request("POST", "/feeds/2021-06-30/feeds", json.dumps(feed_body), access_token)
        feed_res = requests.post("https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/feeds", headers=feed_headers, json=feed_body)
        feed_res.raise_for_status()
        feed_id = feed_res.json()["feedId"]

        return {
            "status": "success",
            "type": "listing_update",
            "asin": req.asin,
            "field": req.field,
            "value": req.value,
            "feedId": feed_id
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

# === Route: /update-price-fast ===
@app.post("/update-price-fast")
def update_price_fast(req: PriceUpdateFastRequest):
    try:
        access_token = get_access_token()

        doc_body = {"contentType": "application/json; charset=UTF-8"}
        doc_headers = sign_request("POST", "/feeds/2021-06-30/documents", json.dumps(doc_body), access_token)
        doc_res = requests.post("https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/documents", headers=doc_headers, json=doc_body)
        doc_res.raise_for_status()
        doc_json = doc_res.json()
        document_id = doc_json["feedDocumentId"]
        upload_url = doc_json["url"]

        feed_data = [{
            "sku": req.sku,
            "standard_price": {
                "currency": "USD",
                "amount": str(req.new_price)
            }
        }]

        upload_res = requests.put(upload_url, headers={"Content-Type": "application/json; charset=UTF-8"}, data=json.dumps(feed_data))
        upload_res.raise_for_status()

        feed_body = {
            "feedType": "POST_PRODUCT_PRICING_DATA",
            "marketplaceIds": [ENV["MARKETPLACE_ID"]],
            "inputFeedDocumentId": document_id
        }

        feed_headers = sign_request("POST", "/feeds/2021-06-30/feeds", json.dumps(feed_body), access_token)
        feed_res = requests.post("https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/feeds", headers=feed_headers, json=feed_body)
        feed_res.raise_for_status()
        feed_id = feed_res.json()["feedId"]

        return {
            "status": "success",
            "type": "price_update",
            "asin": req.asin,
            "sku": req.sku,
            "new_price": req.new_price,
            "feedId": feed_id
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

# === Route: /feed-status ===
@app.get("/feed-status")
def feed_status(feedId: str = Query(...)):
    try:
        access_token = get_access_token()
        headers = sign_request("GET", f"/feeds/2021-06-30/feeds/{feedId}", "", access_token)
        res = requests.get(f"https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/feeds/{feedId}", headers=headers)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})
