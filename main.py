import os
import json
import uuid
import hmac
import hashlib
import datetime
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()


# --------- MODEL ---------
class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float


# --------- ENVIRONMENT CHECK ---------
def get_env(var):
    value = os.getenv(var)
    if not value:
        raise EnvironmentError(f"Missing required environment variable: {var}")
    return value


# Load once
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


# --------- AUTH ---------
def get_access_token():
    res = requests.post(
        "https://api.amazon.com/auth/o2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": ENV["REFRESH_TOKEN"],
            "client_id": ENV["CLIENT_ID"],
            "client_secret": ENV["CLIENT_SECRET"]
        },
    )
    res.raise_for_status()
    return res.json()["access_token"]


# --------- SIGNING ---------
def sign_request(method, endpoint, body, access_token, region="us-east-1", service="execute-api"):
    host = "sellingpartnerapi-na.amazon.com"
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_uri = endpoint
    canonical_querystring = ""
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical_headers = f"host:{host}\n" + f"x-amz-access-token:{access_token}\n" + f"x-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"
    canonical_request = (
        f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + ENV["AWS_SECRET_KEY"]).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={ENV['AWS_ACCESS_KEY']}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Content-Type": "application/json",
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Access-Token": access_token,
        "Authorization": authorization_header,
    }


# --------- ROUTE ---------
@app.post("/update-price")
def update_price(req: PriceUpdateRequest):
    try:
        access_token = get_access_token()

        # STEP 1: Create feed document
        doc_body = {"contentType": "application/json; charset=UTF-8"}
        doc_headers = sign_request("POST", "/feeds/2021-06-30/documents", json.dumps(doc_body), access_token)

        doc_res = requests.post(
            "https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/documents",
            headers=doc_headers,
            json=doc_body
        )
        doc_res.raise_for_status()
        doc_json = doc_res.json()

        # Handle missing documentId
        if "documentId" not in doc_json or "url" not in doc_json:
            return JSONResponse(status_code=500, content={
                "status": "error",
                "message": "Missing documentId or upload URL from SP-API",
                "raw_response": doc_json
            })

        document_id = doc_json["documentId"]
        upload_url = doc_json["url"]

        # STEP 2: Build feed content
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
                "price": {
                    "currency": "USD",
                    "amount": str(req.new_price)
                },
                "fulfillment_availability": [{
                    "fulfillment_channel_code": "DEFAULT",
                    "quantity": 1
                }]
            }
        }]

        upload_res = requests.put(upload_url, headers={"Content-Type": "application/json"}, data=json.dumps(feed_data))
        upload_res.raise_for_status()

        # STEP 3: Submit feed
        feed_body = {
            "feedType": "JSON_LISTINGS_FEED",
            "marketplaceIds": [ENV["MARKETPLACE_ID"]],
            "inputFeedDocumentId": document_id
        }

        feed_headers = sign_request("POST", "/feeds/2021-06-30/feeds", json.dumps(feed_body), access_token)
        feed_res = requests.post(
            "https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/feeds",
            headers=feed_headers,
            json=feed_body
        )
        feed_res.raise_for_status()
        feed_id = feed_res.json().get("feedId")

        return {
            "status": "success",
            "asin": req.asin,
            "sku": req.sku,
            "new_price": req.new_price,
            "feedId": feed_id
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

