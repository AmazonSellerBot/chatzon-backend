from fastapi import FastAPI
from pydantic import BaseModel
import os
import datetime
import hashlib
import hmac
import uuid
import requests
import json

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Chatzon backend is live!"}


class PriceUpdateRequest(BaseModel):
    asin: str
    new_price: float


def sign_request(method, endpoint, access_token, payload, path, query_string=""):
    host = "sellingpartnerapi-na.amazon.com"
    region = "us-west-2"
    service = "execute-api"

    amz_date = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    date_stamp = datetime.datetime.utcnow().strftime("%Y%m%d")

    canonical_uri = path
    canonical_querystring = query_string
    canonical_headers = f"host:{host}\nx-amz-access-token:{access_token}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    secret = os.environ["SPAPI_AWS_SECRET_ACCESS_KEY"]
    access = os.environ["SPAPI_AWS_ACCESS_KEY_ID"]

    kDate = sign(("AWS4" + secret).encode("utf-8"), date_stamp)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, service)
    kSigning = sign(kService, "aws4_request")

    signature = hmac.new(kSigning, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={access}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Content-Type": "application/json",
        "x-amz-access-token": access_token,
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
        "host": host,
    }

    return headers


@app.post("/update-price")
def update_price(data: PriceUpdateRequest):
    asin = data.asin
    new_price = data.new_price
    sku = asin  # assuming SKU = ASIN for now

    # Credentials
    refresh_token = os.environ["SPAPI_REFRESH_TOKEN"]
    lwa_client_id = os.environ["LWA_CLIENT_ID"]
    lwa_client_secret = os.environ["LWA_CLIENT_SECRET"]
    aws_access_key = os.environ["SPAPI_AWS_ACCESS_KEY_ID"]
    aws_secret_key = os.environ["SPAPI_AWS_SECRET_ACCESS_KEY"]
    seller_id = os.environ["SELLER_ID"]

    # Get LWA Access Token
    lwa_resp = requests.post(
        "https://api.amazon.com/auth/o2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": lwa_client_id,
            "client_secret": lwa_client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    if lwa_resp.status_code != 200:
        return {"error": "Failed to get access token", "details": lwa_resp.text}

    access_token = lwa_resp.json()["access_token"]

    # Price update payload
    payload = {
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/standard_price",
                "value": [
                    {"currency": "USD", "amount": new_price}
                ]
            }
        ]
    }

    path = f"/listings/2021-08-01/items/{seller_id}/{sku}"
    url = f"https://sellingpartnerapi-na.amazon.com{path}"

    headers = sign_request(
        method="PATCH",
        endpoint="sellingpartnerapi-na.amazon.com",
        access_token=access_token,
        payload=json.dumps(payload),
        path=path
    )

    response = requests.patch(url, headers=headers, json=payload)

    return {
        "asin": asin,
        "sku": sku,
        "new_price": new_price,
        "status": "success" if response.status_code < 300 else "error",
        "amazon_response": response.json()
    }
