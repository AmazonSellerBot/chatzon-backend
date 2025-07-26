from fastapi import FastAPI, Request
from pydantic import BaseModel
import os
import datetime
import requests
import json
import hashlib
import hmac
import base64

app = FastAPI()


class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float


def execute_signed_request(method, endpoint, body, query_string=""):
    region = "us-east-1"
    service = "execute-api"

    access_key = os.getenv("SPAPI_AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")
    role_arn = os.getenv("SPAPI_ROLE_ARN")
    seller_id = os.getenv("SELLER_ID")
    lwa_token = get_access_token()

    host = "sellingpartnerapi-na.amazon.com"
    uri = f"https://{host}{endpoint}"

    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')

    canonical_uri = endpoint
    canonical_querystring = query_string
    payload_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-access-token:{lwa_token}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"

    canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    k_date = sign(('AWS4' + secret_key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'aws4_request')
    signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Content-Type": "application/json",
        "x-amz-access-token": lwa_token,
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
        "Accept": "application/json"
    }

    response = requests.request(method, uri, headers=headers, data=body)
    return response


def get_access_token():
    client_id = os.getenv("LWA_CLIENT_ID")
    client_secret = os.getenv("LWA_CLIENT_SECRET")
    refresh_token = os.getenv("SPAPI_REFRESH_TOKEN")

    response = requests.post(
        "https://api.amazon.com/auth/o2/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )

    return response.json()["access_token"]


@app.post("/update-price")
def update_price(payload: PriceUpdateRequest):
    feed = {
        "sku": payload.sku,
        "productType": "PRODUCT",
        "price": {
            "listingPrice": {
                "amount": str(payload.new_price),
                "currency": "USD"
            }
        }
    }

    body = json.dumps(feed)

    endpoint = f"/listings/2021-08-01/items/{os.getenv('SELLER_ID')}/{payload.sku}/price"
    response = execute_signed_request("PUT", endpoint, body)

    return {
        "message": "Live price update sent to Amazon",
        "response": response.json()
    }
