import os
import json
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from starlette.responses import JSONResponse
import requests
import uuid
import datetime
import hashlib
import hmac

app = FastAPI()

class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

# Load environment variables
required_env_vars = [
    "SPAPI_REFRESH_TOKEN", "SPAPI_LWA_CLIENT_ID", "SPAPI_LWA_CLIENT_SECRET",
    "SPAPI_ROLE_ARN", "SPAPI_AWS_ACCESS_KEY_ID", "SPAPI_AWS_SECRET_ACCESS_KEY",
    "SPAPI_SELLER_ID", "SPAPI_MARKETPLACE_ID"
]

def get_env(var):
    value = os.getenv(var)
    if not value:
        raise EnvironmentError(f"Missing required environment variable: {var}")
    return value

credentials = {var: get_env(var) for var in required_env_vars}

# === SIGNING + AUTH ===
def get_access_token():
    url = "https://api.amazon.com/auth/o2/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": credentials["SPAPI_REFRESH_TOKEN"],
        "client_id": credentials["SPAPI_LWA_CLIENT_ID"],
        "client_secret": credentials["SPAPI_LWA_CLIENT_SECRET"]
    }
    response = requests.post(url, data=payload)
    response.raise_for_status()
    return response.json()["access_token"]

def sign_request(method, endpoint, body, access_token, region="us-east-1", service="execute-api"):
    host = "sellingpartnerapi-na.amazon.com"
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_uri = endpoint
    canonical_querystring = ""
    payload_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()

    canonical_headers = f"host:{host}\n" + f"x-amz-access-token:{access_token}\n" + f"x-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"
    canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign(key, msg): return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    k_date = sign(("AWS4" + credentials["SPAPI_AWS_SECRET_ACCESS_KEY"]).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")

    signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={credentials['SPAPI_AWS_ACCESS_KEY_ID']}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Content-Type": "application/json",
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Access-Token": access_token,
        "Authorization": authorization_header
    }

    return headers

# === MAIN ENDPOINT ===
@app.post("/update-price")
async def update_price(data: PriceUpdateRequest):
    try:
        access_token = get_access_token()

        feed_doc_body = {
            "contentType": "application/json; charset=UTF-8"
        }

        doc_response = requests.post(
            "https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/documents",
            headers=sign_request(
                method="POST",
                endpoint="/feeds/2021-06-30/documents",
                body=json.dumps(feed_doc_body),
                access_token=access_token
            ),
            json=feed_doc_body
        )
        doc_response.raise_for_status()
        doc = doc_response.json()

        url = doc["url"]
        document_id = doc["documentId"]

        # Build feed
        price_feed = {
            "sku": data.sku,
            "productType": "PRODUCT",
            "attributes": {
                "standard_product_id": {
                    "value": data.asin,
                    "type": "ASIN"
                },
                "condition_type": {
                    "value": "new_new"
                },
                "price": {
                    "currency": "USD",
                    "amount": str(data.new_price)
                },
                "fulfillment_availability": [{
                    "fulfillment_channel_code": "DEFAULT",
                    "quantity": 1
                }]
            }
        }

        requests.put(url, data=json.dumps([price_feed]), headers={"Content-Type": "application/json"}).raise_for_status()

        # Submit feed
        feed_body = {
            "feedType": "POST_PRODUCT_PRICING_DATA",
            "marketplaceIds": [credentials["SPAPI_MARKETPLACE_ID"]],
            "inputFeedDocumentId": document_id
        }

        feed_response = requests.post(
            "https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/feeds",
            headers=sign_request(
                method="POST",
                endpoint="/feeds/2021-06-30/feeds",
                body=json.dumps(feed_body),
                access_token=access_token
            ),
            json=feed_body
        )
        feed_response.raise_for_status()

        return JSONResponse(content={
            "status": "success",
            "asin": data.asin,
            "sku": data.sku,
            "new_price": data.new_price,
            "feedId": feed_response.json().get("feedId")
        })

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})
