from fastapi import FastAPI, Request
from pydantic import BaseModel
import os
import uuid
import datetime
import requests
import json
from typing import Literal
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

app = FastAPI()

# Load credentials from Railway variables (env)
LWA_CLIENT_ID = os.getenv("LWA_CLIENT_ID")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET")
SPAPI_REFRESH_TOKEN = os.getenv("SPAPI_REFRESH_TOKEN")
SPAPI_AWS_ACCESS_KEY_ID = os.getenv("SPAPI_AWS_ACCESS_KEY_ID")
SPAPI_AWS_SECRET_ACCESS_KEY = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")
SELLER_ID = os.getenv("SELLER_ID")

# SP-API endpoints
REGION = "us-east-1"
ENDPOINT = "https://sellingpartnerapi-na.amazon.com"

class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

@app.post("/update-price")
async def update_price(data: PriceUpdateRequest):
    # Step 1: Get Access Token
    auth_url = "https://api.amazon.com/auth/o2/token"
    auth_payload = {
        "grant_type": "refresh_token",
        "refresh_token": SPAPI_REFRESH_TOKEN,
        "client_id": LWA_CLIENT_ID,
        "client_secret": LWA_CLIENT_SECRET,
    }
    auth_response = requests.post(auth_url, data=auth_payload)
    if auth_response.status_code != 200:
        return {"error": "Failed to get access token", "details": auth_response.text}
    access_token = auth_response.json()["access_token"]

    # Step 2: Build Listings PATCH feed
    url = f"{ENDPOINT}/listings/2021-08-01/items/{SELLER_ID}/{data.sku}"
    feed_body = {
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/standard_price",
                "value": [
                    {
                        "currency": "USD",
                        "value": data.new_price
                    }
                ]
            }
        ]
    }

    # Step 3: Sign the request
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-amz-access-token": access_token
    }

    request = AWSRequest(
        method="PATCH",
        url=url,
        data=json.dumps(feed_body),
        headers=headers
    )

    credentials = Credentials(SPAPI_AWS_ACCESS_KEY_ID, SPAPI_AWS_SECRET_ACCESS_KEY)
    SigV4Auth(credentials, "execute-api", REGION).add_auth(request)

    # Step 4: Make request to Amazon SP-API
    session = requests.Session()
    response = session.send(request.prepare())

    # Step 5: Return response
    try:
        return {
            "asin": data.asin,
            "sku": data.sku,
            "new_price": data.new_price,
            "status": "success" if response.status_code == 200 else "error",
            "amazon_response": response.json()
        }
    except Exception:
        return {
            "asin": data.asin,
            "sku": data.sku,
            "new_price": data.new_price,
            "status": "error",
            "raw_response": response.text
        }
