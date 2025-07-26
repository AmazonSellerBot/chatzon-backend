from fastapi import FastAPI, Request
from pydantic import BaseModel
import os
import requests
import datetime
import hashlib
import hmac
import base64
from urllib.parse import quote, urlencode

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Chatzon backend is live!"}


class PriceUpdateRequest(BaseModel):
    asin: str
    new_price: float


@app.post("/update-price")
def update_price(data: PriceUpdateRequest):
    asin = data.asin
    new_price = data.new_price

    # Read credentials from Railway variables
    refresh_token = os.environ["SPAPI_REFRESH_TOKEN"]
    lwa_client_id = os.environ["LWA_CLIENT_ID"]
    lwa_client_secret = os.environ["LWA_CLIENT_SECRET"]
    aws_access_key = os.environ["SPAPI_AWS_ACCESS_KEY_ID"]
    aws_secret_key = os.environ["SPAPI_AWS_SECRET_ACCESS_KEY"]
    seller_id = os.environ["SELLER_ID"]

    # Step 1: Get access token
    auth_response = requests.post(
        "https://api.amazon.com/auth/o2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": lwa_client_id,
            "client_secret": lwa_client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    access_token = auth_response.json()["access_token"]

    # Step 2: Build the feed body
    now = datetime.datetime.utcnow().isoformat() + "Z"
    feed_document = {
        "sku": f"{asin}-SKU",
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/standard_price",
                "value": [
                    {
                        "currency": "USD",
                        "amount": str(new_price)
                    }
                ]
            }
        ]
    }

    # Step 3: Send listing update (placeholder for signed request)
    return {
        "status": "ready",
        "asin": asin,
        "new_price": new_price,
        "note": "Signed feed request logic goes here"
    }
