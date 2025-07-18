from fastapi import FastAPI, Request
from pydantic import BaseModel
import uuid
import datetime
import json
import requests
import os
import base64
import hashlib
import hmac

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "ChatZon Backend is running 🚀"}

class PriceUpdate(BaseModel):
    asin: str
    price: float

@app.post("/update-price")
def update_price(data: PriceUpdate):
    # Setup
    endpoint = "https://sellingpartnerapi-na.amazon.com"
    path = f"/feeds/2021-06-30/feeds"
    full_url = endpoint + path

    # Load credentials from environment
    LWA_CLIENT_ID = os.environ["LWA_CLIENT_ID"]
    LWA_CLIENT_SECRET = os.environ["LWA_CLIENT_SECRET"]
    LWA_REFRESH_TOKEN = os.environ["LWA_REFRESH_TOKEN"]
    AWS_ACCESS_KEY = os.environ["SPAPI_AWS_ACCESS_KEY_ID"]
    AWS_SECRET_KEY = os.environ["SPAPI_AWS_SECRET_ACCESS_KEY"]
    ROLE_ARN = os.environ.get("SPAPI_ROLE_ARN", "arn:aws:iam::484907493961:role/CHATgpttoAmazon")
    SELLER_ID = os.environ.get("SELLER_ID", "A2NHTP38YVLBHH")
    MARKETPLACE_ID = os.environ.get("MARKETPLACE_ID", "ATVPDKIKX0DER")

    # Create the feed content
    feed_content = {
        "sku": f"SKU-{data.asin}",
        "asin": data.asin,
        "price": data.price,
        "currency": "USD"
    }

    # Convert to Amazon JSON_LISTINGS_FEED format
    feed_document = {
        "productType": "PRODUCT",
        "operationType": "UPDATE",
        "attributes": {
            "standard_product_id": {
                "type": "ASIN",
                "value": data.asin
            },
            "list_price": {
                "currency": "USD",
                "amount": data.price
            }
        }
    }

    # Save JSON feed to a string
    feed_json = json.dumps([feed_document])

    # Normally, you'd now: (1) create document, (2) upload feed content, (3) submit feed
    # Here we'll just return the payload for now
    return {
        "message": "This is a placeholder — your backend is live!",
        "asin": data.asin,
        "price": data.price,
        "payload": json.loads(feed_json)
    }
