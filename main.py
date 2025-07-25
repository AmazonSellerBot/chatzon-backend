from fastapi import FastAPI, Request
from pydantic import BaseModel
import os
import uuid
import json
from execute_signed_request import execute_signed_request

app = FastAPI()

class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    price: float

@app.get("/")
def root():
    return {"message": "Chatzon backend is live."}

@app.post("/update-price")
def update_price(payload: PriceUpdateRequest):
    asin = payload.asin
    sku = payload.sku
    price = payload.price

    seller_id = os.getenv("SELLER_ID")

    feed_document_id = str(uuid.uuid4())
    feed_data = {
        "sku": sku,
        "asin": asin,
        "price": price
    }

    # Build the SP-API payload
    listings_feed = {
        "productType": "PRODUCT",
        "requirements": "LISTING",
        "attributes": {
            "standard_product_id": {
                "value": asin,
                "type": "ASIN"
            },
            "sku": sku,
            "product_site_launch_date": "2025-01-01T00:00:00Z",
            "list_price": {
                "currency": "USD",
                "amount": price
            }
        }
    }

    # SP-API Endpoint for listing update
    endpoint = f"/listings/2021-08-01/items/{seller_id}/{sku}"
    method = "PATCH"
    body = {
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/list_price",
                "value": {
                    "currency": "USD",
                    "amount": price
                }
            }
        ]
    }

    try:
        response = execute_signed_request(
            method=method,
            endpoint=endpoint,
            body=body
        )
        return {
            "status": "success",
            "asin": asin,
            "sku": sku,
            "price": price,
            "response": response
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
