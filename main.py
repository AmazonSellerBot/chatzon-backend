from fastapi import FastAPI
from pydantic import BaseModel
import os
import json
from typing import List
from utils import execute_signed_request

app = FastAPI()

# ---------- Price Update ----------
class PriceUpdateRequest(BaseModel):
    sku: str
    price: float
    currency: str = "USD"
    marketplaceId: str = "ATVPDKIKX0DER"  # US default

@app.post("/update-price-fast")
def update_price_fast(data: PriceUpdateRequest):
    sku = data.sku
    price = data.price
    currency = data.currency
    marketplace_id = data.marketplaceId

    path = f"/listings/2021-08-01/items/{os.getenv('SELLER_ID')}/{sku}"
    query_params = {
        "marketplaceIds": marketplace_id
    }

    price_payload = {
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/standard_price",
                "value": [
                    {
                        "currency": currency,
                        "amount": str(price)
                    }
                ]
            }
        ]
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = execute_signed_request(
        method="PATCH",
        endpoint="https://sellingpartnerapi-na.amazon.com",
        path=path,
        params=query_params,
        data=json.dumps(price_payload),
        headers=headers
    )

    return {
        "status": "success" if response.status_code in [200, 202] else "error",
        "code": response.status_code,
        "response": response.json()
    }

# ---------- Listing Content Update ----------
class ListingUpdateRequest(BaseModel):
    sku: str
    title: str = None
    bullets: List[str] = []
    description: str = None
    search_terms: List[str] = []
    marketplaceId: str = "ATVPDKIKX0DER"

@app.post("/update-listing")
def update_listing(data: ListingUpdateRequest):
    sku = data.sku
    marketplace_id = data.marketplaceId

    path = f"/listings/2021-08-01/items/{os.getenv('SELLER_ID')}/{sku}"
    query_params = {
        "marketplaceIds": marketplace_id
    }

    patches = []

    if data.title:
        patches.append({
            "op": "replace",
            "path": "/attributes/item_name",
            "value": [{"value": data.title}]
        })

    if data.bullets:
        patches.append({
            "op": "replace",
            "path": "/attributes/bullet_point",
            "value": [{"value": b} for b in data.bullets]
        })

    if data.description:
        patches.append({
            "op": "replace",
            "path": "/attributes/product_description",
            "value": [{"value": data.description}]
        })

    if data.search_terms:
        patches.append({
            "op": "replace",
            "path": "/attributes/generic_keyword",
            "value": [{"value": t} for t in data.search_terms]
        })

    if not patches:
        return {"status": "error", "message": "No updates provided."}

    payload = {
        "productType": "PRODUCT",
        "patches": patches
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = execute_signed_request(
        method="PATCH",
        endpoint="https://sellingpartnerapi-na.amazon.com",
        path=path,
        params=query_params,
        data=json.dumps(payload),
        headers=headers
    )

    return {
        "status": "success" if response.status_code in [200, 202] else "error",
        "code": response.status_code,
        "response": response.json()
    }

# ---------- Root Test ----------
@app.get("/")
def root():
    return {"message": "Chatzon Listings API is live."}
 
