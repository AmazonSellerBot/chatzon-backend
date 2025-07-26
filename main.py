from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import requests
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()


class PriceUpdate(BaseModel):
    asin: str
    sku: str
    new_price: float


@app.get("/")
def root():
    return {"message": "Chatzon Backend is live!"}


@app.post("/update-price")
def update_price(payload: PriceUpdate):
    access_token = os.getenv("LWA_ACCESS_TOKEN")
    seller_id = os.getenv("SELLER_ID")
    marketplace_id = os.getenv("MARKETPLACE_ID")

    if not all([access_token, seller_id, marketplace_id]):
        raise HTTPException(status_code=500, detail="Missing environment variables.")

    url = f"https://sellingpartnerapi-na.amazon.com/listings/2021-08-01/items/{seller_id}/{payload.sku}/pricing"
    headers = {
        "x-amz-access-token": access_token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    body = {
        "pricing": {
            "price": {
                "currency": "USD",
                "amount": payload.new_price
            }
        }
    }

    response = requests.put(url, json=body, headers=headers)

    if response.status_code != 200:
        return {
            "asin": payload.asin,
            "sku": payload.sku,
            "new_price": payload.new_price,
            "status": "error",
            "amazon_response": response.json()
        }

    return {
        "asin": payload.asin,
        "sku": payload.sku,
        "new_price": payload.new_price,
        "status": "success",
        "amazon_response": response.json()
    }
