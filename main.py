from fastapi import FastAPI, Request
from pydantic import BaseModel
import requests
import os

app = FastAPI()

# === AMAZON CREDS FROM ENV ===
SELLER_ID = os.getenv("SELLER_ID")
MARKETPLACE_ID = os.getenv("MARKETPLACE_ID")
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")  # make sure this is set in Railway

# === INPUT MODEL ===
class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    price: float

# === ENDPOINT ===
@app.post("/update-price-fast")
async def update_price_fast(data: PriceUpdateRequest):
    try:
        headers = {
            "Content-Type": "application/json",
            "x-amz-access-token": ACCESS_TOKEN,
        }

        payload = {
            "productType": "PRODUCT",
            "patches": [
                {
                    "op": "replace",
                    "path": "/attributes/standard_price",
                    "value": [
                        {
                            "currency": "USD",
                            "value": str(data.price)
                        }
                    ]
                }
            ]
        }

        url = f"https://sellingpartnerapi-na.amazon.com/listings/2021-08-01/items/{SELLER_ID}/{data.sku}"

        params = {
            "marketplaceIds": MARKETPLACE_ID
        }

        response = requests.patch(url, headers=headers, json=payload, params=params)

        return {
            "status": "success",
            "amazon_status_code": response.status_code,
            "response": response.json()
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/")
def root():
    return {"status": "ok", "message": "Chatzon backend is live."}
