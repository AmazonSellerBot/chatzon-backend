from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import json
from execute_signed_request import execute_signed_request

app = FastAPI()

class PriceUpdate(BaseModel):
    asin: str
    price: float

@app.get("/")
def read_root():
    return {"message": "App is live and connected to SP-API"}

@app.post("/update-price")
def update_price(data: PriceUpdate):
    try:
        sku = data.asin  # Replace with actual SKU if needed

        feed_body = {
            "skus": {
                sku: {
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
            }
        }

        response = execute_signed_request(
            method="POST",
            endpoint="/feeds/2021-06-30/feeds",
            body={
                "feedType": "JSON_LISTINGS_FEED",
                "marketplaceIds": ["ATVPDKIKX0DER"],
                "inputFeedDocument": {
                    "contentType": "application/json",
                    "body": json.dumps(feed_body)
                }
            }
        )

        return {
            "status": "submitted",
            "asin": data.asin,
            "price": data.price,
            "amazon_response": response
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
