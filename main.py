from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import json

from execute_signed_request import execute_signed_request
from gpt_advisor import get_suggestions

app = FastAPI()

# ----- Request schema -----
class PriceUpdate(BaseModel):
    asin: str
    price: float
    original_price: Optional[float] = None  # optional but helpful

# ----- Health check -----
@app.get("/")
def root():
    return {"message": "Amazon Seller Bot API is live and connected."}

# ----- Price update endpoint -----
@app.post("/update-price")
def update_price(data: PriceUpdate):
    try:
        # Replace this with actual SKU lookup logic if needed
        sku = data.asin

        # Build JSON_LISTINGS_FEED body
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

        # Submit the feed to Amazon SP-API
        amazon_response = execute_signed_request(
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

        # Intelligent advice for the user
        suggestions = get_suggestions("price_update", {
            "asin": data.asin,
            "price": data.price,
            "original_price": data.original_price
        })

        return {
            "status": "success",
            "asin": data.asin,
            "price": data.price,
            "amazon_response": amazon_response,
            "suggestions": suggestions
        }

    except Exception as e:
        if str(e) == "reauth_required":
            # Send user to reauthorize via OAuth
            return {
                "status": "reauth_required",
                "message": "Your Amazon connection has expired. Please reauthorize your account.",
                "reauth_link": (
                    "https://sellercentral.amazon.com/apps/authorize/consent"
                    "?application_id=amzn1.application-oa2-client.3afbc4dd12bc43ca9c2038bad20d89b2"
                    "&state=test-client"
                    "&redirect_uri=https://example.com/callback"
                )
            }
        raise HTTPException(status_code=500, detail=str(e))
