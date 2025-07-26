from fastapi import FastAPI, Request
from pydantic import BaseModel
import os

app = FastAPI()

# Root route to verify the app is live
@app.get("/")
def root():
    return {"message": "Welcome to Chatzon"}

# Update price request model
class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

@app.post("/update-price")
def update_price(req: PriceUpdateRequest):
    # Simulate response for now
    return {
        "status": "success",
        "asin": req.asin,
        "sku": req.sku,
        "new_price": req.new_price,
        "message": "Price update request received"
    }
