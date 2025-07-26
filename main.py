from fastapi import FastAPI, Request
from pydantic import BaseModel
import os

app = FastAPI()

# Data model for the incoming price update request
class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

@app.get("/")
async def root():
    return {"message": "Chatzon backend is live."}

@app.post("/update-price")
async def update_price(payload: PriceUpdateRequest):
    return {
        "message": "Price update simulated",
        "asin": payload.asin,
        "sku": payload.sku,
        "new_price": payload.new_price
    }
