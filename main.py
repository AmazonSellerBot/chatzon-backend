from fastapi import FastAPI, Request
from pydantic import BaseModel
from fastapi.responses import JSONResponse
import os

app = FastAPI()

# Root route (for health check)
@app.get("/")
def read_root():
    return {"message": "Welcome to Chatzon backend!"}

# Example model for incoming update-price request
class PriceUpdate(BaseModel):
    asin: str
    sku: str
    new_price: float

# POST route to simulate a price update
@app.post("/update-price")
async def update_price(payload: PriceUpdate):
    return {
        "status": "success",
        "asin": payload.asin,
        "sku": payload.sku,
        "new_price": payload.new_price
    }
