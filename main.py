from fastapi import FastAPI, Request
from pydantic import BaseModel

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello from Chatzon"}

class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

@app.post("/update-price")
async def update_price(request: PriceUpdateRequest):
    return {
        "message": f"Received price update for ASIN {request.asin}, SKU {request.sku}, new price: {request.new_price}"
    }
