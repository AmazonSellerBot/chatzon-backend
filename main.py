from fastapi import FastAPI
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to Chatzon"}

class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

@app.post("/update-price")
def update_price(request: PriceUpdateRequest):
    return {
        "message": "Price update simulated",
        "asin": request.asin,
        "sku": request.sku,
        "new_price": request.new_price
    }
