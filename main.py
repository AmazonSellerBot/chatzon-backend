from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class PriceUpdate(BaseModel):
    asin: str
    price: float

@app.get("/")
def read_root():
    return {"message": "App is live!"}

@app.post("/update-price")
def update_price(data: PriceUpdate):
    return {
        "status": "success",
        "asin": data.asin,
        "price": data.price
    }
