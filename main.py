from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import os

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Chatzon backend is running."}

@app.get("/callback")
async def callback(request: Request):
    code = request.query_params.get("spapi_oauth_code")
    state = request.query_params.get("state")

    if not code:
        return JSONResponse(status_code=400, content={"error": "No authorization code found."})

    return {
        "message": "Authorization code received!",
        "authorization_code": code,
        "state": state
    }

@app.get("/env")
def read_env():
    return {
        "PORT": os.getenv("PORT"),
        "SPAPI_REFRESH_TOKEN": os.getenv("SPAPI_REFRESH_TOKEN"),
        "LWA_CLIENT_ID": os.getenv("LWA_CLIENT_ID"),
        "LWA_CLIENT_SECRET": os.getenv("LWA_CLIENT_SECRET"),
        "SELLER_ID": os.getenv("SELLER_ID")
    }
