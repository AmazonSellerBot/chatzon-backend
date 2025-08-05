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
def env_check():
    return {
        "PORT": os.getenv("PORT"),
        "SPAPI_REFRESH_TOKEN": os.getenv("SPAPI_REFRESH_TOKEN"),
        "SPAPI_AWS_ACCESS_KEY_ID": os.getenv("SPAPI_AWS_ACCESS_KEY_ID"),
        "SPAPI_AWS_SECRET_ACCESS_KEY": os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY"),
        "SPAPI_LWA_CLIENT_ID": os.getenv("SPAPI_LWA_CLIENT_ID"),
        "SPAPI_LWA_CLIENT_SECRET": os.getenv("SPAPI_LWA_CLIENT_SECRET"),
        "SPAPI_ROLE_ARN": os.getenv("SPAPI_ROLE_ARN"),
        "SPAPI_SELLER_ID": os.getenv("SPAPI_SELLER_ID"),
        "SPAPI_MARKETPLACE_ID": os.getenv("SPAPI_MARKETPLACE_ID")
    }
