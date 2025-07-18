from fastapi import FastAPI, Request
from pydantic import BaseModel
import uvicorn
import os
import requests
import json
import datetime
import hashlib
import hmac

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "ChatZon Backend is running 🚀"}

class PriceUpdateRequest(BaseModel):
    asin: str
    sku: str
    marketplace_id: str
    price: float

@app.post("/update-price")
async def update_price(req: PriceUpdateRequest):
    # Step 1: Auth
    lwa_refresh_token = os.environ.get("LWA_REFRESH_TOKEN")
    lwa_client_id = os.environ.get("LWA_CLIENT_ID")
    lwa_client_secret = os.environ.get("LWA_CLIENT_SECRET")
    access_token = get_access_token(lwa_refresh_token, lwa_client_id, lwa_client_secret)

    # Step 2: Signed request
    endpoint = f"/listings/2021-08-01/items/{req.sku}/pricing"
    body = {
        "productType": "PRODUCT",
        "patches": [{
            "op": "replace",
            "path": "/attributes/standard_price",
            "value": [{
                "currency": "USD",
                "amount": req.price
            }]
        }]
    }

    headers = sign_request(
        method="PATCH",
        endpoint=endpoint,
        access_token=access_token,
        body=json.dumps(body)
    )

    url = f"https://sellingpartnerapi-na.amazon.com{endpoint}?marketplaceIds={req.marketplace_id}"
    response = requests.patch(url, headers=headers, data=json.dumps(body))

    return {
        "status_code": response.status_code,
        "response": response.json()
    }

def get_access_token(refresh_token, client_id, client_secret):
    url = "https://api.amazon.com/auth/o2/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret
    }
    r = requests.post(url, data=payload)
    return r.json()["access_token"]

def sign_request(method, endpoint, access_token, body=""):
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    role_credentials = {
        "access_key": os.environ.get("SPAPI_AWS_ACCESS_KEY_ID"),
        "secret_key": os.environ.get("SPAPI_AWS_SECRET_ACCESS_KEY"),
        "session_token": os.environ.get("SPAPI_AWS_SESSION_TOKEN")  # Optional, for temporary creds
    }

    region = "us-east-1"
    service = "execute-api"
    url = f"https://sellingpartnerapi-na.amazon.com{endpoint}"

    headers = {
        "host": "sellingpartnerapi-na.amazon.com",
        "x-amz-access-token": access_token,
        "content-type": "application/json"
    }

    request = AWSRequest(
        method=method,
        url=url,
        data=body,
        headers=headers
    )

    SigV4Auth(
        Credentials(
            role_credentials["access_key"],
            role_credentials["secret_key"],
            role_credentials.get("session_token")
        ),
        service,
        region
    ).add_auth(request)

    return dict(request.headers)

