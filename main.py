import os
import json
import uuid
import hmac
import hashlib
import datetime
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, Query
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()

# === Models ===
class ListingUpdateRequest(BaseModel):
    asin: str
    sku: str
    field: str
    value: str | float | list[str]

class PriceUpdateFastRequest(BaseModel):
    asin: str
    sku: str
    new_price: float

# === Environment ===
def get_env(var):
    value = os.getenv(var)
    if not value:
        raise EnvironmentError(f"Missing env var: {var}")
    return value

ENV = {
    "REFRESH_TOKEN": get_env("SPAPI_REFRESH_TOKEN"),
    "CLIENT_ID": get_env("SPAPI_LWA_CLIENT_ID"),
    "CLIENT_SECRET": get_env("SPAPI_LWA_CLIENT_SECRET"),
    "ROLE_ARN": get_env("SPAPI_ROLE_ARN"),
    "AWS_ACCESS_KEY": get_env("SPAPI_AWS_ACCESS_KEY_ID"),
    "AWS_SECRET_KEY": get_env("SPAPI_AWS_SECRET_ACCESS_KEY"),
    "SELLER_ID": get_env("SPAPI_SELLER_ID"),
    "MARKETPLACE_ID": get_env("SPAPI_MARKETPLACE_ID"),
}

# === Auth ===
def get_access_token():
    res = requests.post(
        "https://api.amazon.com/auth/o2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": ENV["REFRESH_TOKEN"],
            "client_id": ENV["CLIENT_ID"],
            "client_secret": ENV["CLIENT_SECRET"]
        },
        timeout=10
    )
    res.raise_for_status()
    return res.json()["access_token"]

# === Signing ===
def sign_request(method, endpoint, body, access_token, region="us-east-1", service="execute-api"):
    host = "sellingpartnerapi-na.amazon.com"
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-access-token:{access_token}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"
    canonical_request = (
        f"{method}\n{endpoint}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + ENV["AWS_SECRET_KEY"]).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={ENV['AWS_ACCESS_KEY']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Content-Type": "application/json",
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Access-Token": access_token,
        "Authorization": auth_header,
    }

# === Feed Status Route (patched) ===
@app.get("/feed-status")
def feed_status(feedId: str = Query(...)):
    try:
        access_token = get_access_token()
        headers = sign_request("GET", f"/feeds/2021-06-30/feeds/{feedId}", "", access_token)
        res = requests.get(
            f"https://sellingpartnerapi-na.amazon.com/feeds/2021-06-30/feeds/{feedId}",
            headers=headers,
            timeout=10
        )
        res.raise_for_status()
        return res.json()
    except requests.exceptions.Timeout:
        return JSONResponse(status_code=504, content={"status": "error", "message": "Amazon API timed out."})
    except requests.exceptions.RequestException as e:
        return JSONResponse(status_code=502, content={"status": "error", "message": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

# === Remaining Routes (no changes) ===
# ✅ Leave your `/update-listing`, `/update-price-fast`, and `/scrape-listing` routes as-is from previous working file
