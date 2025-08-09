# main.py
import os
import hmac
import json
import base64
import hashlib
import logging
import datetime as dt
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

# ---------------------------
# Config & Logging
# ---------------------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("chatzon")

APP_NAME = "Chatzon SP-API Bridge"

# Required ENV (set these on Railway)
# LWA_CLIENT_ID
# LWA_CLIENT_SECRET
# LWA_REFRESH_TOKEN
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
# AWS_ROLE_ARN (optional if you’re not assuming a role)
# AWS_SESSION_TOKEN (optional if you’re assuming a role externally)
# SELLER_ID  (Amazon merchant ID)
# REGION  (e.g., "us-east-1")
# SP_API_ENDPOINT (e.g., "https://sellingpartnerapi-na.amazon.com")

REQUIRED_ENVS = [
    "LWA_CLIENT_ID",
    "LWA_CLIENT_SECRET",
    "LWA_REFRESH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "SELLER_ID",
    "REGION",
    "SP_API_ENDPOINT",
]

for k in REQUIRED_ENVS:
    if not os.getenv(k):
        log.warning(f"ENV {k} is not set")

LWA_CLIENT_ID = os.getenv("LWA_CLIENT_ID", "")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET", "")
LWA_REFRESH_TOKEN = os.getenv("LWA_REFRESH_TOKEN", "")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN", "")
SELLER_ID = os.getenv("SELLER_ID", "")
REGION = os.getenv("REGION", "us-east-1")
SP_API_ENDPOINT = os.getenv("SP_API_ENDPOINT", "https://sellingpartnerapi-na.amazon.com")

SERVICE = "execute-api"

app = FastAPI(title=APP_NAME)


# ---------------------------
# Helpers: LWA + SigV4
# ---------------------------
def get_lwa_access_token() -> str:
    """Exchange refresh token for a short-lived LWA access token."""
    url = "https://api.amazon.com/auth/o2/token"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": LWA_REFRESH_TOKEN,
        "client_id": LWA_CLIENT_ID,
        "client_secret": LWA_CLIENT_SECRET,
    }
    r = requests.post(url, data=data, timeout=30)
    if r.status_code != 200:
        log.error(f"LWA token error: {r.status_code} {r.text}")
        raise HTTPException(status_code=500, detail="Failed to obtain LWA access token")
    return r.json()["access_token"]


def _sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(key, date_stamp, region_name, service_name):
    k_date = _sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region_name.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service_name.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    return k_signing


def execute_signed_request(method: str, path: str, query: str = "", body: Optional[str] = None, extra_headers: Optional[dict] = None):
    """
    Minimal SigV4 signer for SP-API. Use this with your LWA bearer token.
    """
    if extra_headers is None:
        extra_headers = {}

    access_token = get_lwa_access_token()

    t = dt.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    host = SP_API_ENDPOINT.replace("https://", "").replace("http://", "")
    canonical_uri = path
    canonical_querystring = query or ""

    payload_hash = hashlib.sha256((body or "").encode("utf-8")).hexdigest()

    # Required headers
    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-access-token": access_token,
        "content-type": extra_headers.get("content-type", "application/json"),
    }

    # Merge any extras (without overwriting required unless intended)
    for k, v in (extra_headers or {}).items():
        headers[k.lower()] = v

    signed_headers = ";".join(sorted([h for h in headers.keys()]))
    canonical_headers = "".join([f"{h}:{headers[h]}\n" for h in sorted(headers.keys())])

    canonical_request = "\n".join([
        method.upper(),
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        algorithm,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    signing_key = _get_signature_key(AWS_SECRET_ACCESS_KEY, date_stamp, REGION, SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={AWS_ACCESS_KEY_ID}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    # Final headers (requests expects original case on common keys)
    final_headers = {k if k.lower() != "host" else "host": v for k, v in headers.items()}
    final_headers["Authorization"] = authorization_header
    if AWS_SESSION_TOKEN:
        final_headers["x-amz-security-token"] = AWS_SESSION_TOKEN

    url = f"{SP_API_ENDPOINT}{path}"
    if canonical_querystring:
        url += f"?{canonical_querystring}"

    resp = requests.request(method, url, headers=final_headers, data=(body or ""), timeout=60)
    return resp


# ---------------------------
# Feed Helpers (JSON feed flow)
# ---------------------------
class PriceUpdatePayload(BaseModel):
    sku: str = Field(..., description="Seller SKU you want to update")
    marketplaceId: str = Field(..., description="e.g., ATVPDKIKX0DER (US)")
    amount: float = Field(..., description="New price amount, e.g., 36.99")
    currency: str = Field(default="USD", description="Currency code (default USD)")


def build_json_listings_price_feed(sku: str, marketplace_id: str, amount: float, currency: str = "USD") -> str:
    """
    Minimal JSON feed to PATCH price via JSON_LISTINGS_FEED.
    NOTE: Amazon’s JSON feed structure can vary by productType. This uses a generic PATCH
    to /attributes/standard_price. If your catalog needs a different path, we can tweak fast.
    """
    message = {
        "sku": sku,
        "operationType": "PATCH",
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/standard_price",
                "value": [
                    {
                        "currency": currency,
                        "amount": round(float(amount), 2)
                    }
                ]
            }
        ]
    }

    feed = {
        "header": {
            "sellerId": SELLER_ID,
            "version": "2.0"
        },
        "messages": [message]
    }

    # Amazon requires a top-level "marketplaceIds" when creating the feed
    # (passed during /feeds create call), not inside the document.
    return json.dumps(feed, separators=(",", ":"))


def create_feed_document() -> dict:
    body = json.dumps({
        "contentType": "application/json; charset=UTF-8"
    })
    resp = execute_signed_request(
        "POST",
        "/feeds/2021-06-30/documents",
        body=body,
        extra_headers={"content-type": "application/json; charset=UTF-8"}
    )
    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=f"createFeedDocument failed: {resp.text}")
    return resp.json()


def upload_feed_to_s3(url: str, feed_body: str, content_type: str = "application/json; charset=UTF-8"):
    """
    JSON feeds use a pre-signed URL; no client-side encryption required.
    """
    put = requests.put(url, data=feed_body.encode("utf-8"), headers={"Content-Type": content_type}, timeout=60)
    if put.status_code not in (200, 201):
        raise HTTPException(status_code=put.status_code, detail=f"S3 upload failed: {put.text}")


def create_feed(feed_document_id: str, feed_type: str, marketplace_ids: list[str]) -> dict:
    body = json.dumps({
        "feedType": feed_type,
        "marketplaceIds": marketplace_ids,
        "inputFeedDocumentId": feed_document_id
    })
    resp = execute_signed_request(
        "POST",
        "/feeds/2021-06-30/feeds",
        body=body,
        extra_headers={"content-type": "application/json; charset=UTF-8"}
    )
    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=resp.status_code, detail=f"createFeed failed: {resp.text}")
    return resp.json()


def get_feed(feed_id: str) -> dict:
    resp = execute_signed_request(
        "GET",
        f"/feeds/2021-06-30/feeds/{feed_id}"
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"getFeed failed: {resp.text}")
    return resp.json()


# ---------------------------
# Routes
# ---------------------------
@app.get("/health")
def health():
    return {
        "app": APP_NAME,
        "status": "ok",
        "time_utc": dt.datetime.utcnow().isoformat() + "Z"
    }


@app.post("/update-price-fast")
def update_price_fast(payload: PriceUpdatePayload):
    """
    Submit a JSON_LISTINGS_FEED to update price for a single SKU.
    Returns feedId so you can poll /feed-status.
    """
    # 1) Build JSON feed body
    feed_body = build_json_listings_price_feed(
        sku=payload.sku,
        marketplace_id=payload.marketplaceId,
        amount=payload.amount,
        currency=payload.currency
    )

    # 2) Create feed document
    doc = create_feed_document()
    feed_doc_id = doc["feedDocumentId"]
    upload_url = doc["url"]

    # 3) Upload feed JSON to S3
    upload_feed_to_s3(upload_url, feed_body)

    # 4) Create feed
    created = create_feed(
        feed_document_id=feed_doc_id,
        feed_type="JSON_LISTINGS_FEED",
        marketplace_ids=[payload.marketplaceId]
    )

    return {
        "status": "submitted",
        "feedId": created.get("feedId"),
        "feedDocumentId": feed_doc_id,
        "note": "Use /feed-status?feedId=... to poll for DONE."
    }


@app.get("/feed-status")
def feed_status(feedId: str = Query(..., description="Feed ID to check")):
    status = get_feed(feedId)
    return status


# OPTIONAL: Simple OAuth callback catcher so you can see Amazon redirect params when support fixes the blank page.
# Set your redirect URI in the Security Profile to: https://<your-app-domain>/oauth/callback
@app.get("/oauth/callback")
def oauth_callback(code: Optional[str] = None, state: Optional[str] = None, selling_partner_id: Optional[str] = None):
    """
    This endpoint doesn't exchange the code (you’ll do that in Seller Central flow),
    but it helps verify that the redirect works and you’re receiving a ?code=... back.
    """
    return {
        "received": True,
        "code": code,
        "state": state,
        "selling_partner_id": selling_partner_id
    }
