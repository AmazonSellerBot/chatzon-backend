# main.py
import os
import hmac
import json
import gzip
import io
import hashlib
import logging
import datetime as dt
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

# ---------------------------
# App setup & logging
# ---------------------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("chatzon")
APP_NAME = "Chatzon SP-API Bridge"

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
# LWA + SigV4 helpers
# ---------------------------
def get_lwa_access_token() -> str:
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


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> bytes:
    k_date = _sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region_name.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service_name.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    return k_signing


def execute_signed_request(method: str, path: str, query: str = "", body: Optional[str] = None, extra_headers: Optional[dict] = None):
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

    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-access-token": access_token,
        "content-type": extra_headers.get("content-type", "application/json"),
    }
    for k, v in (extra_headers or {}).items():
        headers[k.lower()] = v

    signed_headers = ";".join(sorted(headers.keys()))
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

    final_headers = {("host" if k.lower() == "host" else k): v for k, v in headers.items()}
    final_headers["Authorization"] = authorization_header
    if AWS_SESSION_TOKEN:
        final_headers["x-amz-security-token"] = AWS_SESSION_TOKEN

    url = f"{SP_API_ENDPOINT}{path}"
    if canonical_querystring:
        url += f"?{canonical_querystring}"

    resp = requests.request(method, url, headers=final_headers, data=(body or ""), timeout=60)
    return resp


# ---------------------------
# Feed helpers (JSON_LISTINGS_FEED)
# ---------------------------
class PriceUpdatePayload(BaseModel):
    sku: str = Field(..., description="Seller SKU")
    marketplaceId: str = Field(..., description="e.g., ATVPDKIKX0DER (US)")
    amount: float = Field(..., description="New price, e.g., 36.99")
    currency: str = Field(default="USD", description="Currency code")


def build_json_listings_price_feed(sku: str, marketplace_id: str, amount: float, currency: str = "USD") -> str:
    message = {
        "sku": sku,
        "operationType": "PATCH",
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/standard_price",
                "value": [
                    {"currency": currency, "amount": round(float(amount), 2)}
                ]
            }
        ]
    }
    feed = {
        "header": {"sellerId": SELLER_ID, "version": "2.0"},
        "messages": [message]
    }
    return json.dumps(feed, separators=(",", ":"))


def create_feed_document() -> dict:
    body = json.dumps({"contentType": "application/json; charset=UTF-8"})
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
    if resp.status_code not in (200, 201, 202):
        raise HTTPException(status_code=resp.status_code, detail=f"createFeed failed: {resp.text}")
    # 202 Accepted returns {"feedId":"..."}
    return resp.json()


def get_feed(feed_id: str) -> dict:
    resp = execute_signed_request("GET", f"/feeds/2021-06-30/feeds/{feed_id}")
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"getFeed failed: {resp.text}")
    return resp.json()


def list_recent_feeds(max_results: int = 20, feed_type: str = "JSON_LISTINGS_FEED") -> dict:
    created_since = (dt.datetime.utcnow() - dt.timedelta(days=2)).replace(microsecond=0).isoformat() + "Z"
    q = f"maxResults={max_results}&createdSince={created_since}&feedTypes={feed_type}"
    resp = execute_signed_request("GET", "/feeds/2021-06-30/feeds", query=q)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"listFeeds failed: {resp.text}")
    return resp.json()


def get_feed_document(feed_document_id: str) -> dict:
    resp = execute_signed_request("GET", f"/feeds/2021-06-30/documents/{feed_document_id}")
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"getFeedDocument failed: {resp.text}")
    return resp.json()


def download_processing_report(url: str, compression_algorithm: Optional[str]) -> dict | str:
    r = requests.get(url, timeout=60)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=f"download report failed: {r.text}")

    content = r.content
    if (compression_algorithm or "").upper() == "GZIP":
        content = gzip.decompress(content)

    # Try JSON first; if not JSON, return text
    try:
        return json.loads(content.decode("utf-8"))
    except Exception:
        return content.decode("utf-8", errors="replace")


# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def root():
    return {"ok": True}

@app.get("/health")
def health():
    return {"app": APP_NAME, "status": "ok", "time_utc": dt.datetime.utcnow().isoformat() + "Z"}

@app.get("/diag/lwa")
def diag_lwa():
    try:
        r = requests.post(
            "https://api.amazon.com/auth/o2/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": os.getenv("LWA_REFRESH_TOKEN",""),
                "client_id": os.getenv("LWA_CLIENT_ID",""),
                "client_secret": os.getenv("LWA_CLIENT_SECRET",""),
            },
            timeout=30
        )
        ct = r.headers.get("content-type","")
        body = r.json() if "application/json" in ct else r.text
        return {"status": r.status_code, "body": body}
    except Exception as e:
        return {"status": "error", "body": str(e)}


class PriceUpdateResponse(BaseModel):
    status: str
    feedId: Optional[str] = None
    feedDocumentId: Optional[str] = None
    note: Optional[str] = None


@app.post("/update-price-fast", response_model=PriceUpdateResponse)
def update_price_fast(payload: PriceUpdatePayload):
    """
    Submit a JSON_LISTINGS_FEED to update price for a single SKU.
    Returns feedId to poll with /feed-status and report with /feed-report.
    """
    feed_body = build_json_listings_price_feed(
        sku=payload.sku,
        marketplace_id=payload.marketplaceId,
        amount=payload.amount,
        currency=payload.currency
    )

    doc = create_feed_document()
    feed_doc_id = doc["feedDocumentId"]
    upload_url = doc["url"]

    upload_feed_to_s3(upload_url, feed_body)

    created = create_feed(
        feed_document_id=feed_doc_id,
        feed_type="JSON_LISTINGS_FEED",
        marketplace_ids=[payload.marketplaceId]
    )
    return PriceUpdateResponse(
        status="submitted",
        feedId=created.get("feedId"),
        feedDocumentId=feed_doc_id,
        note="Use /feed-status?feedId=... until DONE, then call /feed-report?feedId=..."
    )


@app.get("/feed-status")
def feed_status(feedId: str = Query(..., description="Feed ID to check")):
    return get_feed(feedId)


@app.get("/feeds/recent")
def feeds_recent(maxResults: int = Query(20, ge=1, le=100), feedType: str = "JSON_LISTINGS_FEED"):
    return list_recent_feeds(max_results=maxResults, feed_type=feedType)


@app.get("/feed-report")
def feed_report(feedId: str = Query(..., description="Feed ID whose processing report to fetch")):
    """
    After a feed is DONE, this returns the processing report (JSON or text).
    """
    info = get_feed(feedId)
    result_doc_id = info.get("resultFeedDocumentId")
    if not result_doc_id:
        raise HTTPException(status_code=400, detail="Feed not DONE yet or no resultFeedDocumentId present.")

    doc = get_feed_document(result_doc_id)
    url = doc.get("url")
    comp = doc.get("compressionAlgorithm")
    if not url:
        raise HTTPException(status_code=500, detail="No URL in feed document.")
    report = download_processing_report(url, comp)
    return {"feedId": feedId, "compression": comp, "report": report}


@app.get("/oauth/callback")
def oauth_callback(code: Optional[str] = None, state: Optional[str] = None, selling_partner_id: Optional[str] = None):
    return {"received": True, "code": code, "state": state, "selling_partner_id": selling_partner_id}
