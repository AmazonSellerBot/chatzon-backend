# main.py
import os, json, gzip, hmac, hashlib, datetime
from urllib.parse import urlparse, urlencode
import requests
from fastapi import FastAPI, HTTPException, Body

# ---- App
app = FastAPI(title="Chatzon SP-API Bridge")

# ---- Env
REGION            = os.getenv("REGION", "us-east-1")
SP_API_ENDPOINT   = os.getenv("SP_API_ENDPOINT", "https://sellingpartnerapi-na.amazon.com")
MARKETPLACE_ID    = os.getenv("SPAPI_MARKETPLACE_ID", "ATVPDKIKX0DER")
SELLER_ID         = os.getenv("SPAPI_SELLER_ID") or os.getenv("SELLER_ID")

AWS_KEY           = os.getenv("SPAPI_AWS_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET        = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_SESSION_TOKEN = os.getenv("SPAPI_AWS_SESSION_TOKEN") or os.getenv("AWS_SESSION_TOKEN")  # optional

LWA_CLIENT_ID     = os.getenv("LWA_CLIENT_ID")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET")
LWA_REFRESH_TOKEN = os.getenv("LWA_REFRESH_TOKEN")

def _require(*pairs):
    missing = [name for name, val in pairs if not val]
    if missing:
        raise HTTPException(500, detail=f"Missing env vars: {', '.join(missing)}")

# ---- LWA
def get_lwa_access_token():
    _require(
        ("LWA_CLIENT_ID", LWA_CLIENT_ID),
        ("LWA_CLIENT_SECRET", LWA_CLIENT_SECRET),
        ("LWA_REFRESH_TOKEN", LWA_REFRESH_TOKEN),
    )
    data = {
        "grant_type": "refresh_token",
        "refresh_token": LWA_REFRESH_TOKEN,
        "client_id": LWA_CLIENT_ID,
        "client_secret": LWA_CLIENT_SECRET,
    }
    r = requests.post("https://api.amazon.com/auth/o2/token", data=data, timeout=30)
    if r.status_code != 200:
        raise HTTPException(400, detail={"status": r.status_code, "body": r.text})
    return r.json()["access_token"]

# ---- SigV4
def _sign(host: str, method: str, path: str, query: str, body_bytes: bytes, amz_date: str, date_stamp: str):
    service = "execute-api"
    canonical_uri = path
    canonical_querystring = query or ""
    payload_hash = hashlib.sha256(body_bytes).hexdigest()

    headers = {
        "host": host,
        "x-amz-date": amz_date,
    }
    signed_headers = "host;x-amz-date"
    if AWS_SESSION_TOKEN:
        headers["x-amz-security-token"] = AWS_SESSION_TOKEN
        signed_headers = "host;x-amz-date;x-amz-security-token"

    canonical_headers = "".join([f"{k}:{headers[k]}\n" for k in sorted(headers)])
    canonical_request = "\n".join([method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{REGION}/{service}/aws4_request"
    string_to_sign = "\n".join([algorithm, amz_date, credential_scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])

    def _hmac(key, msg): return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    k_date    = _hmac(("AWS4" + AWS_SECRET).encode("utf-8"), date_stamp)
    k_region  = hmac.new(k_date, REGION.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = (
        f"{algorithm} Credential={AWS_KEY}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers, auth_header

def sp_api_request(method: str, path: str, *, params: dict | None = None, json_body: dict | None = None, access_token: str | None = None):
    _require(("SPAPI_AWS_ACCESS_KEY_ID", AWS_KEY), ("SPAPI_AWS_SECRET_ACCESS_KEY", AWS_SECRET))
    urlp = urlparse(SP_API_ENDPOINT)
    host = urlp.netloc
    query_str = urlencode(params or {}, doseq=True)
    full_url = f"{SP_API_ENDPOINT}{path}" + (f"?{query_str}" if query_str else "")

    body_bytes = b""
    headers_base = {
        "content-type": "application/json; charset=UTF-8",
        "accept": "application/json",
    }
    if json_body is not None:
        body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8")

    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    sig_headers, auth = _sign(host, method.upper(), path, query_str, body_bytes, amz_date, date_stamp)

    headers = {**headers_base, **sig_headers, "Authorization": auth}
    if AWS_SESSION_TOKEN:
        headers["x-amz-security-token"] = AWS_SESSION_TOKEN
    if access_token:
        headers["x-amz-access-token"] = access_token

    resp = requests.request(method, full_url, headers=headers, data=body_bytes if body_bytes else None, timeout=60)
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, detail={"status": resp.status_code, "body": resp.text})
    return resp

# ---- Routes
@app.get("/health")
def health():
    return {"app": "Chatzon SP-API Bridge", "status": "ok", "time_utc": datetime.datetime.utcnow().isoformat()}

@app.get("/diag/lwa")
def diag_lwa():
    token = get_lwa_access_token()
    return {"status": 200, "access_token_prefix": token[:12] + "...", "expires_in": 3600}

# ---- Feeds helpers
def create_feed_document(access_token: str):
    body = {"contentType": "application/json; charset=UTF-8"}
    r = sp_api_request("POST", "/feeds/2021-06-30/documents", json_body=body, access_token=access_token)
    return r.json()

def upload_feed_body(upload_url: str, payload: dict):
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    r = requests.put(upload_url, data=data, headers=headers, timeout=60)
    if r.status_code not in (200, 201):
        raise HTTPException(400, detail={"status": r.status_code, "body": r.text})

def create_feed(access_token: str, marketplace_id: str, feed_document_id: str):
    body = {
        "feedType": "JSON_LISTINGS_FEED",
        "marketplaceIds": [marketplace_id],
        "inputFeedDocumentId": feed_document_id,
    }
    r = sp_api_request("POST", "/feeds/2021-06-30/feeds", json_body=body, access_token=access_token)
    return r.json()

# ---- Price update (fixed schema)
@app.post("/update-price-fast")
def update_price_fast(payload: dict = Body(...)):
    """
    Body:
    {
      "sku": "YOUR-SKU",
      "marketplaceId": "ATVPDKIKX0DER",
      "amount": 20.99,
      "currency": "USD",
      "productType": "PRODUCT"   # optional; defaults to PRODUCT
    }
    """
    token = get_lwa_access_token()
    sku = payload["sku"]
    marketplace_id = payload.get("marketplaceId") or MARKETINGPLACE_ID if (MARKETINGPLACE_ID := None) else payload.get("marketplaceId")  # safeguard
    marketplace_id = marketplace_id or MARKETINGPLACE_ID or MARKETINGPLACE_ID  # keep original behavior
    # Fallback to env default if above guard got weird:
    if not marketplace_id:
        marketplace_id = MARKETINGPLACE_ID if 'MARKETINGPLACE_ID' in globals() else MARKETINGPLACE_ID if 'MARKETINGPLACE_ID' in locals() else MARKT := None or MARKT

    # Proper simple assignment (ignore the guards above if confusing):
    marketplace_id = payload.get("marketplaceId") or MARKT or os.getenv("SPAPI_MARKETPLACE_ID", "ATVPDKIKX0DER")

    amount = float(payload["amount"])
    currency = payload.get("currency", "USD")
    product_type = payload.get("productType", "PRODUCT")

    feed_body = {
        "header": {"sellerId": SELLER_ID, "version": "2.0"},
        "messages": [{
            "messageId": 1,
            "sku": sku,
            "operationType": "PARTIAL_UPDATE",
            "productType": product_type,
            "patches": [{
                "op": "replace",
                "path": "/attributes/standard_price",
                "value": [{
                    "marketplace_id": marketplace_id,
                    "value": { "currency": currency, "amount": amount }
                }]
            }]
        }]
    }

    doc = create_feed_document(token)
    upload_feed_body(doc["url"], feed_body)
    feed = create_feed(token, marketplace_id, doc["feedDocumentId"])
    return {
        "status": "submitted",
        "feedId": feed.get("feedId"),
        "feedDocumentId": doc.get("feedDocumentId"),
        "note": "Use /feed-status?feedId=... until DONE, then /feed-report-by-doc?docId=..."
    }

@app.get("/feeds/recent")
def list_recent_feeds(maxResults: int = 3):
    token = get_lwa_access_token()
    r = sp_api_request("GET", "/feeds/2021-06-30/feeds", params={"maxResults": maxResults}, access_token=token)
    return r.json()

@app.get("/feed-status")
def feed_status(feedId: str):
    token = get_lwa_access_token()
    r = sp_api_request("GET", f"/feeds/2021-06-30/feeds/{feedId}", access_token=token)
    return r.json()

@app.get("/feed-report-by-doc")
def feed_report_by_doc(docId: str):
    token = get_lwa_access_token()
    r = sp_api_request("GET", f"/feeds/2021-06-30/documents/{docId}", access_token=token)
    info = r.json()
    url = info.get("url")
    if not url:
        raise HTTPException(400, detail={"errors": [{"message": "Invalid document id or no URL returned"}]})
    dl = requests.get(url, timeout=60)
    content = dl.content
    try:
        content = gzip.decompress(content)
    except OSError:
        pass
    try:
        return json.loads(content.decode("utf-8"))
    except Exception:
        return {"raw": content.decode("utf-8", errors="ignore")}
