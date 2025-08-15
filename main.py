# main.py
# Chatzon Backend – Catalog + Listings + Price Update + Get Price
# Routes:
#   GET  /health
#   GET  /catalog-by-sku
#   GET  /inspect-listing
#   GET  /get-listing-price
#   POST /update-price
#   POST /update-price-fast  (alias)

import os, hmac, hashlib, json, time, datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlencode, quote
import requests
from fastapi import FastAPI, Body, Query
from fastapi.responses import JSONResponse

# ===== Env =====
LWA_CLIENT_ID = os.getenv("LWA_CLIENT_ID", "")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET", "")
LWA_REFRESH_TOKEN = os.getenv("LWA_REFRESH_TOKEN", "")

AWS_ACCESS_KEY = os.getenv("SPAPI_AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY", "")
AWS_REGION     = os.getenv("REGION", "us-east-1")
ROLE_ARN       = os.getenv("SPAPI_ROLE_ARN", "")

SP_API_ENDPOINT        = os.getenv("SP_API_ENDPOINT", "https://sellingpartnerapi-na.amazon.com")
MARKETPLACE_ID_DEFAULT = os.getenv("SPAPI_MARKETPLACE_ID", "ATVPDKIKX0DER")
SELLER_ID              = os.getenv("SPAPI_SELLER_ID", "")

# ===== Helpers =====
_session = {"expires_at": 0, "creds": None}
def _now() -> int: return int(time.time())

def _assume_role():
    """Assume role if ROLE_ARN is set; cache creds until expiry."""
    if not ROLE_ARN:
        return None
    if _session["creds"] and _session["expires_at"] - 30 > _now():
        return _session["creds"]
    try:
        import boto3  # type: ignore
        sts = boto3.client(
            "sts",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
        )
        r = sts.assume_role(RoleArn=ROLE_ARN, RoleSessionName="chatzon-spapi-session")
        c = r["Credentials"]
        _session["creds"] = {
            "AccessKeyId": c["AccessKeyId"],
            "SecretAccessKey": c["SecretAccessKey"],
            "SessionToken": c["SessionToken"],
        }
        _session["expires_at"] = int(c["Expiration"].timestamp())
        return _session["creds"]
    except Exception:
        return None

def _get_lwa() -> str:
    r = requests.post(
        "https://api.amazon.com/auth/o2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": LWA_REFRESH_TOKEN,
            "client_id": LWA_CLIENT_ID,
            "client_secret": LWA_CLIENT_SECRET,
        },
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"LWA token error {r.status_code}: {r.text}")
    return r.json()["access_token"]

def _sign(method: str, host: str, region: str, uri: str, qs: str,
          hdrs: Dict[str, str], payload: bytes,
          ak: str, sk: str, st: Optional[str] = None) -> Dict[str, str]:
    service = "execute-api"
    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    canonical_headers_items = {"host": host, "x-amz-date": amz_date}
    for k, v in hdrs.items():
        canonical_headers_items[k.lower()] = v
    signed_headers_list = sorted(canonical_headers_items.keys())
    canonical_headers = "".join([f"{k}:{canonical_headers_items[k]}\n" for k in signed_headers_list])
    signed_headers = ";".join(signed_headers_list)
    payload_hash = hashlib.sha256(payload).hexdigest()

    canonical_request = "\n".join([
        method.upper(), uri, qs, canonical_headers, signed_headers, payload_hash
    ])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        algorithm, amz_date, credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    ])

    def hmacd(key, msg): return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    k_date = hmacd(("AWS4" + sk).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, b"execute-api", hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = {
        "x-amz-date": amz_date,
        "Authorization": f"{algorithm} Credential={ak}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
    }
    if st:
        out["x-amz-security-token"] = st
    return out

def _exec(method: str, path: str, query: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None) -> requests.Response:
    base = SP_API_ENDPOINT.rstrip("/")
    url = f"{base}{path}"
    host = base.replace("https://", "").replace("http://", "")
    qs = urlencode(query or {}, doseq=True)

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "x-amz-access-token": _get_lwa(),
    }
    data = None
    payload = b""
    if body is not None:
        data = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        payload = data.encode()

    creds = _assume_role()
    if creds:
        ak, sk, st = creds["AccessKeyId"], creds["SecretAccessKey"], creds.get("SessionToken")
    else:
        ak, sk, st = AWS_ACCESS_KEY, AWS_SECRET_KEY, None

    signed = _sign(
        method, host, AWS_REGION, path, qs,
        {"x-amz-access-token": headers["x-amz-access-token"], "content-type": headers["content-type"]},
        payload, ak, sk, st
    )
    hdr = {**headers, **signed}

    m = method.upper()
    if m == "GET":    return requests.get(url, headers=hdr, params=query, timeout=60)
    if m == "PATCH":  return requests.patch(url, headers=hdr, params=query, data=data, timeout=60)
    if m == "POST":   return requests.post(url, headers=hdr, params=query, data=data, timeout=60)
    if m == "PUT":    return requests.put(url, headers=hdr, params=query, data=data, timeout=60)
    if m == "DELETE": return requests.delete(url, headers=hdr, params=query, data=data, timeout=60)
    raise ValueError("bad method")

# ===== App =====
app = FastAPI(title="Chatzon Backend – Catalog+Listings+PriceUpdate", version="2.9.0")

@app.get("/health")
def health():
    return {"ok": True, "service": "chatzon-backend", "time": datetime.datetime.utcnow().isoformat()+"Z"}

# 1) Catalog lookup by SKU (Amazon REQUIRES sellerId for SKU searches)
@app.get("/catalog-by-sku")
def catalog_by_sku(sku: str = Query(...), marketplaceId: str = Query(MARKETPLACE_ID_DEFAULT)):
    resp = _exec(
        "GET",
        "/catalog/2022-04-01/items",
        query={
            "identifiers": sku,
            "identifiersType": "SKU",
            "marketplaceIds": marketplaceId,
            "sellerId": SELLER_ID,  # required
            "includedData": "summaries,identifiers,attributes"
        },
    )
    try: body = resp.json()
    except Exception: body = {"text": resp.text}
    return JSONResponse(
        status_code=resp.status_code if resp.status_code < 500 else 502,
        content={"status_code": resp.status_code,
                 "x-amzn-RequestId": resp.headers.get("x-amzn-RequestId"),
                 "result": body}
    )

# 2) Listings Items GET (may reveal productType)
@app.get("/inspect-listing")
def inspect_listing(sku: str = Query(...), marketplaceId: str = Query(MARKETPLACE_ID_DEFAULT)):
    path = f"/listings/2021-08-01/items/{SELLER_ID}/{quote(sku, safe='')}"
    resp = _exec("GET", path, query={"marketplaceIds": marketplaceId})
    try: body = resp.json()
    except Exception: body = {"text": resp.text}
    pt = None
    try:
        for s in (body.get("summaries") or []):
            if s.get("marketplaceId") == marketplaceId and s.get("productType"):
                pt = s["productType"]; break
        if not pt and (body.get("summaries") or []):
            pt = body["summaries"][0].get("productType")
    except Exception:
        pt = None
    return JSONResponse(
        status_code=resp.status_code if resp.status_code < 500 else 502,
        content={"status_code": resp.status_code,
                 "x-amzn-RequestId": resp.headers.get("x-amzn-RequestId"),
                 "productType": pt,
                 "raw": body}
    )

# 3) Get current offer price for a SKU (Listings Items GET)
@app.get("/get-listing-price")
def get_listing_price(
    sku: str = Query(...),
    marketplaceId: str = Query(MARKETPLACE_ID_DEFAULT)
):
    """Reads listing and extracts the current price (purchasable_offer / standard_price)."""
    path = f"/listings/2021-08-01/items/{SELLER_ID}/{quote(sku, safe='')}"
    resp = _exec("GET", path, query={"marketplaceIds": marketplaceId})
    try:
        body = resp.json()
    except Exception:
        body = {"text": resp.text}

    productType = None
    try:
        for s in (body.get("summaries") or []):
            if s.get("marketplaceId") == marketplaceId and s.get("productType"):
                productType = s["productType"]; break
        if not productType and (body.get("summaries") or []):
            productType = body["summaries"][0].get("productType")
    except Exception:
        productType = None

    price = None
    currency = None
    source_attribute = None
    attrs = (body.get("attributes") or {})

    def _num_or_obj(v):
        if isinstance(v, (int, float)):
            return float(v), None
        if isinstance(v, dict) and "value" in v:
            return float(v["value"]), v.get("currency")
        return None, None

    # purchasable_offer → our_price → schedule → value_with_tax / value
    try:
        po = attrs.get("purchasable_offer", [])
        if isinstance(po, list) and po:
            op = po[0].get("our_price", [])
            if isinstance(op, list) and op:
                sch = op[0].get("schedule", [])
                if isinstance(sch, list) and sch:
                    vw = sch[0].get("value_with_tax")
                    vv = sch[0].get("value")
                    if vw is not None:
                        val, cur = _num_or_obj(vw)
                        if val is not None:
                            price, currency, source_attribute = val, (cur or po[0].get("currency")), "purchasable_offer.value_with_tax"
                    if price is None and vv is not None:
                        val, cur = _num_or_obj(vv)
                        if val is not None:
                            price, currency, source_attribute = val, (cur or po[0].get("currency")), "purchasable_offer.value"
    except Exception:
        pass

    # standard_price → value / value_with_tax
    if price is None:
        try:
            sp = attrs.get("standard_price", [])
            if isinstance(sp, list) and sp:
                if "value" in sp[0]:
                    val, cur = _num_or_obj(sp[0]["value"])
                    if val is not None:
                        price, currency, source_attribute = val, (cur or currency), "standard_price.value"
                if price is None and "value_with_tax" in sp[0]:
                    val, cur = _num_or_obj(sp[0]["value_with_tax"])
                    if val is not None:
                        price, currency, source_attribute = val, (cur or currency), "standard_price.value_with_tax"
        except Exception:
            pass

    out = {
        "status_code": resp.status_code,
        "sku": sku,
        "marketplaceId": marketplaceId,
        "productType": productType,
        "price": price,
        "currency": currency,
        "source_attribute": source_attribute,
    }
    if resp.status_code >= 300 or price is None:
        out["raw_attributes"] = attrs
        out["raw_summary"] = body.get("summaries")
    return JSONResponse(status_code=resp.status_code if resp.status_code < 500 else 502, content=out)

# --- Price helpers (two attribute paths + two requirement modes) ---
def _bodies_for_price(currency: str, amount: float, productType: str) -> List[Dict[str, Any]]:
    amt = round(float(amount), 2)
    a = {  # purchasable_offer, value_with_tax NUMBER
        "productType": productType,
        "patches": [{
            "op": "replace", "path": "/attributes/purchasable_offer",
            "value": [{"currency": currency, "our_price": [{"schedule": [{"value_with_tax": amt}]}]}]
        }]
    }
    b = {  # purchasable_offer, value_with_tax OBJECT
        "productType": productType,
        "patches": [{
            "op": "replace", "path": "/attributes/purchasable_offer",
            "value": [{"currency": currency, "our_price": [{"schedule": [{"value_with_tax": {"value": amt, "currency": currency}}]}]}]
        }]
    }
    c = {  # standard_price value OBJECT
        "productType": productType,
        "patches": [{
            "op": "replace", "path": "/attributes/standard_price",
            "value": [{"value": {"value": amt, "currency": currency}}]
        }]
    }
    d = {  # standard_price value_with_tax OBJECT
        "productType": productType,
        "patches": [{
            "op": "replace", "path": "/attributes/standard_price",
            "value": [{"value_with_tax": {"value": amt, "currency": currency}}]
        }]
    }
    return [a, b, c, d]

def _try_patch_price(sku: str, marketplaceId: str, currency: str, amount: float, productType: str):
    path = f"/listings/2021-08-01/items/{SELLER_ID}/{quote(sku, safe='')}"
    bodies = _bodies_for_price(currency, amount, productType)
    for req in ("LISTING_OFFER_ONLY", "LISTING"):
        for idx, body in enumerate(bodies, start=1):
            q = {"marketplaceIds": marketplaceId, "requirements": req, "issueLocale": "en_US"}
            resp = _exec("PATCH", path, query=q, body=body)
            try: jr = resp.json()
            except Exception: jr = {"text": resp.text}
            if 200 <= resp.status_code < 300:
                return {"ok": True, "req": req, "variant": idx, "http": resp.status_code, "amazon": jr, "sent": {"query": q, "body": body}}
            if isinstance(jr, dict) and ("issues" in jr or "validationDetails" in jr):
                return {"ok": False, "req": req, "variant": idx, "http": resp.status_code, "amazon": jr, "sent": {"query": q, "body": body}}
    return {"ok": False, "http": 400, "amazon": {"errors": [{"code": "InvalidInput", "message": "Invalid parameters provided.", "details": ""}]}}

# 4) Price update endpoints (alias)
@app.post("/update-price")
@app.post("/update-price-fast")
def update_price(body: Dict[str, Any] = Body(..., example={
    "sku": "ELECTRIC PICKLE JUICE-64 OZ-FBA",
    "marketplaceId": "ATVPDKIKX0DER",
    "currency": "USD",
    "amount": 20.99
})):
    sku = body.get("sku")
    marketplaceId = body.get("marketplaceId") or MARKETPLACE_ID_DEFAULT
    currency = str(body.get("currency", "USD")).upper()
    amount = body.get("amount")
    if not (sku and marketplaceId and amount is not None):
        return JSONResponse(status_code=400, content={"error": "sku, marketplaceId, currency, amount are required"})
    if not SELLER_ID:
        return JSONResponse(status_code=500, content={"error": "SPAPI_SELLER_ID not set"})

    insp = _exec("GET", f"/listings/2021-08-01/items/{SELLER_ID}/{quote(sku, safe='')}",
                 query={"marketplaceIds": marketplaceId})
    try: insp_json = insp.json()
    except Exception: insp_json = {"text": insp.text}
    pt = None
    try:
        for s in (insp_json.get("summaries") or []):
            if s.get("marketplaceId") == marketplaceId and s.get("productType"):
                pt = s["productType"]; break
        if not pt and (insp_json.get("summaries") or []):
            pt = insp_json["summaries"][0].get("productType")
    except Exception:
        pt = None
    if not pt:
        pt = "PRODUCT"

    result = _try_patch_price(sku, marketplaceId, currency, float(amount), pt)
    status = 200 if result.get("ok") else (result.get("http") or 400)
    return JSONResponse(status_code=status if status < 500 else 502, content={"result": result})
