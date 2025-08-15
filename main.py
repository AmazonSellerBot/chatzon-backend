# main.py
# Chatzon Backend – Setup + Price Update (corrected schema)
# Endpoints:
#   GET  /health
#   GET  /check-setup
#   POST /update-price   { "sku": "...", "marketplaceId": "ATVPDKIKX0DER", "currency": "USD", "amount": 20.99 }

import os, hmac, hashlib, json, time, datetime
from typing import Optional, Dict, Any
from urllib.parse import urlencode
import requests
from fastapi import FastAPI, Body
from fastapi.responses import JSONResponse

# -----------------------------
# Env
# -----------------------------
LWA_CLIENT_ID = os.getenv("LWA_CLIENT_ID", "")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET", "")
LWA_REFRESH_TOKEN = os.getenv("LWA_REFRESH_TOKEN", "")

AWS_ACCESS_KEY = os.getenv("SPAPI_AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY", "")
AWS_REGION = os.getenv("REGION", "us-east-1")
ROLE_ARN = os.getenv("SPAPI_ROLE_ARN", "")

SP_API_ENDPOINT = os.getenv("SP_API_ENDPOINT", "https://sellingpartnerapi-na.amazon.com")
MARKETPLACE_ID_DEFAULT = os.getenv("SPAPI_MARKETPLACE_ID", "ATVPDKIKX0DER")
SELLER_ID = os.getenv("SPAPI_SELLER_ID", "")
APPLICATION_ID = os.getenv("SPAPI_APPLICATION_ID", "")

_session_cache: Dict[str, Any] = {"expires_at": 0, "creds": None}
def _now_epoch() -> int: return int(time.time())

def _assume_role_if_configured():
    global _session_cache
    if not ROLE_ARN: return None
    if _session_cache["creds"] and _session_cache["expires_at"] - 30 > _now_epoch():
        return _session_cache["creds"]
    try:
        import boto3  # type: ignore
        sts = boto3.client("sts", region_name=AWS_REGION,
                           aws_access_key_id=AWS_ACCESS_KEY,
                           aws_secret_access_key=AWS_SECRET_KEY)
        resp = sts.assume_role(RoleArn=ROLE_ARN, RoleSessionName="chatzon-spapi-session")
        creds = resp["Credentials"]
        _session_cache["creds"] = {
            "AccessKeyId": creds["AccessKeyId"],
            "SecretAccessKey": creds["SecretAccessKey"],
            "SessionToken": creds["SessionToken"],
        }
        _session_cache["expires_at"] = int(creds["Expiration"].timestamp())
        return _session_cache["creds"]
    except Exception:
        return None

def get_lwa_access_token() -> str:
    r = requests.post("https://api.amazon.com/auth/o2/token", data={
        "grant_type": "refresh_token",
        "refresh_token": LWA_REFRESH_TOKEN,
        "client_id": LWA_CLIENT_ID,
        "client_secret": LWA_CLIENT_SECRET,
    }, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"LWA token error {r.status_code}: {r.text}")
    return r.json()["access_token"]

def _sign(method: str, host: str, region: str, canonical_uri: str,
          canonical_querystring: str, headers: Dict[str, str],
          payload: bytes, aws_access_key: str, aws_secret_key: str,
          aws_session_token: Optional[str] = None) -> Dict[str, str]:
    service = "execute-api"
    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    canonical_headers_items = {"host": host, "x-amz-date": amz_date}
    for k, v in headers.items():
        canonical_headers_items[k.lower()] = v
    signed_headers_list = sorted(canonical_headers_items.keys())
    canonical_headers = "".join([f"{k}:{canonical_headers_items[k]}\n" for k in signed_headers_list])
    signed_headers = ";".join(signed_headers_list)
    payload_hash = hashlib.sha256(payload).hexdigest()

    canonical_request = "\n".join([
        method.upper(), canonical_uri, canonical_querystring,
        canonical_headers, signed_headers, payload_hash
    ])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        algorithm, amz_date, credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    ])

    def _hmac(key, msg): return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    k_date = _hmac(("AWS4" + aws_secret_key).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, b"execute-api", hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = {"x-amz-date": amz_date,
           "Authorization": f"{algorithm} Credential={aws_access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"}
    if aws_session_token: out["x-amz-security-token"] = aws_session_token
    return out

def execute_signed_request(method: str, path: str,
                           query: Optional[Dict[str, Any]] = None,
                           body_json: Optional[Dict[str, Any]] = None,
                           extra_headers: Optional[Dict[str, str]] = None) -> requests.Response:
    base_url = SP_API_ENDPOINT.rstrip("/")
    url = f"{base_url}{path}"
    host = base_url.replace("https://", "").replace("http://", "")
    canonical_querystring = urlencode(query or {}, doseq=True)

    payload_bytes = b""
    headers = {"content-type": "application/json"}
    data_str = None
    if body_json is not None:
        data_str = json.dumps(body_json, separators=(",", ":"), ensure_ascii=False)
        payload_bytes = data_str.encode("utf-8")

    headers["x-amz-access-token"] = get_lwa_access_token()
    if extra_headers: headers.update(extra_headers)

    creds = _assume_role_if_configured()
    if creds:
        ak, sk, st = creds["AccessKeyId"], creds["SecretAccessKey"], creds.get("SessionToken")
    else:
        ak, sk, st = AWS_ACCESS_KEY, AWS_SECRET_KEY, None

    signed = _sign(method, host, AWS_REGION, path, canonical_querystring,
                   {"x-amz-access-token": headers["x-amz-access-token"]},
                   payload_bytes, ak, sk, st)
    final_headers = {**headers, **signed}

    m = method.upper()
    if m == "GET":    return requests.get(url, headers=final_headers, params=query, timeout=60)
    if m == "POST":   return requests.post(url, headers=final_headers, params=query, data=data_str, timeout=60)
    if m == "PUT":    return requests.put(url, headers=final_headers, params=query, data=data_str, timeout=60)
    if m == "PATCH":  return requests.patch(url, headers=final_headers, params=query, data=data_str, timeout=60)
    if m == "DELETE": return requests.delete(url, headers=final_headers, params=query, data=data_str, timeout=60)
    raise ValueError(f"Unsupported method: {method}")

# -----------------------------
# FastAPI
# -----------------------------
app = FastAPI(title="Chatzon Backend – Setup + Price Update", version="2.3.0")

@app.get("/health")
def health():
    return {"ok": True, "service": "chatzon-backend", "time": datetime.datetime.utcnow().isoformat() + "Z"}

@app.get("/check-setup")
def check_setup():
    try:
        resp = execute_signed_request("GET", "/sellers/v1/marketplaceParticipations")
        out = {"status_code": resp.status_code, "content_type": resp.headers.get("content-type", "")}
        try: out["data"] = resp.json()
        except Exception: out["text"] = resp.text[:2000]
        return JSONResponse(status_code=resp.status_code if resp.status_code < 500 else 502, content=out)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# -----------------------------
# POST /update-price  (fixed schema)
# -----------------------------
@app.post("/update-price")
def update_price(payload: Dict[str, Any] = Body(..., example={
    "sku": "ELECTRIC PICKLE JUICE-64 OZ-FBA",
    "marketplaceId": "ATVPDKIKX0DER",
    "currency": "USD",
    "amount": 20.99
})):
    sku = payload.get("sku")
    marketplace_id = payload.get("marketplaceId") or MARKETPLACE_ID_DEFAULT
    currency = str(payload.get("currency", "USD")).upper()
    amount = payload.get("amount")

    if not sku or not marketplace_id or amount is None:
        return JSONResponse(status_code=400, content={"error": "sku, marketplaceId, currency, amount are required"})
    if not SELLER_ID:
        return JSONResponse(status_code=500, content={"error": "SPAPI_SELLER_ID is not set in environment"})

    # Correct Listings Items PATCH body per Amazon docs:
    # Each offer requires audience, currency, marketplace_id; price is numeric at value_with_tax.
    body = {
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/purchasable_offer",
                "value": [
                    {
                        "audience": "ALL",
                        "currency": currency,
                        "marketplace_id": marketplace_id,
                        "our_price": [
                            {
                                "schedule": [
                                    { "value_with_tax": round(float(amount), 2) }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    try:
        path = f"/listings/2021-08-01/items/{SELLER_ID}/{requests.utils.quote(sku, safe='')}"
        resp = execute_signed_request(
            method="PATCH",
            path=path,
            query={"marketplaceIds": [marketplace_id]},
            body_json=body,
        )
        try:
            data = resp.json()
        except Exception:
            data = {"text": resp.text[:2000]}
        return JSONResponse(status_code=resp.status_code if resp.status_code < 500 else 502, content=data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
