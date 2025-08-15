# main.py
# FastAPI app to sanity-check SP-API credentials and signing.
# Endpoints:
#   GET /health
#   GET /check-setup  -> calls /sellers/v1/marketplaceParticipations

import os
import hmac
import hashlib
import json
import time
import datetime
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import requests
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# -----------------------------
# Environment variables (required)
# -----------------------------
LWA_CLIENT_ID = os.getenv("LWA_CLIENT_ID", "")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET", "")
LWA_REFRESH_TOKEN = os.getenv("LWA_REFRESH_TOKEN", "")

AWS_ACCESS_KEY = os.getenv("SPAPI_AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY", "")
AWS_REGION = os.getenv("REGION", "us-east-1")
ROLE_ARN = os.getenv("SPAPI_ROLE_ARN", "")  # optional, recommended

SP_API_ENDPOINT = os.getenv("SP_API_ENDPOINT", "https://sellingpartnerapi-na.amazon.com")
MARKETPLACE_ID = os.getenv("SPAPI_MARKETPLACE_ID", "ATVPDKIKX0DER")  # US default
SELLER_ID = os.getenv("SPAPI_SELLER_ID", "")  # optional (not needed for this check)
APPLICATION_ID = os.getenv("SPAPI_APPLICATION_ID", "")  # optional (Solution ID)

# -----------------------------
# Optional: assume role with boto3 if available & ROLE_ARN set
# -----------------------------
_session_cache: Dict[str, Any] = {"expires_at": 0, "creds": None}

def _now_epoch() -> int:
    return int(time.time())

def _assume_role_if_configured():
    """
    If ROLE_ARN is set and boto3 is available, attempt to assume role.
    Cache creds until they expire; otherwise fall back to static keys.
    """
    global _session_cache
    if not ROLE_ARN:
        return None

    # Use cache if still valid (30s buffer)
    if _session_cache["creds"] and _session_cache["expires_at"] - 30 > _now_epoch():
        return _session_cache["creds"]

    try:
        import boto3  # type: ignore
        sts = boto3.client(
            "sts",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
        )
        resp = sts.assume_role(RoleArn=ROLE_ARN, RoleSessionName="chatzon-spapi-session")
        creds = resp["Credentials"]
        _session_cache["creds"] = {
            "AccessKeyId": creds["AccessKeyId"],
            "SecretAccessKey": creds["SecretAccessKey"],
            "SessionToken": creds["SessionToken"],
        }
        _session_cache["expires_at"] = int(creds["Expiration"].timestamp())
        return _session_cache["creds"]
    except Exception as e:
        # If boto3 not installed or assume_role fails, just return None to use base keys
        return None

# -----------------------------
# LWA access token
# -----------------------------
def get_lwa_access_token() -> str:
    """
    Exchange LWA refresh token for an access token.
    """
    url = "https://api.amazon.com/auth/o2/token"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": LWA_REFRESH_TOKEN,
        "client_id": LWA_CLIENT_ID,
        "client_secret": LWA_CLIENT_SECRET,
    }
    r = requests.post(url, data=data, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"LWA token error {r.status_code}: {r.text}")
    return r.json()["access_token"]

# -----------------------------
# SigV4 signing for SP-API (service execute-api)
# -----------------------------
def _sign(
    method: str,
    host: str,
    region: str,
    canonical_uri: str,
    canonical_querystring: str,
    headers: Dict[str, str],
    payload: bytes,
    aws_access_key: str,
    aws_secret_key: str,
    aws_session_token: Optional[str] = None,
) -> Dict[str, str]:
    """
    Create AWS SigV4 headers for SP-API (execute-api).
    """
    service = "execute-api"
    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    # Required headers
    canonical_headers_items = {
        "host": host,
        "x-amz-date": amz_date,
    }
    # Merge caller headers (e.g., x-amz-access-token)
    for k, v in headers.items():
        canonical_headers_items[k.lower()] = v

    signed_headers_list = sorted(canonical_headers_items.keys())
    canonical_headers = "".join([f"{k}:{canonical_headers_items[k]}\n" for k in signed_headers_list])
    signed_headers = ";".join(signed_headers_list)

    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    def _sign_hmac(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _sign_hmac(("AWS4" + aws_secret_key).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} "
        f"Credential={aws_access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    out_headers = {
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
    }
    if aws_session_token:
        out_headers["x-amz-security-token"] = aws_session_token
    return out_headers

def execute_signed_request(
    method: str,
    path: str,
    query: Optional[Dict[str, Any]] = None,
    body_json: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    """
    Execute a signed HTTP request to SP-API.
    """
    base_url = SP_API_ENDPOINT.rstrip("/")
    url = f"{base_url}{path}"
    host = base_url.replace("https://", "").replace("http://", "")

    # Querystring
    canonical_querystring = urlencode(query or {}, doseq=True)

    # Body
    payload_bytes = b""
    headers = {"content-type": "application/json"}
    if body_json is not None:
        data_str = json.dumps(body_json, separators=(",", ":"), ensure_ascii=False)
        payload_bytes = data_str.encode("utf-8")
    else:
        data_str = None

    # LWA access token
    access_token = get_lwa_access_token()
    headers["x-amz-access-token"] = access_token

    # Merge extra headers (if any)
    if extra_headers:
        headers.update(extra_headers)

    # Credentials: prefer assumed role if possible
    creds = _assume_role_if_configured()
    if creds:
        ak = creds["AccessKeyId"]
        sk = creds["SecretAccessKey"]
        st = creds.get("SessionToken")
    else:
        ak = AWS_ACCESS_KEY
        sk = AWS_SECRET_KEY
        st = None

    # SigV4
    signed = _sign(
        method=method,
        host=host,
        region=AWS_REGION,
        canonical_uri=path,
        canonical_querystring=canonical_querystring,
        headers={"x-amz-access-token": headers["x-amz-access-token"]},
        payload=payload_bytes,
        aws_access_key=ak,
        aws_secret_key=sk,
        aws_session_token=st,
    )

    # Final headers (include those signed + our originals)
    final_headers = {**headers, **signed}

    # Dispatch
    if method.upper() == "GET":
        return requests.get(url, headers=final_headers, params=query, timeout=60)
    elif method.upper() == "POST":
        return requests.post(url, headers=final_headers, params=query, data=data_str, timeout=60)
    elif method.upper() == "PUT":
        return requests.put(url, headers=final_headers, params=query, data=data_str, timeout=60)
    elif method.upper() == "DELETE":
        return requests.delete(url, headers=final_headers, params=query, data=data_str, timeout=60)
    else:
        raise ValueError(f"Unsupported method: {method}")

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(title="Chatzon Backend – Setup Check", version="2.1.0")

@app.get("/health")
def health():
    return {"ok": True, "service": "chatzon-backend", "time": datetime.datetime.utcnow().isoformat() + "Z"}

@app.get("/check-setup")
def check_setup():
    """
    Calls /sellers/v1/marketplaceParticipations to verify:
      - LWA token exchange works
      - SigV4 signing works
      - AWS creds/role are valid
      - Endpoint/region/headers are correct
    """
    try:
        resp = execute_signed_request(
            method="GET",
            path="/sellers/v1/marketplaceParticipations",
        )
        content_type = resp.headers.get("content-type", "")
        out: Dict[str, Any] = {
            "status_code": resp.status_code,
            "content_type": content_type,
        }
        try:
            out["data"] = resp.json()
        except Exception:
            out["text"] = resp.text[:2000]
        return JSONResponse(status_code=resp.status_code if resp.status_code < 500 else 502, content=out)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)},
        )
