from fastapi import FastAPI, Body
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any
import os, json, hmac, hashlib, requests
from datetime import datetime
from urllib.parse import urlencode, quote
import boto3

# =========================
# FastAPI app
# =========================
app = FastAPI(title="Chatzon Backend", version="2.0.0")

# =========================
# Models
# =========================
class SetPriceRequest(BaseModel):
    sku: str = Field(..., description="Seller SKU")
    marketplaceId: str = Field(..., description="Marketplace ID (e.g., ATVPDKIKX0DER)")
    currency: str = Field(..., description="ISO currency, e.g., USD")
    amount: float = Field(..., gt=0, description="New price")

    @validator("currency")
    def currency_upper(cls, v):
        return v.upper()

# =========================
# Helpers
# =========================
def _mask(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    if len(v) <= 6:
        return "***"
    return f"{v[:3]}***{v[-3:]}"

def env_snapshot():
    return {
        "SPAPI_AWS_ACCESS_KEY_ID": _mask(os.getenv("SPAPI_AWS_ACCESS_KEY_ID")),
        "SPAPI_AWS_SECRET_ACCESS_KEY": _mask(os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")),
        "SPAPI_REFRESH_TOKEN": _mask(os.getenv("SPAPI_REFRESH_TOKEN")),
        "SPAPI_SELLER_ID": _mask(os.getenv("SPAPI_SELLER_ID")),
        "SPAPI_ROLE_ARN": _mask(os.getenv("SPAPI_ROLE_ARN")),
        "SPAPI_LWA_CLIENT_ID": _mask(os.getenv("SPAPI_LWA_CLIENT_ID") or os.getenv("LWA_CLIENT_ID")),
        "SPAPI_LWA_CLIENT_SECRET": _mask(os.getenv("SPAPI_LWA_CLIENT_SECRET") or os.getenv("LWA_CLIENT_SECRET")),
        # legacy names (harmless)
        "AWS_ACCESS_KEY_ID": _mask(os.getenv("AWS_ACCESS_KEY_ID")),
        "AWS_SECRET_ACCESS_KEY": _mask(os.getenv("AWS_SECRET_ACCESS_KEY")),
        "LWA_REFRESH_TOKEN": _mask(os.getenv("LWA_REFRESH_TOKEN")),
        "SELLER_ID": _mask(os.getenv("SELLER_ID")),
    }

def required_env_ok():
    required = [
        "SPAPI_AWS_ACCESS_KEY_ID",
        "SPAPI_AWS_SECRET_ACCESS_KEY",
        "SPAPI_REFRESH_TOKEN",
        "SPAPI_SELLER_ID",
        "SPAPI_ROLE_ARN",
    ]
    missing = [k for k in required if not os.getenv(k)]
    # LWA client id/secret can come from either SPAPI_* or legacy names
    if not (os.getenv("SPAPI_LWA_CLIENT_ID") or os.getenv("LWA_CLIENT_ID")):
        missing.append("SPAPI_LWA_CLIENT_ID or LWA_CLIENT_ID")
    if not (os.getenv("SPAPI_LWA_CLIENT_SECRET") or os.getenv("LWA_CLIENT_SECRET")):
        missing.append("SPAPI_LWA_CLIENT_SECRET or LWA_CLIENT_SECRET")
    return missing

# ----- LWA Access Token
def get_lwa_access_token() -> str:
    client_id = os.getenv("SPAPI_LWA_CLIENT_ID") or os.getenv("LWA_CLIENT_ID")
    client_secret = os.getenv("SPAPI_LWA_CLIENT_SECRET") or os.getenv("LWA_CLIENT_SECRET")
    refresh_token = os.getenv("SPAPI_REFRESH_TOKEN") or os.getenv("LWA_REFRESH_TOKEN")

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    r = requests.post("https://api.amazon.com/auth/o2/token", data=data, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"LWA token error: {r.status_code} {r.text}")
    return r.json()["access_token"]

# ----- Assume Role for SigV4
def assume_role() -> Dict[str, str]:
    role_arn = os.getenv("SPAPI_ROLE_ARN")
    access_key = os.getenv("SPAPI_AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")

    sts = boto3.client(
        "sts",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
    )
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="ChatzonSpApiSession")
    creds = resp["Credentials"]
    return {
        "AccessKeyId": creds["AccessKeyId"],
        "SecretAccessKey": creds["SecretAccessKey"],
        "SessionToken": creds["SessionToken"],
    }

# ----- SigV4
def sign_spapi_request(
    method: str,
    path: str,
    query: Dict[str, Any],
    body: Optional[str],
    access_token: str,
    creds: Dict[str, str],
    region: str = "us-east-1",
    service: str = "execute-api",
    host: str = "sellingpartnerapi-na.amazon.com",
):
    t = datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    canonical_uri = path
    canonical_querystring = urlencode(
        [(k, v) for k, v in query.items()], quote_via=quote, safe="~"
    ) if query else ""

    payload_hash = hashlib.sha256((body or "").encode("utf-8")).hexdigest()

    canonical_headers = (
        f"host:{host}\n"
        f"x-amz-access-token:{access_token}\n"
        f"x-amz-date:{amz_date}\n"
        f"x-amz-security-token:{creds['SessionToken']}\n"
    )
    signed_headers = "host;x-amz-access-token;x-amz-date;x-amz-security-token"

    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    ])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        algorithm,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    ])

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + creds["SecretAccessKey"]).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={creds['AccessKeyId']}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "host": host,
        "content-type": "application/json",
        "x-amz-access-token": access_token,
        "x-amz-date": amz_date,
        "x-amz-security-token": creds["SessionToken"],
        "authorization": authorization_header,
    }

    url = f"https://{host}{path}"
    if canonical_querystring:
        url += f"?{canonical_querystring}"

    return url, headers

def listings_items_patch(
    seller_id: str, sku: str, marketplace_id: str, body: Dict[str, Any]
) -> Dict[str, Any]:
    access_token = get_lwa_access_token()
    creds = assume_role()

    method = "PATCH"
    path = f"/listings/2021-08-01/items/{seller_id}/{quote(sku, safe='~')}"
    query = {"marketplaceIds": marketplace_id}
    body_str = json.dumps(body, separators=(",", ":"))

    url, headers = sign_spapi_request(method, path, query, body_str, access_token, creds)
    resp = requests.request(method, url, headers=headers, data=body_str, timeout=60)

    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}

    return {"status_code": resp.status_code, "data": data}

# =========================
# Routes
# =========================
@app.get("/")
def root():
    return {"ok": True, "service": "chatzon-backend", "version": "2.0.0"}

@app.get("/env")
def read_env():
    return {"ok": True, "missing_required": required_env_ok(), "vars": env_snapshot()}

@app.post("/set-price")
def set_price(payload: SetPriceRequest = Body(...)):
    missing = required_env_ok()
    if missing:
        return {
            "ok": False,
            "message": "Missing required environment variables. Add aliases in Railway.",
            "missing_env": missing,
            "env_seen": env_snapshot()
        }

    seller_id = os.getenv("SPAPI_SELLER_ID")
    # Build Listings Items patch body
    patch_body = {
        "productType": "PRODUCT",
        "patches": [
            {
                "op": "replace",
                "path": "/attributes/purchasableOffer",
                "value": [
                    {
                        "marketplaceId": payload.marketplaceId,
                        "currency": payload.currency,
                        "ourPrice": [
                            {
                                "schedule": [
                                    {"valueWithTax": payload.amount}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    result = listings_items_patch(
        seller_id=seller_id,
        sku=payload.sku,
        marketplace_id=payload.marketplaceId,
        body=patch_body
    )

    return {
        "ok": result["status_code"] in (200, 202),
        "status_code": result["status_code"],
        "request": {
            "sku": payload.sku,
            "marketplaceId": payload.marketplaceId,
            "body": patch_body
        },
        "response": result["data"]
    }
