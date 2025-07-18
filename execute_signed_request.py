import hashlib
import hmac
import requests
import datetime
import os
import json

AWS_ACCESS_KEY = os.getenv("SPAPI_AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")
ROLE_ARN = os.getenv("SPAPI_ROLE_ARN")
LWA_CLIENT_ID = os.getenv("LWA_CLIENT_ID")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET")
REFRESH_TOKEN = os.getenv("SPAPI_REFRESH_TOKEN")
REGION = "us-east-1"
ENDPOINT = "https://sellingpartnerapi-na.amazon.com"

def get_access_token():
    url = "https://api.amazon.com/auth/o2/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": REFRESH_TOKEN,
        "client_id": LWA_CLIENT_ID,
        "client_secret": LWA_CLIENT_SECRET
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print("\n🔍 Sending LWA token request with:")
    print("URL:", url)
    print("Payload:", payload)

    response = requests.post(url, data=payload, headers=headers)

    try:
        response.raise_for_status()
        print("✅ LWA token acquired")
        return response.json()["access_token"]
    except requests.exceptions.HTTPError as e:
        print("❌ LWA token request failed:", response.text)
        raise e

def execute_signed_request(method, endpoint, body=None, query_string=None):
    access_token = get_access_token()
    service = "execute-api"
    host = "sellingpartnerapi-na.amazon.com"

    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    canonical_uri = endpoint
    canonical_querystring = query_string or ""
    request_parameters = body or {}
    payload = "" if method == "GET" else json.dumps(request_parameters)
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    canonical_headers = (
        f"host:{host}\n"
        f"x-amz-access-token:{access_token}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-access-token;x-amz-date"

    canonical_request = (
        f"{method}\n"
        f"{canonical_uri}\n"
        f"{canonical_querystring}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{REGION}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + AWS_SECRET_KEY).encode("utf-8"), date_stamp)
    k_region = sign(k_date, REGION)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={AWS_ACCESS_KEY}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "x-amz-date": amz_date,
        "x-amz-access-token": access_token,
        "Authorization": authorization_header,
        "Content-Type": "application/json"
    }

    url = ENDPOINT + canonical_uri
    print("\n📤 Sending signed SP-API request to:", url)
    print("Headers:", headers)
    print("Payload:", payload)

    response = requests.request(method, url, headers=headers, data=payload)
    response.raise_for_status()
    return response.json()
