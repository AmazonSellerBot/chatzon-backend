import os
import json
import datetime
import requests
from requests.auth import HTTPBasicAuth
import hashlib
import hmac
from dotenv import load_dotenv

load_dotenv()

def get_access_token():
    client_id = os.getenv("LWA_CLIENT_ID")
    client_secret = os.getenv("LWA_CLIENT_SECRET")
    refresh_token = os.getenv("SPAPI_REFRESH_TOKEN")

    response = requests.post(
        "https://api.amazon.com/auth/o2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    return response.json()["access_token"]

def sign_aws_request(method, service, region, endpoint, access_token, body=None, query=None):
    host = "sellingpartnerapi-na.amazon.com"
    amz_date = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    datestamp = datetime.datetime.utcnow().strftime('%Y%m%d')

    canonical_uri = endpoint
    canonical_querystring = ''
    if query:
        canonical_querystring = '&'.join([f"{k}={v}" for k, v in query.items()])

    payload = json.dumps(body) if body else ''
    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-access-token:{access_token}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"

    canonical_request = '\n'.join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    ])

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = '\n'.join([
        algorithm,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    ])

    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    secret = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")
    access_key = os.getenv("SPAPI_AWS_ACCESS_KEY_ID")

    kDate = sign(('AWS4' + secret).encode('utf-8'), datestamp)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, service)
    kSigning = sign(kService, 'aws4_request')

    signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    url = f"https://{host}{endpoint}"
    if canonical_querystring:
        url += f"?{canonical_querystring}"

    headers = {
        "x-amz-access-token": access_token,
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
        "Content-Type": "application/json"
    }

    return url, headers, payload

def execute_signed_request(method, endpoint, query=None, body=None):
    access_token = get_access_token()
    url, headers, data = sign_aws_request(
        method=method,
        service="execute-api",
        region="us-east-1",
        endpoint=endpoint,
        access_token=access_token,
        query=query,
        body=body
    )
    response = requests.request(method, url, headers=headers, data=data)
    return response.json()
