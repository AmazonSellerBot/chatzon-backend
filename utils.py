import os
import time
import uuid
import requests
import hashlib
import hmac
import datetime
import urllib.parse

LWA_CLIENT_ID = os.getenv("LWA_CLIENT_ID")
LWA_CLIENT_SECRET = os.getenv("LWA_CLIENT_SECRET")
SPAPI_REFRESH_TOKEN = os.getenv("SPAPI_REFRESH_TOKEN")
AWS_ACCESS_KEY = os.getenv("SPAPI_AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")
ROLE_ARN = os.getenv("SPAPI_ROLE_ARN")
SELLER_ID = os.getenv("SELLER_ID")
REGION = "us-west-2"
SERVICE = "execute-api"

def get_access_token():
    url = "https://api.amazon.com/auth/o2/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": SPAPI_REFRESH_TOKEN,
        "client_id": LWA_CLIENT_ID,
        "client_secret": LWA_CLIENT_SECRET,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url, data=payload, headers=headers)
    return response.json()["access_token"]

def sign_request(method, service, host, region, endpoint, request_parameters, headers={}, body=""):
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')

    canonical_uri = urllib.parse.urlparse(endpoint).path or "/"
    canonical_querystring = urllib.parse.urlparse(endpoint).query

    canonical_headers = f'host:{host}\n'
    signed_headers = 'host'

    if method in ["POST", "PUT", "PATCH"]:
        payload_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()
    else:
        payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

    canonical_request = f'{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}'

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
    string_to_sign = f'{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()}'

    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    kDate = sign(('AWS4' + AWS_SECRET_KEY).encode('utf-8'), datestamp)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, service)
    kSigning = sign(kService, 'aws4_request')
    signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = (
        f'{algorithm} Credential={AWS_ACCESS_KEY}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, Signature={signature}'
    )

    headers.update({
        'Authorization': authorization_header,
        'x-amz-date': amz_date,
        'x-amz-access-token': get_access_token(),
        'Content-Type': 'application/json'
    })

    return headers

def execute_signed_request(method, endpoint, path, params={}, headers={}, data=""):
    url = f"{endpoint}{path}"
    if params:
        url += '?' + urllib.parse.urlencode(params)

    signed_headers = sign_request(
        method=method,
        service=SERVICE,
        host="sellingpartnerapi-na.amazon.com",
        region=REGION,
        endpoint=url,
        request_parameters=params,
        headers=headers,
        body=data
    )

    response = requests.request(
        method=method,
        url=url,
        headers=signed_headers,
        data=data
    )

    return response
