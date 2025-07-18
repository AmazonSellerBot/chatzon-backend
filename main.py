from fastapi import FastAPI, Request
from pydantic import BaseModel
import os
import requests
import datetime
import hashlib
import hmac
import json

app = FastAPI()

@app.get("/")
def root():
    return {"message": "ChatZon Backend is running 🚀"}

class PriceUpdateRequest(BaseModel):
    asin: str
    price: float

def get_access_token():
    lwa_client_id = os.environ['LWA_CLIENT_ID']
    lwa_client_secret = os.environ['LWA_CLIENT_SECRET']
    refresh_token = os.environ['LWA_REFRESH_TOKEN']

    url = "https://api.amazon.com/auth/o2/token"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": lwa_client_id,
        "client_secret": lwa_client_secret
    }

    response = requests.post(url, data=data)
    return response.json()["access_token"]

def execute_signed_request(endpoint, body, access_token):
    region = "us-east-1"
    host = "sellingpartnerapi-na.amazon.com"
    service = "execute-api"
    method = "POST"
    canonical_uri = "/feeds/2021-06-30/documents"

    access_key = os.environ['SPAPI_AWS_ACCESS_KEY_ID']
    secret_key = os.environ['SPAPI_AWS_SECRET_ACCESS_KEY']

    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')

    body_json = json.dumps(body)
    payload_hash = hashlib.sha256(body_json.encode('utf-8')).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-access-token:{access_token}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-access-token;x-amz-date"

    canonical_request = f"{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign(key, msg): return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    kDate = sign(('AWS4' + secret_key).encode('utf-8'), datestamp)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, service)
    kSigning = sign(kService, 'aws4_request')
    signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "x-amz-access-token": access_token,
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
        "Content-Type": "application/json"
    }

    response = requests.post(f"https://{host}{canonical_uri}", headers=headers, data=body_json)
    return response.json()

@app.post("/update-price")
def update_price(payload: PriceUpdateRequest):
    access_token = get_access_token()

    feed_document = {
        "contentType": "application/json"
    }

    # Step 1: Create Feed Document
    doc_response = execute_signed_request("/feeds/2021-06-30/documents", feed_document, access_token)
    upload_url = doc_response['url']
    document_id = doc_response['feedDocumentId']

    # Step 2: Upload listing update to that document
    listings_payload = {
        "sku": "electric-pickle-juice",  # Replace if needed
        "type": "price",
        "price": {
            "currency": "USD",
            "amount": str(payload.price)
        }
    }

    headers = {"Content-Type": "application/json"}
    requests.put(upload_url, data=json.dumps(listings_payload), headers=headers)

    # Step 3: Submit Feed with document ID
    feed_payload = {
        "feedType": "JSON_LISTINGS_FEED",
        "marketplaceIds": ["ATVPDKIKX0DER"],
        "inputFeedDocumentId": document_id
    }

    feed_response = execute_signed_request("/feeds/2021-06-30/feeds", feed_payload, access_token)
    return {"message": "Submitted price update feed", "feedId": feed_response.get("feedId")}
