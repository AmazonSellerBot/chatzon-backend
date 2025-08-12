# main.py
import os, hmac, json, gzip, hashlib, datetime as dt, logging
from typing import Optional
from urllib.parse import quote

import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("chatzon")
APP_NAME = "Chatzon SP-API Bridge"

for k in ["LWA_CLIENT_ID","LWA_CLIENT_SECRET","LWA_REFRESH_TOKEN","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","SELLER_ID","REGION","SP_API_ENDPOINT"]:
    if not os.getenv(k): log.warning(f"ENV {k} is not set")

LWA_CLIENT_ID=os.getenv("LWA_CLIENT_ID",""); LWA_CLIENT_SECRET=os.getenv("LWA_CLIENT_SECRET",""); LWA_REFRESH_TOKEN=os.getenv("LWA_REFRESH_TOKEN","")
AWS_ACCESS_KEY_ID=os.getenv("AWS_ACCESS_KEY_ID",""); AWS_SECRET_ACCESS_KEY=os.getenv("AWS_SECRET_ACCESS_KEY",""); AWS_SESSION_TOKEN=os.getenv("AWS_SESSION_TOKEN","")
SELLER_ID=os.getenv("SELLER_ID",""); REGION=os.getenv("REGION","us-east-1")
SP_API_ENDPOINT=os.getenv("SP_API_ENDPOINT","https://sellingpartnerapi-na.amazon.com")
SERVICE="execute-api"

app = FastAPI(title=APP_NAME)

def get_lwa_access_token()->str:
    r=requests.post("https://api.amazon.com/auth/o2/token",data={
        "grant_type":"refresh_token","refresh_token":LWA_REFRESH_TOKEN,"client_id":LWA_CLIENT_ID,"client_secret":LWA_CLIENT_SECRET
    },timeout=30)
    if r.status_code!=200:
        log.error(f"LWA token error: {r.status_code} {r.text}"); raise HTTPException(500,"Failed to obtain LWA access token")
    return r.json()["access_token"]

def _sign(key:bytes,msg:str)->bytes:
    import hashlib as _hs; return hmac.new(key,msg.encode("utf-8"),_hs.sha256).digest()

def _get_signature_key(key:str,date_stamp:str,region_name:str,service_name:str)->bytes:
    k_date=_sign(("AWS4"+key).encode("utf-8"),date_stamp)
    import hashlib as _hs
    k_region=hmac.new(k_date,region_name.encode("utf-8"),_hs.sha256).digest()
    k_service=hmac.new(k_region,service_name.encode("utf-8"),_hs.sha256).digest()
    return hmac.new(k_service,b"aws4_request",_hs.sha256).digest()

def execute_signed_request(method:str,path:str,query:str="",body:Optional[str]=None,extra_headers:Optional[dict]=None):
    extra_headers=extra_headers or {}
    access_token=get_lwa_access_token()
    t=dt.datetime.utcnow(); amz_date=t.strftime("%Y%m%dT%H%M%SZ"); date_stamp=t.strftime("%Y%m%d")
    host=SP_API_ENDPOINT.replace("https://","").replace("http://","")
    # IMPORTANT: URL-encode the path for SigV4
    canonical_uri = quote(path, safe="/-_.~")
    canonical_querystring=query or ""
    payload=(body or ""); payload_hash=hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # Only send minimal headers for GET; include content-type only when sending a body
    headers={"host":host,"x-amz-date":amz_date,"x-amz-access-token":access_token}
    if payload: headers["content-type"]=extra_headers.get("content-type","application/json")
    for k,v in extra_headers.items(): headers[k.lower()]=v

    signed_headers=";".join(sorted(headers.keys()))
    canonical_headers="".join([f"{h}:{headers[h]}\n" for h in sorted(headers.keys())])
    canonical_request="\n".join([method.upper(),canonical_uri,canonical_querystring,canonical_headers,signed_headers,payload_hash])

    algorithm="AWS4-HMAC-SHA256"; credential_scope=f"{date_stamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign="\n".join([algorithm,amz_date,credential_scope,hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    signing_key=_get_signature_key(AWS_SECRET_ACCESS_KEY,date_stamp,REGION,SERVICE)
    signature=hmac.new(signing_key,string_to_sign.encode("utf-8"),hashlib.sha256).hexdigest()

    final_headers={("host" if k.lower()=="host" else k):v for k,v in headers.items()}
    final_headers["Authorization"]=f"{algorithm} Credential={AWS_ACCESS_KEY_ID}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    if AWS_SESSION_TOKEN: final_headers["x-amz-security-token"]=AWS_SESSION_TOKEN

    url=f"{SP_API_ENDPOINT}{path}"; 
    if canonical_querystring: url+=f"?{canonical_querystring}"
    return requests.request(method,url,headers=final_headers,data=payload,timeout=60)

class PriceUpdatePayload(BaseModel):
    sku:str; marketplaceId:str; amount:float; currency:str="USD"

def build_json_listings_price_feed(sku:str,marketplace_id:str,amount:float,currency:str="USD")->str:
    msg={"sku":sku,"operationType":"PATCH","productType":"PRODUCT","patches":[{"op":"replace","path":"/attributes/standard_price","value":[{"currency":currency,"amount":round(float(amount),2)}]}]}
    return json.dumps({"header":{"sellerId":SELLER_ID,"version":"2.0"},"messages":[msg]},separators=(",",":"))

def create_feed_document()->dict:
    r=execute_signed_request("POST","/feeds/2021-06-30/documents",body=json.dumps({"contentType":"application/json; charset=UTF-8"}),extra_headers={"content-type":"application/json; charset=UTF-8"})
    if r.status_code not in (200,201): raise HTTPException(r.status_code,f"createFeedDocument failed: {r.text}")
    return r.json()

def upload_feed_to_s3(url:str,feed_body:str,content_type:str="application/json; charset=UTF-8"):
    put=requests.put(url,data=feed_body.encode("utf-8"),headers={"Content-Type":content_type},timeout=60)
    if put.status_code not in (200,201): raise HTTPException(put.status_code,f"S3 upload failed: {put.text}")

def create_feed(feed_document_id:str,feed_type:str,marketplace_ids:list[str])->dict:
    r=execute_signed_request("POST","/feeds/2021-06-30/feeds",body=json.dumps({"feedType":feed_type,"marketplaceIds":marketplace_ids,"inputFeedDocumentId":feed_document_id}),extra_headers={"content-type":"application/json; charset=UTF-8"})
    if r.status_code not in (200,201,202): raise HTTPException(r.status_code,f"createFeed failed: {r.text}")
    return r.json()

def get_feed(feed_id:str)->dict:
    r=execute_signed_request("GET",f"/feeds/2021-06-30/feeds/{feed_id}")
    if r.status_code==404 or (r.status_code!=200 and "NotFound" in r.text):
        alt=execute_signed_request("GET","/feeds/2021-06-30/feeds",query=f"feedIds={feed_id}")
        if alt.status_code==200 and alt.json().get("feeds"): return alt.json()["feeds"][0]
    if r.status_code!=200: raise HTTPException(r.status_code,f"getFeed failed: {r.text}")
    return r.json()

def list_recent_feeds(max_results:int=20,feed_type:str="JSON_LISTINGS_FEED")->dict:
    created_since=(dt.datetime.utcnow()-dt.timedelta(days=2)).replace(microsecond=0).isoformat()+"Z"
    r=execute_signed_request("GET","/feeds/2021-06-30/feeds",query=f"maxResults={max_results}&createdSince={created_since}&feedTypes={feed_type}")
    if r.status_code!=200: raise HTTPException(r.status_code,f"listFeeds failed: {r.text}")
    return r.json()

def get_feed_document(feed_document_id:str)->dict:
    # ensure path segment is encoded for signing, but original path string is correct
    r=execute_signed_request("GET",f"/feeds/2021-06-30/documents/{feed_document_id}")
    if r.status_code!=200: raise HTTPException(r.status_code,f"getFeedDocument failed: {r.text}")
    return r.json()

def download_processing_report(url:str,compression_algorithm:Optional[str])->dict|str:
    r=requests.get(url,timeout=60)
    if r.status_code!=200: raise HTTPException(r.status_code,f"download report failed: {r.text}")
    content=r.content
    if (compression_algorithm or "").upper()=="GZIP": content=gzip.decompress(content)
    try: return json.loads(content.decode("utf-8"))
    except Exception: return content.decode("utf-8",errors="replace")

@app.get("/")
def root(): return {"ok": True}

@app.get("/health")
def health(): return {"app":APP_NAME,"status":"ok","time_utc":dt.datetime.utcnow().isoformat()+"Z"}

@app.get("/diag/lwa")
def diag_lwa():
    r=requests.post("https://api.amazon.com/auth/o2/token",data={
        "grant_type":"refresh_token","refresh_token":os.getenv("LWA_REFRESH_TOKEN",""),"client_id":os.getenv("LWA_CLIENT_ID",""),"client_secret":os.getenv("LWA_CLIENT_SECRET","")
    },timeout=30)
    ct=r.headers.get("content-type",""); body=r.json() if "application/json" in ct else r.text
    return {"status":r.status_code,"body":body}

class PriceUpdateResponse(BaseModel):
    status:str; feedId:Optional[str]=None; feedDocumentId:Optional[str]=None; note:Optional[str]=None

@app.post("/update-price-fast", response_model=PriceUpdateResponse)
def update_price_fast(payload:PriceUpdatePayload):
    feed_body=build_json_listings_price_feed(payload.sku,payload.marketplaceId,payload.amount,payload.currency)
    doc=create_feed_document(); upload_feed_to_s3(doc["url"],feed_body)
    created=create_feed(doc["feedDocumentId"],"JSON_LISTINGS_FEED",[payload.marketplaceId])
    return PriceUpdateResponse(status="submitted",feedId=created.get("feedId"),feedDocumentId=doc["feedDocumentId"],note="Use /feed-status?feedId=... until DONE, or call /feed-report-by-doc?docId=...")

@app.get("/feed-status")
def feed_status(feedId:str=Query(...)): return get_feed(feedId)

@app.get("/feeds/recent")
def feeds_recent(maxResults:int=Query(20,ge=1,le=100),feedType:str="JSON_LISTINGS_FEED"): return list_recent_feeds(max_results=maxResults,feed_type=feedType)

@app.get("/feed-report")
def feed_report(feedId:str=Query(...)):
    info=get_feed(feedId); doc_id=info.get("resultFeedDocumentId")
    if not doc_id: raise HTTPException(400,"Feed not DONE yet or no resultFeedDocumentId present.")
    doc=get_feed_document(doc_id)
    return {"feedId":feedId,"compression":doc.get("compressionAlgorithm"),"report":download_processing_report(doc["url"],doc.get("compressionAlgorithm"))}

@app.get("/feed-report-by-doc")
def feed_report_by_doc(docId:str=Query(...)):
    doc=get_feed_document(docId.strip())
    return {"feedDocumentId":docId,"compression":doc.get("compressionAlgorithm"),"report":download_processing_report(doc["url"],doc.get("compressionAlgorithm"))}

@app.get("/oauth/callback")
def oauth_callback(code:Optional[str]=None,state:Optional[str]=None,selling_partner_id:Optional[str]=None):
    return {"received":True,"code":code,"state":state,"selling_partner_id":selling_partner_id}
