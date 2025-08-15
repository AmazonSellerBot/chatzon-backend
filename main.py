# main.py
# Chatzon Backend – Catalog check + Listings inspect + Robust price update
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
def _now(): return int(time.time())

def _assume_role():
    if not ROLE_ARN: return None
    if _session["creds"] and _session["expires_at"] - 30 > _now(): return _session["creds"]
    try:
        import boto3  # type: ignore
        sts = boto3.client("sts",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY)
        r = sts.assume_role(RoleArn=ROLE_ARN, RoleSessionName="chatzon-spapi-session")
        c = r["Credentials"]
        _session["creds"] = {"AccessKeyId": c["AccessKeyId"], "SecretAccessKey": c["SecretAccessKey"], "SessionToken": c["SessionToken"]}
        _session["expires_at"] = int(c["Expiration"].timestamp())
        return _session["creds"]
    except Exception:
        return None

def _get_lwa():
    r = requests.post("https://api.amazon.com/auth/o2/token", data={
        "grant_type":"refresh_token","refresh_token":LWA_REFRESH_TOKEN,
        "client_id":LWA_CLIENT_ID,"client_secret":LWA_CLIENT_SECRET
    }, timeout=30)
    if r.status_code!=200: raise RuntimeError(f"LWA token error {r.status_code}: {r.text}")
    return r.json()["access_token"]

def _sign(method, host, region, uri, qs, hdrs, payload, ak, sk, st=None):
    svc="execute-api"; t=datetime.datetime.utcnow()
    amz=t.strftime("%Y%m%dT%H%M%SZ"); d=t.strftime("%Y%m%d")
    ch={"host":host,"x-amz-date":amz}
    for k,v in hdrs.items(): ch[k.lower()]=v
    sh=";".join(sorted(ch.keys()))
    chs="".join([f"{k}:{ch[k]}\n" for k in sorted(ch.keys())])
    ph=hashlib.sha256(payload).hexdigest()
    creq="\n".join([method.upper(),uri,qs,chs,sh,ph])
    alg="AWS4-HMAC-SHA256"; scope=f"{d}/{region}/{svc}/aws4_request"
    s2s="\n".join([alg,amz,scope,hashlib.sha256(creq.encode()).hexdigest()])
    def h(k,m): return hmac.new(k,m.encode(),hashlib.sha256).digest()
    kdate=h(("AWS4"+sk).encode(),d); kreg=h(kdate,region)
    ksvc=h(kreg,svc); ksig=h(ksvc,"aws4_request")
    sig=hmac.new(ksig,s2s.encode(),hashlib.sha256).hexdigest()
    out={"x-amz-date":amz,"Authorization":f"{alg} Credential={ak}/{scope}, SignedHeaders={sh}, Signature={sig}"}
    if st: out["x-amz-security-token"]=st
    return out

def _exec(method, path, query=None, body=None):
    base=SP_API_ENDPOINT.rstrip("/"); url=f"{base}{path}"; host=base.replace("https://","").replace("http://","")
    qs=urlencode(query or {}, doseq=True)
    headers={"accept":"application/json","content-type":"application/json","x-amz-access-token":_get_lwa()}
    data=None; payload=b""
    if body is not None:
        data=json.dumps(body, separators=(",", ":"), ensure_ascii=False); payload=data.encode()
    creds=_assume_role()
    if creds: ak,sk,st=creds["AccessKeyId"],creds["SecretAccessKey"],creds.get("SessionToken")
    else: ak,sk,st=AWS_ACCESS_KEY,AWS_SECRET_KEY,None
    signed=_sign(method,host,AWS_REGION,path,qs,{"x-amz-access-token":headers["x-amz-access-token"],"content-type":headers["content-type"]},payload,ak,sk,st)
    hdr={**headers,**signed}
    m=method.upper()
    if m=="GET":    return requests.get(url,headers=hdr,params=query,timeout=60)
    if m=="PATCH":  return requests.patch(url,headers=hdr,params=query,data=data,timeout=60)
    if m=="POST":   return requests.post(url,headers=hdr,params=query,data=data,timeout=60)
    if m=="PUT":    return requests.put(url,headers=hdr,params=query,data=data,timeout=60)
    if m=="DELETE": return requests.delete(url,headers=hdr,params=query,data=data,timeout=60)
    raise ValueError("bad method")

# ===== App =====
app = FastAPI(title="Chatzon Backend – Catalog+Listings+PriceUpdate", version="2.8.0")

@app.get("/health")
def health(): return {"ok":True,"service":"chatzon-backend","time":datetime.datetime.utcnow().isoformat()+"Z"}

# 1) Catalog lookup by SKU (sanity: does Amazon recognize this SKU?)
@app.get("/catalog-by-sku")
def catalog_by_sku(sku: str = Query(...), marketplaceId: str = Query(MARKETPLACE_ID_DEFAULT)):
    resp = _exec("GET", "/catalog/2022-04-01/items",
                 query={"identifiers": sku, "identifiersType": "SKU", "marketplaceIds": marketplaceId, "includedData": "summaries,identifiers"})
    try: body=resp.json()
    except Exception: body={"text": resp.text}
    return JSONResponse(status_code=resp.status_code if resp.status_code<500 else 502,
                        content={"status_code":resp.status_code,
                                 "x-amzn-RequestId": resp.headers.get("x-amzn-RequestId"),
                                 "result": body})

# 2) Listings Items GET (if accepted, returns summaries incl. productType)
@app.get("/inspect-listing")
def inspect_listing(sku: str = Query(...), marketplaceId: str = Query(MARKETPLACE_ID_DEFAULT)):
    path=f"/listings/2021-08-01/items/{SELLER_ID}/{quote(sku, safe='')}"
    resp=_exec("GET", path, query={"marketplaceIds": marketplaceId})
    try: body=resp.json()
    except Exception: body={"text": resp.text}
    # Extract productType if present
    pt=None
    try:
        for s in (body.get("summaries") or []):
            if s.get("marketplaceId")==marketplaceId and s.get("productType"):
                pt=s["productType"]; break
        if not pt and (body.get("summaries") or []):
            pt=body["summaries"][0].get("productType")
    except Exception: pt=None
    return JSONResponse(status_code=resp.status_code if resp.status_code<500 else 502,
                        content={"status_code":resp.status_code,
                                 "x-amzn-RequestId": resp.headers.get("x-amzn-RequestId"),
                                 "productType": pt,
                                 "raw": body})

# --- Price helpers (two attribute paths + two requirement modes) ---
def _bodies_for_price(currency: str, amount: float, productType: str) -> List[Dict[str, Any]]:
    amt = round(float(amount), 2)
    # A) purchasable_offer, value_with_tax as NUMBER
    a = {
        "productType": productType,
        "patches": [{
            "op":"replace","path":"/attributes/purchasable_offer",
            "value":[{"currency": currency, "our_price":[{"schedule":[{"value_with_tax": amt}]}]}]
        }]
    }
    # B) purchasable_offer, value_with_tax OBJECT
    b = {
        "productType": productType,
        "patches": [{
            "op":"replace","path":"/attributes/purchasable_offer",
            "value":[{"currency": currency, "our_price":[{"schedule":[{"value_with_tax":{"value": amt, "currency": currency}}]}]}]
        }]
    }
    # C) standard_price (common alt)
    c = {
        "productType": productType,
        "patches": [{
            "op":"replace","path":"/attributes/standard_price",
            "value":[{"value": {"value": amt, "currency": currency}}]
        }]
    }
    # D) standard_price as value_with_tax
    d = {
        "productType": productType,
        "patches": [{
            "op":"replace","path":"/attributes/standard_price",
            "value":[{"value_with_tax": {"value": amt, "currency": currency}}]
        }]
    }
    return [a,b,c,d]

def _try_patch_price(sku: str, marketplaceId: str, currency: str, amount: float, productType: str):
    path=f"/listings/2021-08-01/items/{SELLER_ID}/{quote(sku, safe='')}"
    bodies = _bodies_for_price(currency, amount, productType)
    last=None
    # Try both requirement modes
    for req in ("LISTING_OFFER_ONLY","LISTING"):
        for idx, body in enumerate(bodies, start=1):
            q={"marketplaceIds": marketplaceId, "requirements": req, "issueLocale":"en_US"}
            resp=_exec("PATCH", path, query=q, body=body)
            last={"req":req,"variant":idx,"status":resp.status_code,"headers":dict(resp.headers)}
            try: jr=resp.json()
            except Exception: jr={"text": resp.text}
            last["response"]=jr
            if 200 <= resp.status_code < 300:
                return {"ok":True, "req":req, "variant":idx, "http":resp.status_code, "amazon": jr, "sent": {"query": q, "body": body}}
            # If Amazon provides detailed issues, stop and show them
            if isinstance(jr, dict) and ("issues" in jr or "validationDetails" in jr):
                return {"ok":False, "req":req, "variant":idx, "http":resp.status_code, "amazon": jr, "sent": {"query": q, "body": body}}
            # otherwise loop to next
    return {"ok":False, "last": last}

# 3) Price update endpoints (alias)
@app.post("/update-price")
@app.post("/update-price-fast")
def update_price(body: Dict[str, Any] = Body(..., example={
    "sku":"ELECTRIC PICKLE JUICE-64 OZ-FBA","marketplaceId":"ATVPDKIKX0DER","currency":"USD","amount":20.99
})):
    sku = body.get("sku")
    marketplaceId = body.get("marketplaceId") or MARK
ETPLACE_ID_DEFAULT
    currency = str(body.get("currency","USD")).upper()
    amount = body.get("amount")
    if not (sku and marketplaceId and amount is not None):
        return JSONResponse(status_code=400, content={"error":"sku, marketplaceId, currency, amount are required"})
    if not SELLER_ID:
        return JSONResponse(status_code=500, content={"error":"SPAPI_SELLER_ID not set"})

    # Discover productType (Listings Items GET). If it 400s, fall back to 'PRODUCT'.
    insp = _exec("GET", f"/listings/2021-08-01/items/{SELLER_ID}/{quote(sku, safe='')}",
                 query={"marketplaceIds": marketplaceId})
    try: insp_json = insp.json()
    except Exception: insp_json = {"text": insp.text}
    pt=None
    try:
        for s in (insp_json.get("summaries") or []):
            if s.get("marketplaceId")==marketplaceId and s.get("productType"): pt=s["productType"]; break
        if not pt and (insp_json.get("summaries") or []): pt=insp_json["summaries"][0].get("productType")
    except Exception: pt=None
    if not pt: pt="PRODUCT"

    result=_try_patch_price(sku, marketplaceId, currency, float(amount), pt)
    status = 200 if result.get("ok") else (result.get("http") or 400)
    return JSONResponse(status_code=status if status<500 else 502, content={"result": result})
