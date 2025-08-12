from fastapi import FastAPI, Body
from pydantic import BaseModel, Field, validator
from typing import Optional
import os

app = FastAPI(title="Chatzon Backend", version="1.0.0")

# -------- Models
class SetPriceRequest(BaseModel):
    sku: str = Field(..., description="Seller SKU")
    marketplaceId: str = Field(..., description="Marketplace ID (e.g., ATVPDKIKX0DER)")
    currency: str = Field(..., description="ISO currency, e.g., USD")
    amount: float = Field(..., gt=0, description="Price amount")

    @validator("currency")
    def currency_upper(cls, v):
        return v.upper()

# -------- Helpers
def _mask(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    if len(v) <= 6:
        return "***"
    return f"{v[:3]}***{v[-3:]}"

def env_snapshot():
    # We only display masked values for verification
    return {
        "SPAPI_AWS_ACCESS_KEY_ID": _mask(os.getenv("SPAPI_AWS_ACCESS_KEY_ID")),
        "SPAPI_AWS_SECRET_ACCESS_KEY": _mask(os.getenv("SPAPI_AWS_SECRET_ACCESS_KEY")),
        "SPAPI_REFRESH_TOKEN": _mask(os.getenv("SPAPI_REFRESH_TOKEN")),
        "SPAPI_SELLER_ID": _mask(os.getenv("SPAPI_SELLER_ID")),
        "SPAPI_ROLE_ARN": _mask(os.getenv("SPAPI_ROLE_ARN")),
        # Accept either SPAPI_* or legacy LWA_* names
        "SPAPI_LWA_CLIENT_ID": _mask(os.getenv("SPAPI_LWA_CLIENT_ID") or os.getenv("LWA_CLIENT_ID")),
        "SPAPI_LWA_CLIENT_SECRET": _mask(os.getenv("SPAPI_LWA_CLIENT_SECRET") or os.getenv("LWA_CLIENT_SECRET")),
        # FYI values you already had; harmless if missing
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
    ]
    missing = [k for k in required if not os.getenv(k)]
    return missing

# -------- Routes
@app.get("/")
def root():
    return {"ok": True, "service": "chatzon-backend", "version": "1.0.0"}

@app.get("/env")
def read_env():
    # Quick visibility that the aliases you added are loaded
    return {
        "ok": True,
        "missing_required": required_env_ok(),
        "vars": env_snapshot()
    }

@app.post("/set-price")
def set_price(payload: SetPriceRequest = Body(...)):
    """
    STEP 1 (now): Validate input + show the exact JSON we'll submit via SP-API JSON Listings feed.
    STEP 2 (next): I'll replace this stub with the live signed request so it actually updates your price.
    """
    missing = required_env_ok()
    if missing:
        return {
            "ok": False,
            "message": "Missing required environment variables. Add aliases in Railway.",
            "missing_env": missing,
            "env_seen": env_snapshot()
        }

    # Build the JSON Listings patch Amazon expects (preview only for this step)
    # Using purchasableOffer patch for price; marketplaceId, currency, amount from request
    # (We’ll wire this exact body into Feeds->JSON_LISTINGS_FEED in the next step.)
    preview_feed_body = {
        "sku": payload.sku,
        "marketplaceId": payload.marketplaceId,
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
                                    {
                                        "valueWithTax": payload.amount
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    return {
        "ok": True,
        "message": "Stub executed. Env looks good. Next step is enabling the live SP‑API call.",
        "echo": preview_feed_body
    }
