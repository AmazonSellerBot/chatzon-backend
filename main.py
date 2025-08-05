from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Chatzon backend is running."}

@app.get("/callback")
async def callback(request: Request):
    code = request.query_params.get("spapi_oauth_code")
    state = request.query_params.get("state")

    if not code:
        return JSONResponse(status_code=400, content={"error": "No authorization code found."})

    return {
        "message": "Authorization code received!",
        "authorization_code": code,
        "state": state
    }
