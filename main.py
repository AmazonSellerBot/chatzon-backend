from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Chatzon backend is live!"}

@app.get("/callback")
async def callback_handler(request: Request):
    query_params = dict(request.query_params)
    return HTMLResponse(content=f"""
        <html>
        <body>
            <h2>Authorization Code Received</h2>
            <pre>{query_params}</pre>
        </body>
        </html>
    """)
