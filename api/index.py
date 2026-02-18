import os
import base64
import time
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from dotenv import load_dotenv

load_dotenv(dotenv_path="../.env")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

EB_API_URL = "https://api.enablebanking.com"

# In-memory session storage (for development only)
session_store = {}


def get_private_key() -> str:
    """Decode the base64-encoded private key from environment."""
    key_b64 = os.getenv("EB_PRIVATE_KEY_B64")
    if not key_b64:
        raise ValueError("EB_PRIVATE_KEY_B64 not set")
    return base64.b64decode(key_b64).decode("utf-8")


def generate_eb_jwt() -> str:
    """Generate a signed JWT for Enable Banking API requests."""
    app_id = os.getenv("EB_APPLICATION_ID")
    if not app_id:
        raise ValueError("EB_APPLICATION_ID not set")

    private_key = get_private_key()
    now = int(time.time())

    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": app_id
    }

    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + 3600
    }

    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def get_auth_headers() -> dict:
    """Get headers for Enable Banking API requests."""
    token = generate_eb_jwt()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/api/start-auth")
async def start_auth():
    """
    Start the Enable Banking authorization flow.
    Returns a URL to redirect the user to for bank authentication.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{EB_API_URL}/auth",
                headers=get_auth_headers(),
                json={
                    "access": {
                        "valid_until": (time.time() + 90 * 24 * 3600).__int__()  # 90 days
                    },
                    "aspsp": {
                        "name": "ABN AMRO",
                        "country": "NL"
                    },
                    "state": "daybal-auth",
                    "redirect_url": "http://localhost:5173/callback",
                    "psu_type": "personal"
                }
            )

            if response.status_code != 200:
                return {
                    "error": True,
                    "status": response.status_code,
                    "detail": response.text
                }

            data = response.json()
            session_store["auth_url"] = data.get("url")

            return {
                "auth_url": data.get("url"),
                "session_id": data.get("session_id")
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/callback")
async def handle_callback(code: str = None, state: str = None, error: str = None):
    """
    Handle the callback from Enable Banking after user authenticates.
    Exchange the auth code for a session.
    """
    if error:
        return {"error": True, "detail": error}

    if not code:
        return {"error": True, "detail": "No authorization code received"}

    try:
        async with httpx.AsyncClient() as client:
            # Complete the authorization
            response = await client.post(
                f"{EB_API_URL}/sessions",
                headers=get_auth_headers(),
                json={"code": code}
            )

            if response.status_code != 200:
                return {
                    "error": True,
                    "status": response.status_code,
                    "detail": response.text
                }

            data = response.json()
            session_store["session_id"] = data.get("session_id")
            session_store["accounts"] = data.get("accounts", [])

            return {
                "success": True,
                "session_id": data.get("session_id"),
                "accounts": data.get("accounts", [])
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/accounts")
async def get_accounts():
    """Get linked accounts from the current session."""
    if "accounts" not in session_store:
        return {"error": True, "detail": "No active session. Please authenticate first."}

    return {"accounts": session_store.get("accounts", [])}


@app.get("/api/balance/{account_id}")
async def get_balance(account_id: str):
    """Fetch the balance for a specific account."""
    session_id = session_store.get("session_id")

    if not session_id:
        return {"error": True, "detail": "No active session. Please authenticate first."}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{EB_API_URL}/accounts/{account_id}/balances",
                headers=get_auth_headers()
            )

            if response.status_code != 200:
                return {
                    "error": True,
                    "status": response.status_code,
                    "detail": response.text
                }

            return response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
