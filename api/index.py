import os
import base64
import time
import hashlib
from datetime import datetime, timedelta
from statistics import median
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from dotenv import load_dotenv

load_dotenv(dotenv_path="../.env")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://daybal.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

EB_API_URL = "https://api.enablebanking.com"

# In-memory storage (for development - will be replaced with database)
session_store = {}
pin_attempts = {}  # IP -> {"count": int, "last_attempt": timestamp}
MAX_PIN_ATTEMPTS = 5
PIN_LOCKOUT_SECONDS = 300  # 5 minutes


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


def get_client_ip(request: Request) -> str:
    """Get client IP for rate limiting."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(ip: str) -> tuple[bool, int]:
    """Check if IP is rate limited. Returns (is_allowed, seconds_remaining)."""
    if ip not in pin_attempts:
        return True, 0

    attempt_data = pin_attempts[ip]
    now = time.time()

    # Reset if lockout period has passed
    if now - attempt_data["last_attempt"] > PIN_LOCKOUT_SECONDS:
        pin_attempts[ip] = {"count": 0, "last_attempt": now}
        return True, 0

    if attempt_data["count"] >= MAX_PIN_ATTEMPTS:
        remaining = int(PIN_LOCKOUT_SECONDS - (now - attempt_data["last_attempt"]))
        return False, remaining

    return True, 0


def record_pin_attempt(ip: str, success: bool):
    """Record a PIN attempt for rate limiting."""
    now = time.time()
    if ip not in pin_attempts:
        pin_attempts[ip] = {"count": 0, "last_attempt": now}

    if success:
        # Reset on success
        pin_attempts[ip] = {"count": 0, "last_attempt": now}
    else:
        pin_attempts[ip]["count"] += 1
        pin_attempts[ip]["last_attempt"] = now


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/api/verify-pin")
async def verify_pin(request: Request):
    """Verify the user's PIN with rate limiting."""
    ip = get_client_ip(request)

    # Check rate limit
    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        return {
            "error": True,
            "locked": True,
            "detail": f"Too many attempts. Try again in {remaining} seconds.",
            "remaining_seconds": remaining
        }

    body = await request.json()
    pin = body.get("pin", "")
    correct_pin = os.getenv("APP_PIN", "")

    if not correct_pin:
        return {"error": True, "detail": "PIN not configured on server"}

    if pin == correct_pin:
        record_pin_attempt(ip, success=True)
        # Generate a simple session token
        session_token = hashlib.sha256(f"{ip}{time.time()}{pin}".encode()).hexdigest()[:32]
        session_store["authenticated"] = True
        session_store["session_token"] = session_token
        return {"success": True, "session_token": session_token}
    else:
        record_pin_attempt(ip, success=False)
        attempts_left = MAX_PIN_ATTEMPTS - pin_attempts[ip]["count"]
        return {
            "error": True,
            "detail": "Incorrect PIN",
            "attempts_left": attempts_left
        }


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
                    "redirect_url": os.getenv("REDIRECT_URL", "https://daybal.vercel.app/callback"),
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
            session_store["bank_connected"] = True

            return {
                "success": True,
                "session_id": data.get("session_id"),
                "accounts": data.get("accounts", [])
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/session-status")
async def session_status():
    """Check if bank is connected."""
    return {
        "bank_connected": session_store.get("bank_connected", False),
        "has_accounts": len(session_store.get("accounts", [])) > 0
    }


@app.get("/api/accounts")
async def get_accounts():
    """Get linked accounts from the current session."""
    if "accounts" not in session_store:
        return {"error": True, "detail": "No active session. Please authenticate first."}

    return {"accounts": session_store.get("accounts", [])}


@app.get("/api/balance")
async def get_balance():
    """Fetch the current balance for the first linked account."""
    if not session_store.get("bank_connected"):
        return {"error": True, "detail": "Bank not connected"}

    accounts = session_store.get("accounts", [])
    if not accounts:
        return {"error": True, "detail": "No accounts found"}

    # Use the first account
    account_id = accounts[0].get("account_id") or accounts[0].get("uid")

    if not account_id:
        return {"error": True, "detail": "No account ID found", "accounts": accounts}

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

            data = response.json()

            # Extract balance amount
            balances = data.get("balances", [])
            if balances:
                # Prefer "expected" or "available" balance type
                for bal in balances:
                    if bal.get("balance_type") in ["expected", "available", "closingBooked"]:
                        return {
                            "balance": float(bal.get("balance_amount", {}).get("amount", 0)),
                            "currency": bal.get("balance_amount", {}).get("currency", "EUR"),
                            "type": bal.get("balance_type"),
                            "date": bal.get("reference_date")
                        }
                # Fallback to first balance
                bal = balances[0]
                return {
                    "balance": float(bal.get("balance_amount", {}).get("amount", 0)),
                    "currency": bal.get("balance_amount", {}).get("currency", "EUR"),
                    "type": bal.get("balance_type"),
                    "date": bal.get("reference_date")
                }

            return {"error": True, "detail": "No balance data found", "raw": data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/balance/{account_id}")
async def get_balance_by_id(account_id: str):
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


@app.get("/api/comparison-data")
async def get_comparison_data():
    """
    Get comparison data: current balance vs historical medians/averages.
    For now, returns mock historical data. Will be replaced with database queries.
    """
    # Get current balance first
    balance_response = await get_balance()

    if balance_response.get("error"):
        return balance_response

    current_balance = balance_response.get("balance", 0)

    # TODO: Replace with actual database queries
    # For now, return the current balance with placeholder comparison values
    # These will be populated once we have historical data

    today = datetime.now()
    day_of_month = today.day

    return {
        "current_balance": current_balance,
        "currency": balance_response.get("currency", "EUR"),
        "date": balance_response.get("date"),
        "day_of_month": day_of_month,
        "median_12m": None,  # Will be calculated from DB
        "average_24m": None,  # Will be calculated from DB
        "historical_data_available": False,
        "message": "Historical data collection not yet started. Check back after data has been collected."
    }
