import os
import base64
import time
import hashlib
from datetime import datetime, timedelta, timezone
from statistics import median
import psycopg2
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

# In-memory rate limiting (resets per cold start — acceptable for PIN brute-force protection)
pin_attempts = {}
MAX_PIN_ATTEMPTS = 5
PIN_LOCKOUT_SECONDS = 300


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Open and return a psycopg2 connection."""
    url = os.getenv("DATABASE_URL")
    if not url:
        raise ValueError("DATABASE_URL environment variable is not set")
    return psycopg2.connect(url)


def init_db():
    """Create tables if they don't exist. Call once via /api/setup-db."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    session_id TEXT,
                    account_uid TEXT NOT NULL,
                    expiry_date TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS daily_balances (
                    id SERIAL PRIMARY KEY,
                    recorded_date DATE NOT NULL UNIQUE,
                    balance_amount DECIMAL(15,2) NOT NULL,
                    currency TEXT DEFAULT 'EUR',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
        conn.commit()
    finally:
        conn.close()


def save_session(session_id: str, account_uid: str, expiry_days: int = 90):
    """Persist a bank session to the database."""
    conn = get_db()
    try:
        expiry = datetime.now(timezone.utc) + timedelta(days=expiry_days)
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (session_id, account_uid, expiry_date) VALUES (%s, %s, %s)",
                (session_id, account_uid, expiry)
            )
        conn.commit()
    finally:
        conn.close()


def get_active_session() -> dict | None:
    """Return the most recent non-expired session, or None."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT session_id, account_uid, expiry_date
                FROM sessions
                WHERE expiry_date > NOW()
                ORDER BY created_at DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
            if row:
                return {"session_id": row[0], "account_uid": row[1], "expiry_date": row[2]}
            return None
    finally:
        conn.close()


def upsert_daily_balance(date: str, amount: float, currency: str = "EUR"):
    """Insert or update today's balance snapshot."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_balances (recorded_date, balance_amount, currency)
                VALUES (%s, %s, %s)
                ON CONFLICT (recorded_date) DO UPDATE
                    SET balance_amount = EXCLUDED.balance_amount,
                        currency = EXCLUDED.currency
                """,
                (date, amount, currency)
            )
        conn.commit()
    finally:
        conn.close()


def get_historical_balances(day_of_month: int, months: int) -> list[float]:
    """Return balance amounts for the same day-of-month over the last N months."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT balance_amount
                FROM daily_balances
                WHERE EXTRACT(DAY FROM recorded_date) = %s
                  AND recorded_date >= NOW() - (%s * INTERVAL '1 month')
                ORDER BY recorded_date DESC
                """,
                (day_of_month, months)
            )
            return [float(row[0]) for row in cur.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Enable Banking helpers
# ---------------------------------------------------------------------------

def get_private_key() -> str:
    key_b64 = os.getenv("EB_PRIVATE_KEY_B64")
    if not key_b64:
        raise ValueError("EB_PRIVATE_KEY_B64 not set")
    return base64.b64decode(key_b64).decode("utf-8")


def generate_eb_jwt() -> str:
    app_id = os.getenv("EB_APPLICATION_ID")
    if not app_id:
        raise ValueError("EB_APPLICATION_ID not set")

    private_key = get_private_key()
    now = int(time.time())

    headers = {"alg": "RS256", "typ": "JWT", "kid": app_id}
    payload = {
        "iss": "enablebanking.com",
        "aud": "api.enablebanking.com",
        "iat": now,
        "exp": now + 3600,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def get_auth_headers() -> dict:
    return {
        "Authorization": f"Bearer {generate_eb_jwt()}",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(ip: str) -> tuple[bool, int]:
    if ip not in pin_attempts:
        return True, 0
    attempt_data = pin_attempts[ip]
    now = time.time()
    if now - attempt_data["last_attempt"] > PIN_LOCKOUT_SECONDS:
        pin_attempts[ip] = {"count": 0, "last_attempt": now}
        return True, 0
    if attempt_data["count"] >= MAX_PIN_ATTEMPTS:
        remaining = int(PIN_LOCKOUT_SECONDS - (now - attempt_data["last_attempt"]))
        return False, remaining
    return True, 0


def record_pin_attempt(ip: str, success: bool):
    now = time.time()
    if ip not in pin_attempts:
        pin_attempts[ip] = {"count": 0, "last_attempt": now}
    if success:
        pin_attempts[ip] = {"count": 0, "last_attempt": now}
    else:
        pin_attempts[ip]["count"] += 1
        pin_attempts[ip]["last_attempt"] = now


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/setup-db")
async def setup_db():
    """Create database tables. Call once after first deploy."""
    try:
        init_db()
        return {"success": True, "message": "Tables created (or already exist)"}
    except Exception as e:
        return {"error": True, "detail": str(e)}


@app.post("/api/verify-pin")
async def verify_pin(request: Request):
    ip = get_client_ip(request)

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        return {
            "error": True,
            "locked": True,
            "detail": f"Too many attempts. Try again in {remaining} seconds.",
            "remaining_seconds": remaining,
        }

    body = await request.json()
    pin = body.get("pin", "")
    correct_pin = os.getenv("APP_PIN", "")

    if not correct_pin:
        return {"error": True, "detail": "PIN not configured on server"}

    if pin == correct_pin:
        record_pin_attempt(ip, success=True)
        return {"success": True}
    else:
        record_pin_attempt(ip, success=False)
        attempts_left = MAX_PIN_ATTEMPTS - pin_attempts[ip]["count"]
        return {"error": True, "detail": "Incorrect PIN", "attempts_left": attempts_left}


@app.get("/api/start-auth")
async def start_auth():
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{EB_API_URL}/auth",
                headers=get_auth_headers(),
                json={
                    "access": {"valid_until": int(time.time() + 90 * 24 * 3600)},
                    "aspsp": {"name": "ABN AMRO", "country": "NL"},
                    "state": "daybal-auth",
                    "redirect_url": os.getenv("REDIRECT_URL", "https://daybal.vercel.app/callback"),
                    "psu_type": "personal",
                },
            )
            if response.status_code != 200:
                return {"error": True, "status": response.status_code, "detail": response.text}
            data = response.json()
            return {"auth_url": data.get("url"), "session_id": data.get("session_id")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/callback")
async def handle_callback(code: str = None, state: str = None, error: str = None):
    if error:
        return {"error": True, "detail": error}
    if not code:
        return {"error": True, "detail": "No authorization code received"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{EB_API_URL}/sessions",
                headers=get_auth_headers(),
                json={"code": code},
            )
            if response.status_code != 200:
                return {"error": True, "status": response.status_code, "detail": response.text}

            data = response.json()
            session_id = data.get("session_id")
            accounts = data.get("accounts", [])

            account_uids = [acc.get("uid") for acc in accounts if acc.get("uid")]

            # Persist session to database
            if account_uids:
                try:
                    save_session(session_id, account_uids[0], expiry_days=90)
                except Exception as db_err:
                    # Log but don't fail — client still gets account_uid via localStorage
                    print(f"DB save_session error: {db_err}")

            return {
                "success": True,
                "session_id": session_id,
                "account_uids": account_uids,
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/session-status")
async def session_status():
    """Check DB for a valid (non-expired) bank session."""
    try:
        session = get_active_session()
        if session:
            return {
                "bank_connected": True,
                "account_uid": session["account_uid"],
            }
    except Exception as e:
        print(f"DB session_status error: {e}")

    return {"bank_connected": False, "account_uid": None}


@app.get("/api/balance")
async def get_balance(account_uid: str = None):
    """Fetch the current balance. Falls back to DB session if no account_uid passed."""
    account_id = account_uid
    if not account_id:
        try:
            session = get_active_session()
            if session:
                account_id = session["account_uid"]
        except Exception:
            pass

    if not account_id:
        return {"error": True, "detail": "No account UID available. Please reconnect your bank."}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{EB_API_URL}/accounts/{account_id}/balances",
                headers=get_auth_headers(),
            )
            if response.status_code != 200:
                return {"error": True, "status": response.status_code, "detail": response.text}

            data = response.json()
            balances = data.get("balances", [])
            if balances:
                for bal in balances:
                    if bal.get("balance_type") in ["expected", "available", "closingBooked"]:
                        return {
                            "balance": float(bal["balance_amount"]["amount"]),
                            "currency": bal["balance_amount"].get("currency", "EUR"),
                            "type": bal.get("balance_type"),
                            "date": bal.get("reference_date"),
                        }
                bal = balances[0]
                return {
                    "balance": float(bal["balance_amount"]["amount"]),
                    "currency": bal["balance_amount"].get("currency", "EUR"),
                    "type": bal.get("balance_type"),
                    "date": bal.get("reference_date"),
                }
            return {"error": True, "detail": "No balance data found", "raw": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/comparison-data")
async def get_comparison_data(
    account_uid: str = None,
    median_months: int = 12,
    average_months: int = 24,
):
    """Current balance vs N-month median and M-month average (same day-of-month)."""
    balance_response = await get_balance(account_uid=account_uid)
    if balance_response.get("error"):
        return balance_response

    current_balance = balance_response["balance"]
    currency = balance_response.get("currency", "EUR")
    today = datetime.now()
    day_of_month = today.day

    median_val = None
    average_val = None
    historical_data_available = False

    try:
        values_median = get_historical_balances(day_of_month, months=median_months)
        values_average = get_historical_balances(day_of_month, months=average_months)

        if values_median:
            median_val = median(values_median)
        if values_average:
            average_val = sum(values_average) / len(values_average)

        historical_data_available = bool(values_median or values_average)
    except Exception as e:
        print(f"DB historical query error: {e}")

    return {
        "current_balance": current_balance,
        "currency": currency,
        "date": balance_response.get("date"),
        "day_of_month": day_of_month,
        "median_months": median_months,
        "average_months": average_months,
        "median_val": median_val,
        "average_val": average_val,
        "historical_data_available": historical_data_available,
    }


@app.get("/api/backfill")
async def backfill_historical(account_uid: str = None):
    """
    Populate daily_balances with up to 24 months of history from Enable Banking
    transaction data. Call once after initial setup.
    Uses balance_after_transaction if available; otherwise reconstructs from
    current balance by reversing transactions chronologically.
    """
    uid = account_uid
    if not uid:
        try:
            session = get_active_session()
            if session:
                uid = session["account_uid"]
        except Exception:
            pass
    if not uid:
        return {"error": True, "detail": "No account UID available"}

    # Anchor: current balance
    balance_response = await get_balance(account_uid=uid)
    if balance_response.get("error"):
        return {"error": True, "detail": "Failed to fetch current balance"}

    current_balance = balance_response["balance"]
    currency = balance_response.get("currency", "EUR")

    # Fetch all transactions for the past 24 months (handle pagination)
    date_from = (datetime.now() - timedelta(days=730)).strftime("%Y-%m-%d")
    date_to = datetime.now().strftime("%Y-%m-%d")
    all_transactions = []

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            continuation_key = None
            while True:
                params = {"date_from": date_from, "date_to": date_to}
                if continuation_key:
                    params["continuation_key"] = continuation_key

                response = await client.get(
                    f"{EB_API_URL}/accounts/{uid}/transactions",
                    headers=get_auth_headers(),
                    params=params,
                )
                if response.status_code != 200:
                    return {
                        "error": True,
                        "status": response.status_code,
                        "detail": response.text,
                    }

                data = response.json()
                transactions = data.get("transactions", [])
                all_transactions.extend(transactions)

                continuation_key = data.get("continuation_key")
                if not continuation_key:
                    break
    except Exception as e:
        return {"error": True, "detail": f"Failed to fetch transactions: {e}"}

    if not all_transactions:
        return {"error": True, "detail": "No transactions returned from Enable Banking"}

    # Determine strategy: use balance_after_transaction if present
    has_balance_after = any(t.get("balance_after_transaction") for t in all_transactions)

    daily_map: dict[str, float] = {}  # date -> closing balance

    if has_balance_after:
        # Direct: pick the last balance_after_transaction for each date
        for txn in all_transactions:
            bal = txn.get("balance_after_transaction")
            if not bal:
                continue
            date_str = txn.get("booking_date")
            amount_str = (
                bal.get("balance_amount", {}).get("amount")
                or bal.get("amount", {}).get("amount")
            )
            if date_str and amount_str:
                daily_map[date_str] = float(amount_str)
    else:
        # Reconstruct: start from today's balance and work backwards
        sorted_txns = sorted(
            all_transactions,
            key=lambda t: t.get("booking_date", ""),
            reverse=True,  # newest first
        )
        running = current_balance
        for txn in sorted_txns:
            date_str = txn.get("booking_date")
            raw_amount = txn.get("amount", {})
            try:
                amount = float(raw_amount.get("amount", 0))
            except (ValueError, TypeError):
                continue

            # Record running balance as end-of-day for this date (first time we see it)
            if date_str and date_str not in daily_map:
                daily_map[date_str] = running

            # Reverse the transaction to get the balance before it
            indicator = txn.get("credit_debit_indicator", "CRDT")
            if indicator == "CRDT":
                running -= amount
            else:
                running += amount

    # Upsert into daily_balances
    saved, errors = 0, []
    for date_str, balance in daily_map.items():
        try:
            upsert_daily_balance(date_str, balance, currency)
            saved += 1
        except Exception as e:
            errors.append(f"{date_str}: {e}")

    return {
        "success": True,
        "transactions_fetched": len(all_transactions),
        "days_saved": saved,
        "method": "balance_after_transaction" if has_balance_after else "reconstruction",
        "errors": errors[:10],
    }


@app.get("/api/record-balance")
async def record_balance():
    """
    Cron endpoint: fetch and store today's balance snapshot.
    Scheduled daily at 23:55 UTC via vercel.json crons.
    """
    try:
        session = get_active_session()
    except Exception as e:
        return {"error": True, "detail": f"DB error getting session: {e}"}

    if not session:
        return {"error": True, "detail": "No active bank session found"}

    balance_response = await get_balance(account_uid=session["account_uid"])
    if balance_response.get("error"):
        return balance_response

    today = datetime.now().strftime("%Y-%m-%d")
    amount = balance_response["balance"]
    currency = balance_response.get("currency", "EUR")

    try:
        upsert_daily_balance(today, amount, currency)
    except Exception as e:
        return {"error": True, "detail": f"DB upsert error: {e}"}

    return {
        "success": True,
        "recorded_date": today,
        "balance_amount": amount,
        "currency": currency,
    }
