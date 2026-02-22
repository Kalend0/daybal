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
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    id INTEGER PRIMARY KEY,
                    median_months INTEGER NOT NULL DEFAULT 12,
                    average_months INTEGER NOT NULL DEFAULT 24,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
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


def get_user_preferences() -> dict:
    """Return saved interval preferences, or defaults if not set."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT median_months, average_months FROM user_preferences WHERE id = 1")
            row = cur.fetchone()
            if row:
                return {"median_months": row[0], "average_months": row[1]}
        return {"median_months": 12, "average_months": 24}
    finally:
        conn.close()


def save_user_preferences(median_months: int, average_months: int):
    """Upsert the single-row preferences record."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_preferences (id, median_months, average_months, updated_at)
                VALUES (1, %s, %s, NOW())
                ON CONFLICT (id) DO UPDATE
                    SET median_months = EXCLUDED.median_months,
                        average_months = EXCLUDED.average_months,
                        updated_at = NOW()
                """,
                (median_months, average_months)
            )
        conn.commit()
    finally:
        conn.close()


def get_historical_balances(day_of_month: int, months: int) -> list[float]:
    """
    Return one balance per calendar month for the last N months.
    Picks the record closest to day_of_month within each month,
    so the result is meaningful even when there is no transaction
    on the exact target day.
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (DATE_TRUNC('month', recorded_date))
                    balance_amount
                FROM daily_balances
                WHERE recorded_date >= NOW() - (%s * INTERVAL '1 month')
                  AND recorded_date < NOW()
                ORDER BY
                    DATE_TRUNC('month', recorded_date),
                    ABS(EXTRACT(DAY FROM recorded_date) - %s),
                    recorded_date DESC
                """,
                (months, day_of_month)
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


@app.get("/api/preferences")
async def preferences_get():
    """Return saved interval window preferences."""
    try:
        return get_user_preferences()
    except Exception as e:
        return {"median_months": 12, "average_months": 24, "error": str(e)}


@app.post("/api/preferences")
async def preferences_save(request: Request):
    """Persist interval window preferences."""
    body = await request.json()
    median_months = int(body.get("median_months", 12))
    average_months = int(body.get("average_months", 24))
    try:
        save_user_preferences(median_months, average_months)
        return {"success": True}
    except Exception as e:
        return {"error": True, "detail": str(e)}


@app.get("/api/backfill")
async def backfill_historical(account_uid: str = None, offset_months: int = 0):
    """
    Store end-of-day balances for one calendar month using balance_after_transaction
    values from Enable Banking transactions. Only the target month is fetched, so
    each call is fast regardless of how far back offset_months goes.

    Run for offset_months = 0, 1, 2, ..., 23 to populate 24 months of history.
    """
    try:
        uid = account_uid
        if not uid:
            try:
                session = get_active_session()
                if session:
                    uid = session["account_uid"]
            except Exception as e:
                return {"error": True, "step": "get_session", "detail": str(e)}
        if not uid:
            return {"error": True, "step": "resolve_uid",
                    "detail": "No account UID. Pass ?account_uid=<uid> or reconnect your bank."}

        # Target month boundaries
        today = datetime.now()
        month = today.month - offset_months
        year = today.year + (month - 1) // 12
        month = ((month - 1) % 12) + 1
        first_of_month = datetime(year, month, 1)
        if month == 12:
            last_of_month = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            last_of_month = datetime(year, month + 1, 1) - timedelta(days=1)

        # Only fetch the target month — balance_after_transaction is self-contained
        date_from = first_of_month.strftime("%Y-%m-%d")
        date_to = min(last_of_month, today).strftime("%Y-%m-%d")

        # Fetch transactions for target month only (fast, bounded)
        all_transactions = []
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
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
                            "step": "fetch_transactions",
                            "status": response.status_code,
                            "detail": response.text[:500],
                        }

                    data = response.json()
                    txns = data.get("transactions", [])
                    # EB returns a flat list for this account
                    if isinstance(txns, dict):
                        txns = txns.get("booked", []) + txns.get("pending", [])
                    all_transactions.extend(txns)

                    continuation_key = data.get("continuation_key")
                    if not continuation_key:
                        break
        except Exception as e:
            return {"error": True, "step": "fetch_transactions",
                    "detail": f"{type(e).__name__}: {e}"}

        if not all_transactions:
            return {"success": True, "date_from": date_from, "date_to": date_to,
                    "transactions_fetched": 0, "days_saved": 0,
                    "note": "No transactions in this period"}

        # Extract end-of-day balance from balance_after_transaction.
        # ABN AMRO format: {"currency": "EUR", "amount": "2550.9"}
        # Last transaction of each day gives the closing balance for that day.
        daily_map: dict[str, float] = {}
        no_balance_count = 0
        for txn in all_transactions:
            bal = txn.get("balance_after_transaction")
            if not isinstance(bal, dict):
                no_balance_count += 1
                continue
            date_str = txn.get("booking_date")
            try:
                val = float(bal.get("amount", "nan"))
                if date_str and not (val != val):  # nan check
                    daily_map[date_str] = val      # last txn of day wins
            except (ValueError, TypeError):
                pass

        if not daily_map and no_balance_count == len(all_transactions):
            return {"error": True, "step": "parse",
                    "detail": "No balance_after_transaction found in any transaction. "
                              "Bank may not support this field."}

        saved, errors = 0, []
        for date_str, balance in daily_map.items():
            try:
                upsert_daily_balance(date_str, balance)
                saved += 1
            except Exception as e:
                errors.append(f"{date_str}: {e}")

        return {
            "success": True,
            "date_from": date_from,
            "date_to": date_to,
            "offset_months": offset_months,
            "transactions_fetched": len(all_transactions),
            "days_saved": saved,
            "errors": errors[:5],
        }

    except Exception as e:
        return {"error": True, "step": "unhandled", "detail": f"{type(e).__name__}: {e}"}


@app.get("/api/db-stats")
async def db_stats():
    """Show how many balance records exist per month in daily_balances."""
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    TO_CHAR(DATE_TRUNC('month', recorded_date), 'YYYY-MM') AS month,
                    COUNT(*) AS records,
                    MIN(balance_amount) AS min_bal,
                    MAX(balance_amount) AS max_bal
                FROM daily_balances
                GROUP BY DATE_TRUNC('month', recorded_date)
                ORDER BY DATE_TRUNC('month', recorded_date) DESC
            """)
            rows = cur.fetchall()
        conn.close()
        return {
            "total_months": len(rows),
            "months": [
                {"month": r[0], "records": r[1],
                 "min": float(r[2]), "max": float(r[3])}
                for r in rows
            ]
        }
    except Exception as e:
        return {"error": True, "detail": str(e)}


@app.get("/api/debug-transactions")
async def debug_transactions(account_uid: str):
    """Return the raw Enable Banking transactions response for inspection."""
    try:
        today = datetime.now()
        date_from = today.replace(day=1).strftime("%Y-%m-%d")
        date_to = today.strftime("%Y-%m-%d")
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                f"{EB_API_URL}/accounts/{account_uid}/transactions",
                headers=get_auth_headers(),
                params={"date_from": date_from, "date_to": date_to},
            )
            data = response.json()
            # Return the structure and first 2 transactions without modification
            txns_raw = data.get("transactions", "__key_missing__")
            return {
                "status": response.status_code,
                "top_level_keys": list(data.keys()),
                "transactions_value_type": type(txns_raw).__name__,
                "transactions_sub_keys": list(txns_raw.keys()) if isinstance(txns_raw, dict) else None,
                "first_2_transactions": (
                    txns_raw[:2] if isinstance(txns_raw, list)
                    else txns_raw.get("booked", [])[:2] if isinstance(txns_raw, dict)
                    else txns_raw
                ),
                "raw_data_keys_only": {k: type(v).__name__ for k, v in data.items()},
            }
    except Exception as e:
        return {"error": True, "detail": f"{type(e).__name__}: {e}"}


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
