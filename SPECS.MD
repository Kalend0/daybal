Technical Specification: DayBal

**Overview**
DayBal is a private, secure web application designed to track and compare a personal bank balance (ABN AMRO via Enable Banking) against historical data (X-month rolling median and Y-month rolling average, which can be controlled via a user setting).

**Tech Stack**
Backend: Python (FastAPI or Flask) hosted on Vercel.

Frontend: React (Vite) hosted on Vercel.

Database: Vercel Postgres or Supabase (for balance history).

API: Enable Banking (Production).

**Chapter 1: Secure Credential Management & Authentication**
The most sensitive part of this application is the RSA Private Key (.pem) used to sign requests.

1.1 Storing the PEM Key
Never store the .pem file in the GitHub repository.

Method: Base64 encode the .pem file content and store it as a single-line environment variable in Vercel named EB_PRIVATE_KEY_B64.

Usage: The backend must decode this at runtime to sign JWTs.

1.2 JWT Generation (Enable Banking Auth)
The backend must generate a RS256 signed JWT for every request to the Enable Banking API.

Issuer (iss): enablebanking.com

Audience (aud): api.enablebanking.com

Header (kid): Your Enable Banking application_id.

Algorithm: RS256 using the decoded private key.

Expiration (exp): Set to 1 hour from the issued time (iat).

**Chapter 2: Functional Requirements**
2.1 The "Gatekeeper"
A simple numeric keypad UI on the frontend, optimised for mobile touch input.

The user must enter a 4-digit PIN stored as APP_PIN in environment variables.

The backend must verify this PIN before returning any bank data.

Mobile-first design: Large touch-friendly buttons (minimum 48x48px tap targets), centered layout for one-handed use.

2.2 Data Logic & Calculation
Upon successful PIN entry, the app displays:

Current Balance: Real-time fetch from ABN AMRO.

12-Month Median: The median balance of the "comparable day" (e.g., the 2nd of every month) for the last 12 months.

24-Month Average: The average balance of the "comparable day" for the last 24 months.

Visual Indicator:

GREEN if Current Balance > Comparison Value.

RED if Current Balance < Comparison Value.

2.3 Mobile UI/UX Requirements
Responsive Design: Mobile-first approach with viewport meta tag configured for optimal mobile rendering.

Touch Targets: All interactive elements must be at least 48x48px with adequate spacing.

Typography: Large, readable font sizes (minimum 16px base) to prevent zoom on input focus.

Layout: Single-column layout optimised for portrait orientation on smartphones.

Performance: Minimal bundle size and fast initial load for mobile networks.

PWA Consideration: Consider adding a web app manifest for "Add to Home Screen" capability.

2.4 Automated Data Collection (Vercel Cron)
A scheduled script must run once daily (e.g., 23:55).

It fetches the current balance and saves a record (date, balance_amount) to the database.

Note: During the initial setup, the script should iterate through the last 24 months of transaction history to "backfill" the daily balances for immediate comparison availability.

**Chapter 3: Safety & Security**
AIS Only: The application must only use Account Information Service permissions. No payment initiation capability is allowed.

Database Privacy: Store only the date and the amount. Do not store IBANs, names, or bank account IDs.

Rate Limiting: The backend must limit PIN attempts to prevent brute-force attacks.

**Chapter 4: Implementation Status & Technical Notes**

4.1 Completed
- PIN gatekeeper with mobile-friendly numeric keypad
- Rate limiting: 5 failed attempts triggers 5-minute lockout
- Enable Banking OAuth flow with ABN AMRO (production)
- Real-time balance fetching and display
- Mobile-first responsive design with PWA meta tags
- Vercel deployment with Python serverless functions + React frontend

4.2 Serverless Architecture Considerations
Vercel serverless functions do not share memory between requests. To handle this:
- The `account_uid` from Enable Banking is stored in browser localStorage after successful bank auth
- Subsequent API calls pass `account_uid` as a query parameter
- This allows balance fetches to work across different serverless instances

4.3 Enable Banking Session Validity
- Sessions are configured with 90-day validity (`valid_until` parameter)
- After 90 days, user must re-authenticate with ABN AMRO
- PIN is still required on every app use (security gatekeeper)

4.4 Next Steps (Database Integration)
1. Set up Vercel Postgres (add DATABASE_URL to environment variables)
2. Create tables:
   - `sessions`: store session_id, account_uid, expiry_date
   - `daily_balances`: store date, balance_amount (no PII)
3. On app load: check for valid session in DB, skip bank auth if valid
4. Implement daily cron job to record balance snapshots
5. Calculate 12-month median and 24-month average from stored data
6. Optional: backfill historical balances from transaction history