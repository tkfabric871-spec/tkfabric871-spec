# Smart Investment — Professional Member + Admin Portal

This package upgrades the supplied Smart Invest demo into a responsive member portal and a MySQL-backed admin operations dashboard.

## Run
1. Install Node.js LTS.
2. Make a copy of `backend/.env.example` named `backend/.env` and fill in your local MySQL password, a long JWT secret, and admin credentials. Never publish `.env`.
3. In PowerShell, from `backend`:
   `npm install`
   `npm start`
4. Health check: `http://localhost:4000/api/health`
5. Member portal: `http://localhost:4000/`
6. Admin portal: `http://localhost:4000/admin.html`

If your database already exists, the backend performs small additive migrations for `users.status` and `payment_requests.payment_screenshot` at startup. For a clean installation, run `backend/schema.sql` first.

## Included admin operations
- Customer list and account status
- Payment request review
- Payment screenshot viewing
- Withdrawal review
- Investment records
- Plan activation/editing
- Referral ledger effect when an approved payment belongs to a referred customer

## Security
- Passwords are bcrypt-hashed and are never returned to the UI or admin.
- User sessions use signed JWTs.
- Admin credentials are read from `.env`.
- Uploaded payment images are limited to images and 5 MB.
- Do not expose database credentials or admin passwords in frontend files.

## Financial/legal note
The interface can display published plan terms, but displayed rates are not represented as guaranteed profits. Before accepting real customer funds, integrate an appropriate regulated payment/financial workflow, KYC/AML and consumer disclosures as required by the jurisdiction, reconciliation, audit logs, secure object storage, HTTPS, rate limiting, fraud controls and professional legal/compliance review.
