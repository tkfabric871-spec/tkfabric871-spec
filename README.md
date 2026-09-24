# Smart Invest Backend

Node.js + Express + MySQL backend scaffold for the supplied Smart Invest reference/demo UI.

## Setup

1. Make sure MySQL Server is running and create the database/tables by running `schema.sql` in MySQL Workbench or the MySQL CLI.
2. Copy `.env.example` to `.env`.
3. Put your own MySQL password in `.env` and replace `JWT_SECRET` and `ADMIN_PASSWORD` with your own secrets.
4. Open a terminal in this `backend` folder and run:

```bash
npm install
npm run dev
```

The API starts at `http://localhost:4000`.

## Health check

Open `http://localhost:4000/api/health` in a browser. It should return `{"ok":true,"database":true}` when MySQL is reachable.

## Main API routes

- `POST /api/auth/signup` — username, password, optional referralCode
- `POST /api/auth/login`
- `GET /api/profile` — Bearer token
- `GET /api/plans`
- `POST /api/payments` — Bearer token
- `GET /api/investments` — Bearer token
- `POST /api/withdrawals` — Bearer token
- Admin payment and withdrawal review routes use `x-admin-username` and `x-admin-password` headers.

## Important

The existing root-level `app.js` is still the original browser demo and uses localStorage. This backend is a separate server/API layer added to the ZIP. The demo UI should not be used to collect real customer money. Earnings and referral values are simulated reference behavior and must not be presented as guaranteed real investment returns.

Never commit `.env` or real passwords to source control.
