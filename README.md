# RE-DACT

A deployable data-protection workspace. Redact, mask, or anonymize personal data in text and documents, optionally encrypt the original, and keep a tamper-evident audit trail.

This is a rebuild of the original Streamlit + Ganache prototype. The product plan is the same. The architecture is not.

## What replaced Ganache

Audit records now live in SQLite as a **hash chain**: each row stores `previous_hash` and `chain_hash = sha256(prev|user|action|data|time)`. The Logs screen verifies the chain. That is the hosted equivalent of a local blockchain: tamper-evident, no wallet, no gas, no node.

If you later need a public chain, point an optional writer at a hosted RPC (Sepolia, Polygon). It is not required for the product to work.

## Local run

```bash
npm install
cp .env.example .env
npm test
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). Demo login: `demo@redact.app` / `redact-demo-2026`.

`npm start` binds `0.0.0.0` and honors `PORT`, which is what Render expects.

## Deploy on Render (free)

Render's Free web plan is $0. The site is public at `https://<name>.onrender.com`.

Free-plan limits:
- The service sleeps after 15 minutes with no traffic. The next visit takes about a minute to wake.
- No persistent disk. SQLite (accounts, history, audit chain) resets when the service sleeps, restarts, or redeploys. The demo login still works because it is recreated on boot.
- 512 MB RAM / 0.1 CPU.

### Dashboard (easiest)

1. Open [New Web Service](https://dashboard.render.com/web/new) and connect `jagadeepmamidi/Abhivriddhi_21`.
2. Branch: `main`. Runtime: Node.
3. Build: `npm ci && npm run build`
4. Start: `npm start`
5. Instance type: **Free** (not Starter).
6. Environment:
   - `SESSION_SECRET` = a random string of at least 32 characters
   - `NODE_ENV` = `production`
   - `NODE_OPTIONS` = `--max-old-space-size=384`
7. Health check path: `/api/health`
8. Create Web Service.

Do not add a disk. Free web services cannot use one.

### Blueprint

`render.yaml` is already set to `plan: free`. In the dashboard choose New Blueprint Instance, pick this repo, and apply. If Render asks for a payment method for Blueprints, use the Dashboard flow above instead. It is still free when the instance type is Free.

## Stack

- Next.js App Router UI
- Session cookies (jose) instead of Firebase
- Compromise + regex instead of spaCy
- unpdf / mammoth / JSZip instead of PyMuPDF in the request path
- tesseract.js + sharp for image redaction
- SQLite via better-sqlite3

The original Streamlit/Truffle files are under `legacy/` for reference.
