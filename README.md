# RE-DACT

A deployable data-protection workspace. Redact, mask, or anonymize personal data in text and documents, optionally encrypt the original, and keep a tamper-evident audit trail.

This is a rebuild of the original Streamlit + Ganache prototype. The product plan is the same. The architecture is not.

## Why the old stack could not ship

- Streamlit was a single 900-line script with broken contract calls, hardcoded Firebase keys, and a local filesystem for downloads.
- Ganache (`127.0.0.1:7545`) is a local Ethereum simulator. It does not exist on Streamlit Community Cloud, Render, or any hosted web service.
- The Solidity `addLog` ABI did not match what the Python app sent, and `getUserLogs` was never on the contract.

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

## Deploy on Render

1. Push this repo.
2. Use the Blueprint in `render.yaml`, or create a Node web service:
   - Build: `npm ci && npm run build`
   - Start: `npm start`
   - Health check: `/api/health`
3. Set `SESSION_SECRET` to a long random string.
4. Attach a disk at `/var/data` and set `DATA_DIR=/var/data` so the SQLite ledger survives deploys. On the free web plan the disk is unavailable and data resets on restart.

## Stack

- Next.js App Router UI
- Session cookies (jose) instead of Firebase
- Compromise + regex instead of spaCy
- unpdf / mammoth / JSZip instead of PyMuPDF in the request path
- tesseract.js + sharp for image redaction
- SQLite via better-sqlite3

The original Streamlit/Truffle files are under `legacy/` for reference.
