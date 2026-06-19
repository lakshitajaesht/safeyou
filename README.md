# SafeYou

SafeYou is a Firefox extension plus a Vercel-compatible Node.js API. It checks
top-level web navigations, blocks pages classified as malicious, labels safe
pages, and asks for community feedback when evidence is inconclusive.

## Security first

Never place a MongoDB URI in extension code or commit it to Git. If a credential
has been pasted into chat, logs, or source code, rotate it in MongoDB Atlas.
Create a least-privilege database user and restrict Atlas network access where
your hosting setup permits it.

## Run the backend locally

1. Install dependencies:

   ```bash
   npm install
   ```

2. Optionally copy `.env.example` to `.env` and set `MONGODB_URI`.
   Without it, the local server uses an in-memory development database that
   resets whenever the server restarts.
3. Start the API:

   ```bash
   npm run dev
   ```

4. Verify `http://localhost:3000/health`.

## Load the Firefox extension

1. Open `about:debugging#/runtime/this-firefox`.
2. Select **Load Temporary Add-on**.
3. Choose `extension/manifest.json`.
4. Open the SafeYou settings and leave the backend URL as
   `http://localhost:3000`.

After deploying, change the setting to the Vercel project URL, such as
`https://your-project.vercel.app`.

## Deploy the API to Vercel

Import this directory as a Vercel project and add these environment variables:

- `MONGODB_URI`
- `MONGODB_DB` (optional, defaults to `safeyou`)
- `SCAN_TIMEOUT_MS` (optional)
- `URLSCAN_API_KEY` (recommended for urlscan.io submission and higher quotas)
- `URLSCAN_VISIBILITY` (recommended: `unlisted` or `private`)
- `URLSCAN_WAIT_MS` (optional result polling budget)

The API routes are:

- `POST /api/check` with `{ "url": "https://example.com" }`
- `POST /api/report` with `{ "url": "...", "vote": "safe|malicious", "reporterId": "..." }`
- `GET /api/health`

## Admin dashboard

Set `ADMIN_PASSWORD` and a long random `ADMIN_SESSION_SECRET` in `.env`, then
open `http://localhost:3000/admin`. The protected dashboard lists scanned
websites, risk scores, confidence, verdicts, and community reports.

Protected admin routes:

- `POST /api/admin/login`
- `POST /api/admin/logout`
- `GET /api/admin/session`
- `GET /api/admin/sites?page=1&limit=50&search=example`

## Classification notes

The server first uses a cached database result. New or stale URLs are fetched
with private-network protections and assessed using explainable URL and HTML
signals. The response body is scanned with YARA-X using the rules in
`rules/web-threats.yar`. The backend also follows the search, submit, and result
workflow exposed by urlscan.io (the same service wrapped by
`hrbrmstr/urlscan`). Without `URLSCAN_API_KEY`, SafeYou can search public recent
results but does not submit new scans.

URL submission can disclose the complete address to urlscan.io. Keep
`URLSCAN_VISIBILITY=unlisted` or use `private` when your urlscan.io plan supports
it, and avoid submitting URLs containing personal information or secret query
parameters.

These signals are heuristic evidence, not proof that a website is safe. A
production security product also needs durable rate limiting, abuse controls,
privacy disclosures, retention limits, and independent security testing.
