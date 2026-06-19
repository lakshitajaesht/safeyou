# SafeYou

SafeYou is an open-source phishing and malicious-URL detection system for
Firefox and Chrome. It combines a cloud reputation database, backend webpage
analysis, YARA-X rules, explainable risk scoring, and community reports.

The browser extension checks a website before opening it. Known malicious
pages receive a red warning screen, safe pages receive a green status, and
uncertain pages ask the user to proceed carefully and contribute a report.

[Download the browser extensions](https://github.com/lakshitajaesht/safeyou/releases/tag/Extension)
· Default cloud backend: `https://safeyou.vercel.app`

## Why SafeYou?

Threat intelligence becomes more useful when browsers can share signals.
SafeYou treats its backend as a cloud reputation service:

- Every participating browser queries the same URL reputation database.
- Previously analyzed URLs can be answered quickly from MongoDB.
- New or stale URLs are fetched and analyzed by the backend.
- Users can report every checked website as safe or malicious.
- Community vote counts are stored alongside automated analysis.
- Administrators can inspect the accumulated intelligence from a protected
  dashboard.

This creates a peer-assisted and crowd-sourced feedback loop. One browser's
analysis and report can help inform later checks from other browsers connected
to the same backend.

## How it works

```mermaid
flowchart LR
    A["Firefox or Chrome user opens a URL"] --> B["SafeYou extension"]
    B --> C["Cloud reputation API"]
    C --> D{"Fresh MongoDB record?"}
    D -->|Yes| E["Return cached verdict and score"]
    D -->|No| F["Backend safely fetches the webpage"]
    F --> G["Domain, URL, HTML, form and script analysis"]
    F --> H["YARA-X content scan"]
    G --> I["Combined explainable risk score"]
    H --> I
    I --> J["Store result in MongoDB"]
    J --> E
    E --> K{"Verdict"}
    K -->|Safe| L["Open page with green status"]
    K -->|Unknown| M["Open page with caution status"]
    K -->|Malicious| N["Display red warning page"]
    L --> O["User can report safe or malicious"]
    M --> O
    N --> O
    O --> P["Crowd report stored in cloud database"]
```

## Detection technologies

### Cloud reputation and caching

The backend stores normalized URLs, verdicts, scores, scan signals, timestamps,
page metadata, and community report counts in MongoDB. Fresh records are reused
for 24 hours before the backend rescans them.

### Safe backend webpage loading

Unknown URLs are loaded by the backend with:

- HTTP and HTTPS protocol validation
- Private-network and localhost blocking
- DNS checks to reduce server-side request forgery risks
- Redirect limits
- Response-size limits
- Scan timeouts

The scanner records final redirects, content type, HTTP status, title,
description, owner/site metadata, form counts, password fields, iframe counts,
cross-domain form submissions, and HTML size.

### Domain and URL analysis

SafeYou evaluates signals including:

- Missing HTTPS
- IP-address hosts
- Embedded URL credentials
- Internationalized/punycode hostnames
- Excessive subdomains and hyphens
- Account-verification and urgency keywords
- Redirects to different registered domains

### HTML and JavaScript analysis

The scanner checks for:

- Password forms
- Forms that submit data to another domain
- Hidden frames
- Obfuscated JavaScript
- Script-driven redirects
- Unusual numbers of forms
- Suspicious download patterns

### YARA-X

Fetched page content is scanned with
[YARA-X](https://github.com/VirusTotal/yara-x). Project rules live in
[`rules/web-threats.yar`](rules/web-threats.yar) and currently cover patterns
such as:

- Credential-phishing language
- Cryptocurrency seed phrase and wallet theft
- Obfuscated redirect scripts
- Fake security alerts and scareware
- Suspicious download scripts
- Hidden credential or payment collection forms

YARA matches are returned as explainable signals and contribute to the final
risk score.

### Crowd-sourced reports

Every classified website exposes **Report safe** and **Report malicious**
controls. SafeYou creates a random reporter ID for each browser and permits one
report from that browser for each normalized URL. The backend stores the votes
and displays their totals in the reputation record and admin dashboard.

Community reports are supporting evidence, not a guarantee. Production
deployments should add stronger identity, anti-abuse controls, rate limiting,
and vote-trust policies before allowing crowd votes to directly override
automated verdicts.

## Verdicts

| Verdict | Behavior |
| --- | --- |
| `safe` | The page opens and SafeYou displays a green status. |
| `unknown` | The page opens with a caution message and reporting controls. |
| `malicious` | SafeYou displays a red warning page before the user proceeds. |

SafeYou intentionally fails open when the backend is unavailable so a server
outage does not make the browser unusable. In that situation it marks the
result as unknown.

## Project structure

```text
api/                 Vercel API functions
api/admin/           Protected admin APIs
extension/           Firefox extension
extension-chrome/    Chrome Manifest V3 extension
lib/                 Database, scanner, authentication and URL logic
public/              Login and administrator dashboard
rules/               YARA-X detection rules
server/              Local Node.js server
test/                Automated tests
dist/                Packaged browser extensions
vercel.json          Vercel function and route configuration
```

## Technology stack

- Firefox WebExtensions
- Chrome Manifest V3
- Node.js 20+
- Vercel Functions
- MongoDB Atlas
- YARA-X through `@litko/yara-x`
- `tldts` for registered-domain parsing
- Signed HTTP-only cookies for administrator authentication

## Run the backend locally

Requirements:

- Node.js 20 or newer
- npm
- Optional MongoDB Atlas database

Install dependencies:

```bash
npm install
```

Copy the environment template:

```bash
cp .env.example .env
```

Configure `.env`:

```env
MONGODB_URI=mongodb+srv://USERNAME:PASSWORD@CLUSTER.mongodb.net/
MONGODB_DB=safeyou
PORT=3000
SCAN_TIMEOUT_MS=8000
ADMIN_PASSWORD=choose-a-strong-password
ADMIN_SESSION_SECRET=generate-a-long-random-secret
```

Never commit `.env`. Use a least-privilege MongoDB user and rotate any
credential that has been exposed in source code, chat, screenshots, or logs.

Start the development server:

```bash
npm run dev
```

Or start it without file watching:

```bash
npm start
```

Verify the backend:

```bash
curl http://localhost:3000/health
```

Without `MONGODB_URI`, the local server uses temporary in-memory storage that
is erased whenever the process restarts.

## Firefox extension

Download the packaged extension from the
[Extension release](https://github.com/lakshitajaesht/safeyou/releases/tag/Extension),
or load it for development:

1. Open `about:debugging#/runtime/this-firefox`.
2. Select **Load Temporary Add-on**.
3. Choose `extension/manifest.json`.

The default backend is `https://safeyou.vercel.app`. Open **Backend settings**
from the extension popup to use another deployment or
`http://localhost:3000`.

## Chrome extension

Build the package:

```bash
npm run build:chrome
```

This creates `dist/safeyou-chrome.zip`.

For development:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the `extension-chrome` directory.

## Deploy to Vercel

Import the repository into Vercel and configure:

```env
MONGODB_URI=...
MONGODB_DB=safeyou
SCAN_TIMEOUT_MS=8000
ADMIN_PASSWORD=...
ADMIN_SESSION_SECRET=...
```

The project uses the Node.js runtime because YARA-X requires a native Node
binary. `vercel.json` includes the YARA rules in the function bundle and allows
up to 60 seconds for analysis.

After deployment:

- API health: `https://your-project.vercel.app/health`
- Admin dashboard: `https://your-project.vercel.app/admin`
- Extension backend: `https://your-project.vercel.app`

## API

### Check a URL

```http
POST /api/check
Content-Type: application/json

{
  "url": "https://example.com"
}
```

The response includes the verdict, risk score, confidence, page metadata,
analysis signals, YARA matches, and report totals.

### Report a URL

```http
POST /api/report
Content-Type: application/json

{
  "url": "https://example.com",
  "vote": "safe",
  "reporterId": "browser-generated-identifier"
}
```

`vote` must be `safe` or `malicious`.

### Health

```http
GET /api/health
```

### Protected administrator APIs

- `POST /api/admin/login`
- `POST /api/admin/logout`
- `GET /api/admin/session`
- `GET /api/admin/sites?page=1&limit=50&search=example`

## Admin dashboard

Open `/admin` and sign in using `ADMIN_PASSWORD`. The dashboard displays:

- Scanned URLs and page titles
- Automated verdicts
- Risk and confidence scores
- Safe and malicious report totals
- Last scan timestamps
- Search and pagination

Authentication uses a signed, HTTP-only, same-site cookie with an eight-hour
session.

## Testing

Run:

```bash
npm test
```

The test suite verifies URL normalization and YARA-X rule matching.

## Privacy and security considerations

SafeYou sends the full visited URL to the configured backend. Operators should:

- Publish a clear privacy policy.
- Avoid retaining unnecessary query strings or personal data.
- Use HTTPS in production.
- Apply API rate limiting and abuse prevention.
- Restrict MongoDB access.
- Review and test YARA rules before deploying updates.
- Provide a deletion and retention policy.
- Perform independent security testing.

The backend never executes webpage JavaScript in a browser environment. It
downloads bounded response content and analyzes it as data.

## Limitations

SafeYou provides heuristic risk analysis, not proof that a website is safe or
malicious. Attackers can evade static rules, legitimate websites can contain
suspicious-looking behavior, and crowd reports can be wrong or manipulated.

Do not use SafeYou as the only security control for high-risk browsing,
payments, credentials, or regulated environments.

## Contributing

Contributions are welcome for:

- New and improved YARA rules
- False-positive reduction
- Reputation and trust algorithms
- Privacy-preserving URL normalization
- Extension usability and accessibility
- Backend rate limiting and abuse prevention
- Automated tests and security reviews

When adding a detection rule, include a test and explain the expected risk
signal.

## License

Add a license file before distributing or accepting external contributions.
