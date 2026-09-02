# SOC Analyzer

An AI-powered web application for SOC analysts to upload ZScaler web proxy logs and receive instant threat analysis powered by Claude AI.

## Features

- Secure login and registration with JWT authentication
- Drag-and-drop log file upload
- AI analysis of ZScaler web proxy logs using Claude (Anthropic)
- Dashboard showing: threat summary, risk level, event timeline, anomaly table with confidence scores, top users, and SOC recommendations
- Live progress while the analysis runs — each pipeline stage is reported as it completes, not a blank spinner
- Upload history ("My Analyses") — reports are stored server-side, so closing the tab doesn't lose them
- Filter and sort the anomaly table by user, URL, reason, severity, or confidence
- Export any report as Markdown — copy to the clipboard or download for a ticket
- Backend and database fully Dockerized — frontend runs with npm

---

## How to Run Locally

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- [Node.js](https://nodejs.org/) installed (version 18 or higher)
- An Anthropic API key (see below)

### 1. Get an Anthropic API Key

1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Sign in or create a free account
3. Navigate to **API Keys** and create a new key
4. Copy the key — it starts with `sk-ant-...`

### 2. Configure Environment Variables

Open **`backend/.env`** and set your key:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
SECRET_KEY=any-random-string-for-jwt
```

The file is already present — just fill in the values. `SECRET_KEY` isn't
looked up anywhere; it's any random string, used to sign login tokens.

Two things worth knowing:

- **`backend/.env` is the only file to edit.** Docker Compose reads it via
  `env_file`, and the app reads it directly when run outside Docker, so there
  is one source of truth either way. Write `KEY=value` with no spaces around
  the `=` and no quotes.
- **Restart with `docker compose up -d`, not `restart`.** Environment
  variables are fixed when a container is created, so `docker compose restart`
  keeps the old values and it will look like your new key was ignored.

If your API key is *identity-linked* (the API rejects calls with
`anthropic-workspace-id is required`), add the workspace ID from the Anthropic
Console as well — ordinary keys don't need it:

```
ANTHROPIC_WORKSPACE_ID=wrkspc_...
```

### 3. Start the Backend and Database

In a terminal from the project root:

```bash
docker compose up --build
```

This starts two services:
- **PostgreSQL** on port 5432
- **FastAPI backend** on port 8000

Wait until you see `Application startup complete` in the terminal output.

### 4. Start the Frontend

Open a **second terminal** and run:

```bash
cd frontend
npm install
npm run dev
```

This starts the Next.js frontend on port 3000.

Then open [http://localhost:3000](http://localhost:3000) in your browser.

### 5. Use the Application

1. **Register** a new account (or log in if you already have one)
2. **Upload** a log file — use one of the samples in `sample_logs/`
3. **Watch** the pipeline stages tick by (~10–20 seconds while Claude analyzes the logs)
4. **View** the full analysis dashboard, and export it as Markdown if you need it in a ticket
5. **Revisit** any past report from **My Analyses** — the analysis runs on the server, so it survives a closed tab

---

## Sample Log Files

Two sample log files are included in `sample_logs/`:

| File | Description |
|------|-------------|
| `normal_traffic.log` | Routine web proxy traffic — low risk, standard browsing and SaaS usage |
| `incident_scenario.log` | Simulated security incident — contains malware download attempts, C2 communication, and data exfiltration events |

Use `incident_scenario.log` to see the dashboard at its most informative.

---

## How AI Analysis Works

### Log Parsing

When a log file is uploaded, the backend parser (`parser.py`) reads the ZScaler pipe-delimited format and extracts structured fields: timestamp, user, source/destination IPs, URL, category, bytes transferred, risk score, threat name, malware classification, and more.

### Which Events Get Sent

A real ZScaler export runs to tens of thousands of lines, so the prompt can't hold the whole file. Sending the *first* 150 events would judge a full day's traffic on its first few minutes — an incident at line 9,000 would be invisible.

Instead, `parser.py` scores every event for how much a SOC analyst would care about it (ZScaler risk score, BLOCK actions, named threats and malware classifications, risky destination countries, suspicious URL categories, and outbound transfers above the file's own 95th percentile), then sends the highest-scoring events plus an evenly-spaced sample of routine traffic. The routine sample matters: without a baseline, Claude can't tell whether a file is 5% malicious or 100% malicious.

The aggregate statistics in the prompt always describe **every** event in the file, so the totals are correct even when the individual events are a sample.

### Claude AI Analysis

The selected events and the aggregate statistics are sent to **Claude Opus 5** (`claude-opus-5`) via the Anthropic Python SDK (`ai.py`). Claude acts as a senior SOC analyst and returns:

- **Summary** — plain-English overview of the log file
- **Risk Level** — Critical / High / Medium / Low classification
- **Timeline** — the 10 most significant events in chronological order
- **Anomalies** — suspicious events with explanations and a confidence score (0.0–1.0)
- **Top Users** — most active users with risk notes
- **Threat Breakdown** — counts per threat category (malware, data loss, policy violations, network scans, C2 communications)
- **Recommendations** — specific, actionable next steps

The report shape is declared as Pydantic models and passed to the API as a structured output schema (`client.messages.parse(..., output_format=SocAnalysis)`), so the response is *guaranteed* to match it. There is no markdown-fence stripping or hand-rolled `json.loads` that a single malformed response could break. Every field — including risk level and recommendations — is persisted to Postgres, so the dashboard renders Claude's own judgement rather than re-deriving it in the browser.

### Analysis Runs in the Background

Analysis takes 15–20 seconds, which is too long to hold an HTTP request open. `POST /api/analyze/{id}` queues a background job and returns immediately; the frontend polls `GET /api/analyze/{id}/status` for the current pipeline stage and fetches `GET /api/results/{id}` when it's done. The Anthropic client is `AsyncAnthropic`, so one analysis doesn't block the event loop and freeze the server for every other user.

A job interrupted by a server restart can be retried — the upload's status and error message are recorded on the row, and re-visiting the dashboard restarts it.

### Why Claude?

Claude excels at reasoning over semi-structured data. Rather than relying on rigid signature-matching rules, Claude understands context — it can identify that an unusual combination of a high risk score, a known-bad URL category, and large outbound bytes is suspicious even if no single field triggers an alert. This lets the system detect novel or blended threats that rule-based systems would miss.

### Anomaly Detection Approach

Claude evaluates each event against multiple signals simultaneously:
- **Risk score** from ZScaler (pre-computed)
- **URL category** (malware, botnets, P2P, unauthorized communication)
- **Bytes transferred** (unusually large = potential exfiltration)
- **Destination country risk** (`is_dst_cntry_risky` field)
- **TLS anomalies** (self-signed certs, expired CAs, weak protocol versions)
- **Threat name / malware classification** fields
- **User behavior patterns** (access outside normal scope, repeated suspicious requests)

The confidence score reflects how many of these signals align — a high-confidence anomaly has multiple corroborating indicators.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16, React 19, Tailwind CSS 4, TypeScript |
| Backend | FastAPI (Python), SQLAlchemy |
| Database | PostgreSQL |
| AI | Anthropic Claude Opus 5 (`claude-opus-5`) |
| Infrastructure | Docker, Docker Compose |

---

## Project Structure

```
TENEX_Assignment/
├── backend/
│   ├── main.py            # FastAPI entry point
│   ├── models.py          # SQLAlchemy ORM models
│   ├── database.py        # DB connection + lightweight schema updates
│   ├── parser.py          # ZScaler log parser + event scoring/selection
│   ├── ai.py              # Claude API integration (structured outputs, async)
│   ├── tests/
│   │   └── test_parser.py # Parser, stats, and event-selection tests
│   └── routers/
│       ├── auth.py        # Register + login endpoints
│       ├── upload.py      # File upload + upload history endpoints
│       └── analyze.py     # Background analysis job, status, and results
├── frontend/
│   └── src/
│       ├── app/
│       │   ├── login/     # Login + register page
│       │   ├── upload/    # File upload page
│       │   ├── history/   # "My Analyses" — past uploads and reports
│       │   └── dashboard/ # Analysis results dashboard
│       └── lib/
│           ├── api.ts     # Backend API client
│           └── report.ts  # Report types + Markdown export
├── sample_logs/
│   ├── normal_traffic.log
│   └── incident_scenario.log
├── docker-compose.yml
└── .env                   # Set ANTHROPIC_API_KEY here
```

---

## Running the Tests

The parser is the one part of the pipeline with no AI in it, so it's the part worth pinning down with tests — malformed lines, missing fields, non-numeric bytes, and the event-selection logic that decides what a large file sends to Claude.

```bash
cd backend
pip install -r requirements.txt
pytest
```

No database or API key is needed — the tests write temporary log files and exercise `parser.py` directly.
