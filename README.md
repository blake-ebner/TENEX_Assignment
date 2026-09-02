# SOC Analyzer

An AI-powered web application for SOC analysts to upload ZScaler web proxy logs and receive instant threat analysis powered by Claude AI.

## Features

- Secure login and registration with JWT authentication
- Drag-and-drop log file upload
- AI analysis of ZScaler web proxy logs using Claude (Anthropic)
- Dashboard showing: threat summary, risk level, event timeline, anomaly table with confidence scores, top users, and SOC recommendations
- **MITRE ATT&CK mapping** — every anomaly is tagged with the techniques it demonstrates
- **Sigma detection rules** — the report hands back deployable SIEM rules, not just findings
- **Cross-upload trends** — repeat offenders and recurring techniques across every log you've analyzed
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
6. **Analyze a second file**, then open **Trends** — repeat offenders and recurring ATT&CK techniques only become visible across two or more reports

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
- **Anomalies** — suspicious events with explanations, a confidence score (0.0–1.0), and the MITRE ATT&CK techniques they demonstrate
- **Top Users** — most active users with risk notes
- **Threat Breakdown** — counts per threat category (malware, data loss, policy violations, network scans, C2 communications)
- **Recommendations** — specific, actionable next steps
- **Detection Rules** — Sigma rules that would catch the same activity next time

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

### ATT&CK Mapping and Detection Rules

A finding is only half the job. Two things turn a report into something a SOC team can act on:

**MITRE ATT&CK techniques.** Each anomaly is tagged with the techniques it demonstrates (`T1071.001` — Web Protocols, `T1041` — Exfiltration Over C2 Channel). Every SOC tool speaks ATT&CK, so this is how a finding here gets compared against detections and coverage gaps elsewhere. The prompt is explicit that accuracy beats coverage: an empty list is the right answer for an event that doesn't clearly demonstrate a technique, because an analyst will act on a wrong technique ID.

**Sigma rules.** For findings worth alerting on, Claude writes a complete Sigma rule — vendor-neutral YAML that drops into a SIEM. The dashboard shows each rule collapsed with a copy button; the Markdown export includes them in fenced `yaml` blocks.

The rules are written against the exact field names `parser.py` produces. That list is *imported* into the prompt from `parser.FIELDS_WE_CARE_ABOUT` rather than duplicated, so a rule can never reference a field the pipeline doesn't emit.

### Cross-Upload Trends

Every other view in the app looks at one log file. `/trends` looks across all of them, because the useful question usually isn't "was this file bad" but "is this the fourth week running that the same account got flagged".

`GET /api/trends` rolls up every completed report and surfaces:

- **Repeat offenders** — users ranked by how many *separate reports* flagged them
- **Recurring ATT&CK techniques** — behaviour that keeps reappearing, which is a control gap rather than an incident
- **Risk over time** — every analysis in order

The ranking counts distinct reports, not raw anomaly hits. Five hits in one bad afternoon is one event; three hits across three weeks is a pattern, and the second should rank higher. That logic lives in `trends.py` as a pure function over plain dicts — no ORM, no network — so it's tested without a database.

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
│   ├── main.py             # FastAPI entry point
│   ├── models.py           # SQLAlchemy ORM models
│   ├── database.py         # DB connection + lightweight schema updates
│   ├── parser.py           # ZScaler log parser + event scoring/selection
│   ├── ai.py               # Claude API integration (structured outputs, async)
│   ├── trends.py           # Cross-upload aggregation (pure, no DB)
│   ├── .env                # Set ANTHROPIC_API_KEY here (gitignored)
│   ├── tests/
│   │   ├── test_parser.py  # Parser, stats, and event-selection tests
│   │   └── test_trends.py  # Cross-upload aggregation tests
│   └── routers/
│       ├── auth.py         # Register + login endpoints
│       ├── upload.py       # File upload + upload history endpoints
│       └── analyze.py      # Background analysis job, status, results, trends
├── frontend/
│   └── src/
│       ├── app/
│       │   ├── login/      # Login + register page
│       │   ├── upload/     # File upload page
│       │   ├── history/    # "My Analyses" — past uploads and reports
│       │   ├── trends/     # Cross-upload patterns
│       │   └── dashboard/  # Analysis results dashboard
│       └── lib/
│           ├── api.ts      # Backend API client
│           └── report.ts   # Report types + Markdown export
├── sample_logs/
│   ├── normal_traffic.log
│   └── incident_scenario.log
└── docker-compose.yml
```

---

## API Reference

All `/api` routes require an `Authorization: Bearer <token>` header.

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/auth/register` | Create an account, returns a JWT |
| `POST` | `/auth/login` | Log in, returns a JWT |
| `POST` | `/api/upload` | Upload a `.log`/`.txt` file, returns an `upload_id` |
| `GET` | `/api/uploads` | This user's uploads, newest first |
| `POST` | `/api/analyze/{id}` | Queue analysis; returns immediately |
| `GET` | `/api/analyze/{id}/status` | Current status and pipeline stage |
| `GET` | `/api/results/{id}` | The stored report (409 if not finished) |
| `GET` | `/api/trends` | Cross-upload patterns across all reports |

---

## Running the Tests

```bash
cd backend
pip install -r requirements.txt
pytest
```

No database or API key is needed — the tests build temporary log files and call the
modules directly.

The two tested modules are the ones where the logic is deterministic and the bugs
would be silent:

- **`parser.py`** — malformed lines, missing fields, non-numeric bytes, and the
  event-selection logic that decides what a large file sends to Claude. One test
  pins the case that matters most: a threat at line 900 of a 1,000-line file must
  still reach the prompt.
- **`trends.py`** — that a user flagged across three weeks outranks one flagged
  five times in a single file, plus the degenerate inputs (missing users, junk
  confidence values, reports predating ATT&CK mapping).

The AI layer itself isn't unit-tested — its output is model-generated, so the
guarantee comes from the enforced response schema rather than from assertions.
