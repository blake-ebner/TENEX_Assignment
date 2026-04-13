# SOC Analyzer

An AI-powered web application for SOC analysts to upload ZScaler web proxy logs and receive instant threat analysis powered by Claude AI.

## Features

- Secure login and registration with JWT authentication
- Drag-and-drop log file upload
- AI analysis of ZScaler web proxy logs using Claude (Anthropic)
- Dashboard showing: threat summary, risk level, event timeline, anomaly table with confidence scores, top users, and SOC recommendations
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

Open the `.env` file in the root of the project and set your key:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
SECRET_KEY=any-random-string-for-jwt
```

The `.env` file is already present — just fill in the values.

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
3. **Wait** ~10–20 seconds while Claude analyzes the logs
4. **View** the full analysis dashboard

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

### Claude AI Analysis

The parsed events (up to 150) along with aggregate statistics are sent to **Claude claude-opus-4-5** via the Anthropic Python SDK (`AI.py`). Claude receives a structured prompt instructing it to act as a senior SOC analyst and return a JSON report with:

- **Summary** — plain-English overview of the log file
- **Risk Level** — Critical / High / Medium / Low classification
- **Timeline** — the 10 most significant events in chronological order
- **Anomalies** — suspicious events with explanations and a confidence score (0.0–1.0)
- **Top Users** — most active users with risk notes
- **Threat Breakdown** — counts per threat category (malware, data loss, policy violations, network scans, C2 communications)

### Why Claude?

Claude excels at reasoning over semi-structured data and producing consistent, parseable JSON output. Rather than relying on rigid signature-matching rules, Claude understands context — it can identify that an unusual combination of a high risk score, a known-bad URL category, and large outbound bytes is suspicious even if no single field triggers an alert. This lets the system detect novel or blended threats that rule-based systems would miss.

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
| AI | Anthropic Claude claude-opus-4-5 |
| Infrastructure | Docker, Docker Compose |

---

## Project Structure

```
TENEX_Assignment/
├── backend/
│   ├── main.py          # FastAPI entry point
│   ├── models.py        # SQLAlchemy ORM models
│   ├── database.py      # DB connection
│   ├── parser.py        # ZScaler log parser
│   ├── AI.py            # Claude API integration
│   └── routers/
│       ├── auth.py      # Register + login endpoints
│       ├── upload.py    # File upload endpoint
│       └── analyze.py   # Analysis + results endpoints
├── frontend/
│   └── src/app/
│       ├── login/       # Login + register page
│       ├── upload/      # File upload page
│       └── dashboard/   # Analysis results dashboard
├── sample_logs/
│   ├── normal_traffic.log
│   └── incident_scenario.log
├── docker-compose.yml
└── .env                 # Set ANTHROPIC_API_KEY here
```
