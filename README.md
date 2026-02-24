# 🛡️ ThreatTriage

**Automated SOC Alert & Log Analysis Engine**

A full-stack cybersecurity platform that ingests raw logs (syslog, HTTP, database), detects threats using 15+ rules and ML anomaly detection, enriches IOCs via threat intelligence APIs, auto-triggers SOAR playbooks, correlates alerts into incidents, and maps everything to MITRE ATT&CK — with a real-time hacker-themed React dashboard.

---

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14-red)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)

---

## 🚀 Quick Start (3 Commands)

> **You need:** Python 3.11+ and Node.js 18+ installed on your machine.

```bash
# 1. Clone the repo
git clone https://github.com/uchihashahin01/ThreatTriage.git
cd ThreatTriage

# 2. One-time setup (creates venv, installs Python + Node deps)
./start.sh --setup

# 3. Start everything (backend + frontend in one command)
./start.sh
```

That's it. Open **http://localhost:5173** in your browser to see the dashboard.

| What you'll see | URL |
|---|---|
| **SOC Dashboard** | http://localhost:5173 |
| **API Docs (Swagger)** | http://localhost:8000/docs |
| **Health Check** | http://localhost:8000/health |
| **WebSocket Feed** | ws://localhost:8000/ws/alerts |

To stop both servers: press **Ctrl+C** or run `./start.sh --stop`.

### Alternative: Start Servers Manually

If you prefer running backend and frontend in separate terminals:

```bash
# Terminal 1 — Backend
source .venv/bin/activate
PYTHONPATH=src uvicorn threattriage.main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend && npm run dev
```

### Alternative: Docker Compose

```bash
docker compose up -d
```

Starts FastAPI, Celery workers, Redis, PostgreSQL, and Flower monitoring.

---

## 🔑 First Steps After Starting

1. **Register an account** — Click "Register" on the login page (or use the API):
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{"username":"analyst1","email":"analyst1@soc.local","password":"SecurePass123!"}'
   ```

2. **Log in** — Use your credentials on the dashboard login page.

3. **Ingest some logs** — Go to the "Log Ingestion" page, paste sample logs, and click Submit. Or use the API:
   ```bash
   # Get your token
   TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"analyst1","password":"SecurePass123!"}' \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

   # Ingest sample logs
   curl -X POST http://localhost:8000/api/v1/logs/ingest \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "raw_logs": [
         "Mar  5 08:23:41 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2",
         "185.220.101.1 - - [05/Mar/2024:09:00:00 +0000] \"GET /api/users?id=1 UNION SELECT * FROM users HTTP/1.1\" 200 4521 \"-\" \"sqlmap/1.7\""
       ]
     }'
   ```

4. **Explore the dashboard** — Check Alerts, Incidents, MITRE ATT&CK map, SOAR playbooks, and the Admin panel.

---

## ✨ Features

### Log Parsing
| Format | Details |
|--------|---------|
| **Syslog** | RFC 3164 (BSD) and RFC 5424, auto-detected |
| **HTTP Access** | Apache/Nginx combined and common log format |
| **Database Audit** | MySQL general_log, PostgreSQL statement logs |

### Threat Detection
- **15 built-in rules** — Brute force, SQL injection, XSS, path traversal, web shell upload, Log4Shell, privilege escalation, SSH tunneling, DB exfiltration, and more
- **5 statistical anomaly detectors** — Volume spikes, error rate anomaly, off-hours activity, distributed attacks, rapid scanning
- **ML anomaly detection** — Isolation Forest model learns normal traffic and flags deviations per IP (8 behavioral features)

### SOAR (Security Orchestration, Automation & Response)
- **4 built-in playbooks** auto-triggered when alerts are created:
  - PB-001: Critical Alert Auto-Response (block IP + notify)
  - PB-002: Brute Force Response (block + escalate)
  - PB-003: Lateral Movement Containment (quarantine + enrich)
  - PB-004: Data Exfiltration Alert (notify + escalate + log)
- 6 action types: block IP, webhook, enrich IOC, escalate, log, quarantine
- Safe simulate mode — no real infrastructure changes in demo
- Full execution history viewable in the SOAR Dashboard

### Threat Intelligence
| Provider | What it does |
|----------|-------------|
| **VirusTotal** | IP, domain, hash, URL reputation |
| **AlienVault OTX** | Pulse-based threat correlation |
| **AbuseIPDB** | IP abuse confidence scoring |

Works in **demo mode** without API keys (returns realistic mock data).

### GeoIP Attack Map
- Geolocates source IPs from alerts (MaxMind GeoLite2 or built-in fallback)
- Country-level lat/lng for 20+ countries

### MITRE ATT&CK
- 27+ techniques mapped automatically across 12 tactics
- ATT&CK Navigator JSON export
- Tactic-based attack narrative + remediation recommendations

### Alert Correlation & Incidents
- Groups alerts by source IP and time window
- Multi-factor severity scoring (base × reputation × context)
- Auto-escalation for multi-tactic attacks

### Reports
- **JSON** and **HTML** reports with executive summary, timeline, IOC blocklist
- **PDF** via WeasyPrint (falls back to self-contained HTML)
- **MITRE Navigator Layer** JSON export

### Auth & Admin
- JWT authentication (register / login / `/me`)
- Role-based access: **Admin**, **Analyst**, **Read-Only**
- Admin panel: user management, audit logs, ML status, cold storage
- Immutable audit trail for all privileged actions

### Cold Storage
- Archive old logs to gzip-compressed JSON
- Storage stats dashboard (active vs. archived)
- Configurable retention period

### Dashboard Pages
| Page | Description |
|------|-------------|
| **Dashboard** | Metrics, severity charts, top IPs, recent alerts |
| **Alerts** | Filterable list, investigate / resolve / false-positive actions |
| **Incidents** | Correlated incidents with MITRE technique summary |
| **Log Ingestion** | Paste or upload log files, see parsing results in real-time |
| **MITRE ATT&CK** | Technique heatmap with detection counts |
| **Threat Intel** | IOC lookup (IP, domain, hash) |
| **SOAR** | Playbook viewer, test-execute, execution timeline |
| **Admin** | Audit logs, user management, storage, ML anomaly detection |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          ThreatTriage                                │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────────┤
│  Log     │  Threat  │ Analysis │  SOAR    │  Report  │  REST API    │
│  Parsers │  Intel   │  Engine  │  Engine  │  Gen     │  (FastAPI)   │
├──────────┼──────────┼──────────┼──────────┼──────────┼──────────────┤
│ Syslog   │ VirusTo. │ 15 Rules │ 4 Play-  │ JSON     │ /logs        │
│ HTTP     │ AlienV.  │ Anomaly  │  books   │ HTML/PDF │ /alerts      │
│ DB Audit │ AbuseIP  │ ML Isol. │ 6 Action │ MITRE    │ /incidents   │
│ (Plugin) │ GeoIP    │ Correlat.│  Types   │ Navigator│ /soar        │
│          │ (Multi)  │ Scoring  │ Simulate │          │ /admin       │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────────┘
     ↑           ↑          ↑          ↑          ↑           ↑
     └───────────┴──────────┴──────────┴──────────┴───────────┘
              Celery + Redis (Async) │ SQLite/PostgreSQL (Storage)
              WebSocket (Live Feed)  │ JWT Auth + RBAC
┌──────────────────────────────────────────────────────────────────────┐
│                    React SOC Dashboard (Vite)                        │
│  Dashboard │ Alerts │ Incidents │ MITRE │ SOAR │ Intel │ Admin      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 📡 API Reference

Full interactive docs at **http://localhost:8000/docs** after starting the server.

### Auth
```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","email":"analyst1@soc.local","password":"SecurePass123!"}'

# Login → returns { "access_token": "..." }
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"SecurePass123!"}'
```

### Core Endpoints
```bash
# All examples assume: TOKEN=<your JWT token>

# Ingest logs
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"raw_logs": ["Mar 5 08:23:41 host sshd[123]: Failed password for root from 1.2.3.4 port 22"]}'

# List alerts
curl http://localhost:8000/api/v1/alerts -H "Authorization: Bearer $TOKEN"

# List incidents
curl http://localhost:8000/api/v1/incidents -H "Authorization: Bearer $TOKEN"

# Dashboard metrics
curl http://localhost:8000/api/v1/dashboard/metrics -H "Authorization: Bearer $TOKEN"

# GeoIP data
curl http://localhost:8000/api/v1/dashboard/geoip -H "Authorization: Bearer $TOKEN"
```

### SOAR
```bash
curl http://localhost:8000/api/v1/soar/playbooks -H "Authorization: Bearer $TOKEN"
curl http://localhost:8000/api/v1/soar/history -H "Authorization: Bearer $TOKEN"
```

### ML Anomaly Detection
```bash
curl http://localhost:8000/api/v1/ml/status -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:8000/api/v1/ml/detect -H "Authorization: Bearer $TOKEN"
```

### Admin
```bash
curl http://localhost:8000/api/v1/admin/audit-logs -H "Authorization: Bearer $TOKEN"
curl http://localhost:8000/api/v1/admin/users -H "Authorization: Bearer $TOKEN"
curl http://localhost:8000/api/v1/admin/storage/stats -H "Authorization: Bearer $TOKEN"
curl -X POST "http://localhost:8000/api/v1/admin/storage/rotate?retention_days=7" \
  -H "Authorization: Bearer $TOKEN"
```

### PDF Reports
```bash
curl -X POST http://localhost:8000/api/v1/incidents/{incident_id}/pdf \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🧪 Testing

```bash
source .venv/bin/activate
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src/threattriage --cov-report=term-missing
```

---

## 📁 Project Structure

```
ThreatTriage/
├── start.sh                  # ⭐ One-command startup script
├── src/threattriage/
│   ├── main.py               # FastAPI app with lifespan
│   ├── config.py             # Pydantic Settings (env vars)
│   ├── database.py           # Async SQLModel + SQLite/PostgreSQL
│   ├── auth.py               # JWT + bcrypt password hashing
│   ├── celery_app.py         # Celery task queue config
│   ├── cli.py                # CLI commands (analyze, serve, demo)
│   ├── models/               # DB models (Alert, Incident, LogEntry, User, AuditLog, IOC)
│   ├── parsers/              # Syslog, HTTP access, DB audit parsers
│   ├── intel/                # VirusTotal, AlienVault, AbuseIPDB, GeoIP
│   ├── analysis/             # Detection rules, anomaly, ML, correlator, scorer, MITRE mapper
│   ├── soar/                 # SOAR playbook engine (4 playbooks, 6 action types)
│   ├── reports/              # HTML/JSON/PDF report generators
│   ├── tasks/                # Celery tasks + cold storage rotation
│   └── api/v1/               # REST routes (core, auth, intel, admin, websocket)
├── frontend/                 # React 19 + Vite 7 SPA
│   └── src/
│       ├── pages/            # Dashboard, Alerts, Incidents, Logs, MITRE,
│       │                     # ThreatIntel, SOARDashboard, AdminPanel
│       ├── components/       # Sidebar
│       └── api.js            # API client with JWT auth
├── tests/                    # Pytest suite
├── sample_data/              # Demo log files
├── reports/                  # Generated reports (gitignored)
├── docker-compose.yml        # Full-stack Docker deployment
└── pyproject.toml            # Python project config
```

---

## 🔧 Configuration

Set via environment variables or a `.env` file in the project root:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./threattriage.db` | Database connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis (for Celery tasks) |
| `DEMO_MODE` | `true` | Use mock threat intel data (no API keys needed) |
| `JWT_SECRET_KEY` | `change-me-in-production` | Secret for signing JWT tokens |
| `JWT_EXPIRE_MINUTES` | `1440` | Token expiry (default 24 hours) |
| `VIRUSTOTAL_API_KEY` | *(empty)* | VirusTotal API key (optional) |
| `ALIENVAULT_API_KEY` | *(empty)* | AlienVault OTX key (optional) |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB key (optional) |
| `API_KEY` | `threat-triage-dev-key` | API key authentication |

> **Note:** Everything works out of the box in demo mode. API keys are only needed if you want real threat intelligence enrichment.

---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Techniques | Example Detection |
|--------|-----------|-------------------|
| Reconnaissance | T1595.002 | Security scanner signatures |
| Initial Access | T1190, T1078, T1189 | SQL injection, valid accounts |
| Execution | T1059, T1203 | Command injection, exploits |
| Persistence | T1136, T1505.003, T1053 | Account creation, web shells |
| Privilege Escalation | T1548.003 | Sudo abuse |
| Credential Access | T1110 | Brute force attacks |
| Discovery | T1083, T1046 | Path traversal, port scanning |
| Lateral Movement | T1021 | SSH tunneling |
| Collection | T1005, T1530 | Data access patterns |
| Exfiltration | T1041, T1048 | Large transfers, DB exports |
| Command & Control | T1572 | SSH tunneling |
| Impact | T1485, T1498, T1561 | Data destruction, DoS |

---

## 🐳 CLI Usage

```bash
# Analyze a log file (outputs to terminal with Rich formatting)
threattriage analyze sample_data/syslog_sample.log --output reports/

# Run the full demo on all sample data
threattriage demo

# Start the API server
threattriage serve
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/awesome-feature`)
3. Commit your changes (`git commit -m 'Add awesome feature'`)
4. Push to the branch (`git push origin feature/awesome-feature`)
5. Open a Pull Request
