# 🛡️ ThreatTriage

**Automated SOC Alert & Log Analysis Engine**

A production-grade Python utility that ingests, parses, and analyzes enterprise log formats (syslog, HTTP access logs, database audit logs), enriches Indicators of Compromise via Threat Intelligence APIs (VirusTotal, AlienVault OTX, AbuseIPDB), and generates structured incident response reports mapped to the MITRE ATT&CK framework.

---

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14-red?logo=data:image/svg+xml;base64,...)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)

## ✨ Features

### 🔍 Multi-Format Log Parsing
- **Syslog** — RFC 3164 (BSD) and RFC 5424 with auto-detection
- **HTTP Access Logs** — Apache/Nginx combined and common log format
- **Database Audit Logs** — MySQL general_log and PostgreSQL statement logs
- Plugin-based parser registry with auto-format detection

### 🧠 Intelligent Detection Engine
- **15 built-in detection rules** (Sigma-inspired YAML format)
  - Brute force attacks, SQL injection, XSS, path traversal
  - Web shell upload, Log4Shell (CVE-2021-44228)
  - Privilege escalation, suspicious commands, SSH tunneling
  - Database exfiltration, destructive DDL, schema enumeration
- **5 statistical anomaly detectors**
  - Volume spike detection (Z-score based)
  - Error rate anomaly
  - Off-business-hours activity
  - Distributed attack detection
  - Rapid endpoint scanning

### 🌐 Threat Intelligence Integration
| Provider | Capabilities |
|----------|-------------|
| **VirusTotal** (v3 API) | IP, domain, file hash, URL reputation |
| **AlienVault OTX** | Pulse-based threat correlation |
| **AbuseIPDB** | IP abuse confidence scoring |

- Multi-provider enrichment with weighted score aggregation
- Redis-backed caching for rate limit management
- Demo mode with realistic mock data (works without API keys)

### 🎯 MITRE ATT&CK Framework
- Automatic technique mapping for all detections (27+ techniques)
- ATT&CK Navigator layer JSON export for visualization
- Tactic-based attack narrative generation
- Remediation recommendations per technique

### 📊 Alert Correlation & Scoring
- Groups alerts by source IP and time window into incidents
- Multi-factor severity scoring: base severity × TI reputation × context weight
- Automatic severity escalation for multi-tactic attacks

### 📝 Incident Response Reports
- **JSON** — Machine-readable structured reports
- **HTML** — Professional dark-themed reports with:
  - Executive summary and metrics
  - MITRE ATT&CK technique table
  - Alert details with severity badges
  - Event timeline
  - IOC blocklist
  - Remediation recommendations
- **MITRE Navigator Layer** — Importable JSON for ATT&CK Navigator

### 🚀 REST API (FastAPI)
- Full OpenAPI/Swagger documentation at `/docs`
- Endpoints for log ingestion, alert management, TI lookups
- Dashboard metrics and MITRE heatmap data
- API key authentication with demo-mode bypass

### 💻 CLI Interface
- `threattriage analyze` — Analyze log files with Rich terminal output
- `threattriage serve` — Start the API server
- `threattriage demo` — Run analysis on sample data

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ThreatTriage                             │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│  Log     │  Threat  │ Analysis │  Report  │   REST API          │
│  Parsers │  Intel   │  Engine  │  Gen     │   (FastAPI)         │
├──────────┼──────────┼──────────┼──────────┼─────────────────────┤
│ Syslog   │ VirusTo. │ 15 Rules │ JSON     │ /api/v1/logs        │
│ HTTP     │ AlienV.  │ Anomaly  │ HTML/PDF │ /api/v1/alerts      │
│ DB Audit │ AbuseIP  │ Correlat.│ MITRE    │ /api/v1/intel       │
│ (Plugin) │ (Multi)  │ Scoring  │ Navigator│ /api/v1/dashboard   │
└──────────┴──────────┴──────────┴──────────┴─────────────────────┘
     ↑           ↑          ↑          ↑              ↑
     └───────────┴──────────┴──────────┴──────────────┘
                    Celery + Redis (Async)
                    PostgreSQL (Storage)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose (optional, for full stack)

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/ThreatTriage.git
cd ThreatTriage

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install
pip install -e ".[dev]"

# Copy environment config
cp .env.example .env
```

### 2. Run Demo Analysis (No Docker Required)

```bash
# Analyze sample logs with beautiful CLI output
threattriage analyze sample_data/syslog_sample.log --output reports/
threattriage analyze sample_data/apache_access.log --output reports/
threattriage analyze sample_data/db_audit.log --output reports/

# Or run the full demo
threattriage demo
```

### 3. Start the API Server

```bash
# Development server
threattriage serve

# Or directly with uvicorn
uvicorn threattriage.main:app --reload
```

Then open **http://localhost:8000/docs** for interactive API documentation.

### 4. Full Stack with Docker

```bash
docker compose up -d
```

This starts: FastAPI API, Celery workers, Redis, PostgreSQL, and Flower monitoring.

---

## 📡 API Usage

### Ingest Logs
```bash
# Ingest raw log lines
curl -X POST http://localhost:8000/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "raw_logs": [
      "Mar  5 08:23:41 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2",
      "185.220.101.1 - - [05/Mar/2024:09:00:00 +0000] \"GET /api/users?id=1 UNION SELECT * FROM users HTTP/1.1\" 200 4521 \"-\" \"sqlmap/1.7\""
    ]
  }'

# Upload a log file
curl -X POST http://localhost:8000/api/v1/logs/upload \
  -F "file=@sample_data/syslog_sample.log"
```

### Query Alerts & Dashboard
```bash
# List all alerts
curl http://localhost:8000/api/v1/alerts

# Dashboard metrics
curl http://localhost:8000/api/v1/dashboard/metrics

# MITRE heatmap
curl http://localhost:8000/api/v1/dashboard/mitre
```

### Threat Intelligence Lookup
```bash
curl -X POST http://localhost:8000/api/v1/intel/lookup \
  -H "Content-Type: application/json" \
  -d '{"ioc_type": "ip", "value": "185.220.101.1"}'
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src/threattriage --cov-report=term-missing

# Run specific test modules
pytest tests/test_parsers.py -v
pytest tests/test_analysis.py -v
```

---

## 📁 Project Structure

```
ThreatTriage/
├── src/threattriage/
│   ├── main.py              # FastAPI application
│   ├── config.py             # Pydantic Settings
│   ├── database.py           # Async SQLModel engine
│   ├── celery_app.py         # Celery configuration
│   ├── cli.py                # Typer CLI
│   ├── models/               # SQLModel DB models
│   ├── schemas/              # Pydantic API schemas
│   ├── parsers/              # Log parsing engine
│   │   ├── base.py           # Parser registry
│   │   ├── syslog.py         # RFC 3164/5424
│   │   ├── http_access.py    # Apache/Nginx
│   │   └── db_audit.py       # MySQL/PostgreSQL
│   ├── intel/                # Threat Intelligence
│   │   ├── virustotal.py     # VirusTotal v3
│   │   ├── alienvault.py     # AlienVault OTX
│   │   ├── abuseipdb.py      # AbuseIPDB
│   │   └── enrichment.py     # Multi-provider pipeline
│   ├── analysis/             # Detection engine
│   │   ├── detection.py      # 15 Sigma-inspired rules
│   │   ├── anomaly.py        # Statistical anomalies
│   │   ├── correlator.py     # Alert correlation
│   │   ├── scorer.py         # Severity scoring
│   │   └── mitre_mapper.py   # MITRE ATT&CK mapping
│   ├── reports/              # Report generation
│   │   ├── generator.py
│   │   └── templates/
│   └── api/v1/               # REST API routers
├── tests/                    # Pytest test suite
├── sample_data/              # Demo log files
├── docker-compose.yml        # Full-stack deployment
├── Dockerfile               # Multi-stage build
└── pyproject.toml           # Project configuration
```

---

## 🔧 Configuration

All configuration is managed via environment variables or `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./threattriage.db` | Database connection |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `VIRUSTOTAL_API_KEY` | *(empty)* | VirusTotal API key |
| `ALIENVAULT_API_KEY` | *(empty)* | AlienVault OTX key |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB API key |
| `DEMO_MODE` | `true` | Enable demo mode (mock TI data) |
| `API_KEY` | `threat-triage-dev-key` | API authentication key |

---

## 🎯 MITRE ATT&CK Coverage

ThreatTriage detects and maps to the following MITRE ATT&CK tactics:

| Tactic | Techniques | Example Detection |
|--------|-----------|-------------------|
| **Reconnaissance** | T1595.002 | Security scanner signatures |
| **Initial Access** | T1190, T1078, T1189 | SQL injection, valid accounts |
| **Execution** | T1059, T1203 | Command injection, exploits |
| **Persistence** | T1136, T1505.003, T1053 | Account creation, web shells, cron |
| **Privilege Escalation** | T1548.003 | Sudo abuse |
| **Credential Access** | T1110 | Brute force attacks |
| **Discovery** | T1083, T1046 | Path traversal, port scanning |
| **Collection** | T1005, T1530 | Data access patterns |
| **Exfiltration** | T1041, T1048 | Large transfers, DB exports |
| **Command & Control** | T1572 | SSH tunneling |
| **Impact** | T1485, T1498, T1561 | Data destruction, DoS |

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
