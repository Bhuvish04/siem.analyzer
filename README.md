# 🛡️ SIEM Log Analyzer

A full-stack **Security Information and Event Management (SIEM)** system built with FastAPI + React. Ingest logs, detect threats in real-time, manage incidents, and visualize security events — all from a clean dashboard.

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.135-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?logo=pydantic)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- **Real-time log ingestion** — paste raw logs or upload `.log` / `.txt` files
- **Multi-format parser** — Syslog RFC3164/5424, Apache/Nginx, JSON, Windows Event Log
- **Rule-based detection engine** — regex pattern matching with 9 built-in rules
- **Anomaly detection** — IP burst detection (>10 events in 30s from same IP)
- **Incident management** — full lifecycle with timeline, MITRE ATT&CK mapping, status tracking
- **Alert feed** — escalate any alert to an incident with one click
- **Live WebSocket updates** — real-time event streaming to all connected clients
- **Log Explorer** — searchable, filterable log viewer
- **Custom detection rules** — add your own regex rules via UI or API
- **Dark mode** — fully supported

---

## 🏗️ Tech Stack

| Layer | Tech |
|-------|------|
| Backend | Python 3.13, FastAPI, Uvicorn, Pydantic v2 |
| Frontend | React 18, Vite, Zustand |
| Realtime | WebSockets |
| Styling | Plain CSS (dark mode included) |

---

## 📁 Project Structure

```
siem/
├── backend/
│   ├── main.py          # FastAPI app — REST + WebSocket endpoints
│   ├── models.py        # Pydantic data models
│   ├── parser.py        # Multi-format log parser
│   ├── detector.py      # Rule-based + anomaly threat detection
│   ├── store.py         # In-memory data store
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── App.jsx
    │   ├── App.css
    │   ├── store.js
    │   ├── pages/
    │   │   ├── Dashboard.jsx
    │   │   ├── Incidents.jsx
    │   │   ├── Alerts.jsx
    │   │   ├── LogExplorer.jsx
    │   │   ├── IngestLogs.jsx
    │   │   ├── Rules.jsx
    │   │   └── Sources.jsx
    │   └── components/
    │       ├── Badge.jsx
    │       ├── MetricCard.jsx
    │       ├── Modal.jsx
    │       └── Notification.jsx
    ├── index.html
    ├── package.json
    └── vite.config.js
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm

### 1. Clone the repo

```bash
git clone https://github.com/Bhuvish04/siem.analyzer.git
cd siem.analyzer
```

### 2. Backend setup

```bash
cd backend

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install "pydantic>=2.10" fastapi uvicorn python-multipart websockets

./.venv/bin/uvicorn main:app --reload --port 8000
```

API running at: **http://localhost:8000**  
Interactive docs: **http://localhost:8000/docs**

### 3. Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Open: **http://localhost:5173**

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Aggregated metrics |
| `GET` | `/api/logs` | Fetch logs with filters |
| `POST` | `/api/ingest` | Ingest raw log string |
| `POST` | `/api/ingest/file` | Upload log file |
| `GET` | `/api/alerts` | List alerts |
| `DELETE` | `/api/alerts` | Clear all alerts |
| `GET` | `/api/incidents` | List incidents |
| `POST` | `/api/incidents` | Create incident |
| `PATCH` | `/api/incidents/{id}` | Update incident |
| `POST` | `/api/incidents/from-alert/{id}` | Escalate alert → incident |
| `GET` | `/api/rules` | List detection rules |
| `POST` | `/api/rules` | Add custom rule |
| `PATCH` | `/api/rules/{id}/toggle` | Enable / disable rule |
| `DELETE` | `/api/rules/{id}` | Delete rule |
| `GET` | `/api/sources` | List log sources |
| `POST` | `/api/simulate` | Fire a simulated live event |
| `WS` | `/ws` | WebSocket live stream |

---

## 📋 Supported Log Formats

**Syslog RFC 3164**
```
Jan 15 10:22:01 host sshd[123]: Failed password for user admin
```

**Apache / Nginx Combined**
```
1.2.3.4 - - [15/Jan/2024:10:22:01] "GET /path" 200 1234
```

**JSON Structured**
```json
{"timestamp": "2024-01-15T10:22:01", "level": "error", "message": "Auth failed"}
```

**Windows Event Log**
```
EventID=4625 Source=Security Message=An account failed to log on
```

---

## 🔍 Built-in Detection Rules

| Rule | Severity | Detects |
|------|----------|---------|
| SSH Brute Force | 🔴 Critical | `failed password`, `invalid user` |
| SQL Injection | 🔴 Critical | `UNION SELECT`, `OR 1=1`, `DROP TABLE` |
| Malware Execution | 🔴 Critical | `trojan`, `ransomware`, `malware` |
| Privilege Escalation | 🟠 High | `sudo FAILED`, `privilege escalat` |
| Data Exfiltration | 🟠 High | `large transfer`, `unusual traffic` |
| Port Scan | 🟠 High | `port scan`, `nmap`, `connection refused` |
| Firewall Denied | 🟡 Medium | `DENIED`, `dropped packet` |
| Web Scanner | 🟡 Medium | `nikto`, `sqlmap`, `gobuster` |
| Suspicious User Agent | 🟢 Low | `python-requests`, `wget --quiet` |

---

## 🔧 Extending to Production

- **Database** — replace `store.py` with SQLAlchemy + PostgreSQL
- **Authentication** — add JWT middleware to FastAPI
- **Scale** — swap in Elasticsearch for log storage
- **Alerting** — add PagerDuty / Slack webhooks in `detector.py`
- **Deploy** — Docker Compose with FastAPI + React + Nginx

---

## 📄 License

MIT — free to use, modify, and distribute.
