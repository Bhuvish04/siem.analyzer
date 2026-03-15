<<<<<<< HEAD
# siem.analyzer
=======
# SIEM Log Analyzer

A full-stack mini SIEM (Security Information and Event Management) system with:

- **Real-time log ingestion** — paste raw logs or upload files
- **Multi-format parser** — Syslog RFC3164/5424, Apache/Nginx, JSON, Windows Event Log
- **Rule-based detection engine** — regex pattern matching with 9 built-in rules
- **Anomaly detection** — IP burst detection (>10 events/30s from same IP)
- **Incident management** — full lifecycle with timeline, MITRE ATT&CK mapping, status tracking
- **Alert feed** — escalate alerts to incidents with one click
- **Live WebSocket updates** — real-time event streaming to all connected clients
- **Log Explorer** — searchable, filterable log viewer
- **Detection Rules editor** — add/enable/disable custom regex rules

---

## Project Structure

```
siem/
├── backend/
│   ├── main.py          # FastAPI app + REST + WebSocket endpoints
│   ├── models.py        # Pydantic data models
│   ├── parser.py        # Multi-format log parser
│   ├── detector.py      # Rule-based + anomaly threat detection
│   ├── store.py         # In-memory data store (swap for DB)
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── App.jsx          # Root component + sidebar nav + WebSocket
    │   ├── App.css          # All styles (dark mode included)
    │   ├── store.js         # Zustand global state + API calls
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

## Setup & Run

### 1. Backend

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload --port 8000
```

The API will be live at: http://localhost:8000  
Interactive docs: http://localhost:8000/docs

### 2. Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

Open: http://localhost:5173

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Aggregated metrics |
| GET | `/api/logs` | Fetch logs (search, source, level filters) |
| POST | `/api/ingest` | Ingest raw log string |
| POST | `/api/ingest/file` | Upload log file |
| GET | `/api/alerts` | List alerts |
| DELETE | `/api/alerts` | Clear all alerts |
| DELETE | `/api/alerts/{id}` | Delete one alert |
| GET | `/api/incidents` | List incidents |
| POST | `/api/incidents` | Create incident |
| PATCH | `/api/incidents/{id}` | Update incident |
| POST | `/api/incidents/from-alert/{id}` | Escalate alert → incident |
| GET | `/api/rules` | List detection rules |
| POST | `/api/rules` | Add detection rule |
| PATCH | `/api/rules/{id}/toggle` | Enable/disable rule |
| DELETE | `/api/rules/{id}` | Delete rule |
| GET | `/api/sources` | List log sources |
| POST | `/api/simulate` | Fire a random simulated event |
| WS | `/ws` | WebSocket: live metrics + event stream |

---

## Supported Log Formats

**Syslog RFC 3164**
```
Jan 15 10:22:01 host sshd[123]: Failed password for user admin
```

**Syslog RFC 5424**
```
<34>1 2024-01-15T10:22:01Z host sshd 123 - - Failed password
```

**Apache / Nginx Combined**
```
1.2.3.4 - - [15/Jan/2024:10:22:01] "GET /path" 200 1234
```

**JSON Structured**
```json
{"timestamp":"2024-01-15T10:22:01","level":"error","host":"web-01","message":"Auth failed"}
```

**Windows Event Log**
```
EventID=4625 Source=Security Message=An account failed to log on
```

---

## Built-in Detection Rules

| Rule | Severity | Pattern |
|------|----------|---------|
| SSH Brute Force | Critical | `failed.password\|invalid.user` |
| Port Scan | High | `connection.refused\|port.scan\|nmap` |
| SQL Injection | Critical | `union.select\|or.1=1\|drop.table` |
| Privilege Escalation | High | `sudo.*FAILED\|privilege.escalat` |
| Malware Execution | Critical | `malware\|trojan\|ransomware` |
| Data Exfiltration | High | `large.transfer\|exfiltrat\|unusual.traffic` |
| Firewall Denied | Medium | `DENIED\|dropped.*packet` |
| Web Scanner | Medium | `nikto\|sqlmap\|masscan\|gobuster` |
| Suspicious UA | Low | `python-requests\|wget.*quiet` |

Custom rules can be added via the UI or POST `/api/rules`.

---

## Extending to Production

- **Database**: Replace `store.py` with SQLAlchemy + PostgreSQL/SQLite
- **Auth**: Add JWT middleware to FastAPI
- **Persistence**: Add Elasticsearch for log storage at scale
- **Alerting**: Integrate PagerDuty / Slack webhook from `detector.py`
- **Deployment**: Docker Compose — FastAPI + React + Nginx
>>>>>>> 37ca026 (Added SIEM analyzer code)
