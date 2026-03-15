"""
SIEM Log Analyzer - FastAPI Backend
Run: uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import json
import re
from datetime import datetime
from typing import Optional
from collections import defaultdict
import random

from models import (
    Log, Alert, Incident, Rule, LogSource,
    IngestRequest, NewIncidentRequest, NewRuleRequest,
    UpdateIncidentRequest
)
from parser import LogParser
from detector import ThreatDetector
from store import DataStore

app = FastAPI(title="SIEM Log Analyzer", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = DataStore()
parser = LogParser()
detector = ThreatDetector(store)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()


# ── REST ENDPOINTS ────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "2.1.0", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/stats")
def get_stats():
    return store.get_stats()


@app.get("/api/logs")
def get_logs(
    search: Optional[str] = None,
    source: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 200
):
    return store.filter_logs(search=search, source=source, level=level, limit=limit)


@app.post("/api/ingest")
async def ingest_logs(req: IngestRequest):
    raw_lines = req.raw.strip().split("\n")
    raw_lines = [l.strip() for l in raw_lines if l.strip()]

    logs = []
    for line in raw_lines:
        log = parser.parse(line)
        store.add_log(log)
        logs.append(log)

    alerts = detector.analyze(logs)
    for alert in alerts:
        store.add_alert(alert)

    await manager.broadcast({
        "type": "ingest",
        "logs_count": len(logs),
        "alerts": [a.dict() for a in alerts]
    })

    return {
        "ingested": len(logs),
        "alerts_triggered": len(alerts),
        "alerts": [a.dict() for a in alerts]
    }


@app.post("/api/ingest/file")
async def ingest_file(file: UploadFile = File(...)):
    content = await file.read()
    raw = content.decode("utf-8", errors="replace")
    lines = [l.strip() for l in raw.split("\n") if l.strip()]

    logs = [parser.parse(line) for line in lines]
    for log in logs:
        store.add_log(log)

    alerts = detector.analyze(logs)
    for alert in alerts:
        store.add_alert(alert)

    await manager.broadcast({
        "type": "ingest",
        "logs_count": len(logs),
        "alerts": [a.dict() for a in alerts]
    })

    return {"filename": file.filename, "ingested": len(logs), "alerts_triggered": len(alerts)}


# ── ALERTS ────────────────────────────────────────────────────────

@app.get("/api/alerts")
def get_alerts(severity: Optional[str] = None, search: Optional[str] = None):
    return store.filter_alerts(severity=severity, search=search)


@app.delete("/api/alerts")
def clear_alerts():
    store.clear_alerts()
    return {"cleared": True}


@app.delete("/api/alerts/{alert_id}")
def delete_alert(alert_id: int):
    store.remove_alert(alert_id)
    return {"deleted": alert_id}


# ── INCIDENTS ─────────────────────────────────────────────────────

@app.get("/api/incidents")
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None
):
    return store.filter_incidents(status=status, severity=severity, search=search)


@app.post("/api/incidents")
def create_incident(req: NewIncidentRequest):
    inc = store.create_incident(req)
    return inc


@app.get("/api/incidents/{inc_id}")
def get_incident(inc_id: str):
    inc = store.get_incident(inc_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


@app.patch("/api/incidents/{inc_id}")
async def update_incident(inc_id: str, req: UpdateIncidentRequest):
    inc = store.update_incident(inc_id, req)
    if not inc:
        raise HTTPException(404, "Incident not found")
    await manager.broadcast({"type": "incident_updated", "incident": inc.dict()})
    return inc


@app.post("/api/incidents/from-alert/{alert_id}")
async def escalate_alert(alert_id: int):
    alert = store.get_alert(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    inc = store.escalate_alert_to_incident(alert)
    await manager.broadcast({"type": "incident_created", "incident": inc.dict()})
    return inc


# ── RULES ─────────────────────────────────────────────────────────

@app.get("/api/rules")
def get_rules(category: Optional[str] = None):
    return store.filter_rules(category=category)


@app.post("/api/rules")
def create_rule(req: NewRuleRequest):
    rule = store.add_rule(req)
    return rule


@app.patch("/api/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int):
    rule = store.toggle_rule(rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int):
    store.remove_rule(rule_id)
    return {"deleted": rule_id}


# ── SOURCES ───────────────────────────────────────────────────────

@app.get("/api/sources")
def get_sources():
    return store.get_sources()


# ── WEBSOCKET ─────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep alive + push live metrics every 5s
            await asyncio.sleep(5)
            await websocket.send_json({
                "type": "metrics",
                "data": store.get_stats()
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── SIMULATION (dev only) ─────────────────────────────────────────

@app.post("/api/simulate")
async def simulate_event():
    """Generate a random live log event (for demo/dev)."""
    templates = [
        "Jan 15 {ts} firewall-01 fw[100]: DENIED IN=eth0 OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=443 dropped packet",
        "Jan 15 {ts} auth-server-dc1 sshd[9999]: Failed password for invalid user test from {ip} port 22 ssh2",
        "Jan 15 {ts} web-server-prod apache2: {ip} - - \"GET /api/health\" 200 32",
        "Jan 15 {ts} vpn-gateway openvpn: {ip} TLS handshake complete",
        "Jan 15 {ts} web-server-prod apache2: {ip} - - \"GET /admin?id=1 UNION SELECT * FROM users--\" 403 128",
    ]
    ts = datetime.now().strftime("%H:%M:%S")
    ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    line = random.choice(templates).format(ts=ts, ip=ip)

    log = parser.parse(line)
    store.add_log(log)
    alerts = detector.analyze([log])
    for a in alerts:
        store.add_alert(a)

    await manager.broadcast({
        "type": "live_event",
        "log": log.dict(),
        "alerts": [a.dict() for a in alerts]
    })

    return {"log": log.dict(), "alerts": [a.dict() for a in alerts]}
