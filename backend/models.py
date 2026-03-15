"""
SIEM Log Analyzer - Pydantic Models
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class Log(BaseModel):
    id: int
    raw: str
    ts: str
    source: str
    level: str          # INFO | WARN | CRIT
    message: str
    ingested_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class Alert(BaseModel):
    id: int
    rule_id: int
    rule: str
    severity: str       # Critical | High | Medium | Low
    category: str
    message: str
    source: str
    ts: str
    raw: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class TimelineEntry(BaseModel):
    time: str
    text: str


class Incident(BaseModel):
    id: str
    title: str
    severity: str
    status: str         # Open | Investigating | Resolved
    assigned: str = "Unassigned"
    created: str = Field(default_factory=lambda: datetime.utcnow().strftime("%H:%M today"))
    description: str = ""
    ioc: str = ""
    mitre: str = ""
    affected: str = ""
    timeline: List[TimelineEntry] = []
    alert_id: Optional[int] = None


class Rule(BaseModel):
    id: int
    name: str
    pattern: str
    severity: str
    category: str
    desc: str
    enabled: bool = True
    hits: int = 0


class LogSource(BaseModel):
    name: str
    type: str
    status: str         # active | warning | error
    eps: int
    last: str
    total: int


# ── Request models ─────────────────────────────────────────────────

class IngestRequest(BaseModel):
    raw: str


class NewIncidentRequest(BaseModel):
    title: str = "New Investigation"
    severity: str = "Medium"
    description: str = ""
    assigned: str = "Unassigned"
    ioc: str = ""
    mitre: str = ""
    affected: str = ""


class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned: Optional[str] = None
    description: Optional[str] = None
    ioc: Optional[str] = None
    mitre: Optional[str] = None
    affected: Optional[str] = None
    timeline_entry: Optional[str] = None   # text for a new timeline entry


class NewRuleRequest(BaseModel):
    name: str
    pattern: str
    severity: str = "Medium"
    category: str = "Network"
    desc: str = "Custom detection rule"
    enabled: bool = True
