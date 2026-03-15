"""
SIEM Log Analyzer - In-Memory Data Store
Swap out for SQLite/Postgres by replacing the methods here.
"""

from datetime import datetime
from collections import defaultdict
from typing import Optional
from models import (
    Log, Alert, Incident, Rule, LogSource,
    TimelineEntry, NewIncidentRequest, NewRuleRequest, UpdateIncidentRequest
)


class DataStore:
    def __init__(self):
        self._logs: list[Log] = []
        self._alerts: list[Alert] = []
        self._incidents: list[Incident] = []
        self._rules: list[Rule] = []
        self._sources: list[LogSource] = []
        self._inc_seq = 1
        self._rule_seq = 1
        self._seed()

    # ── Seed default data ──────────────────────────────────────────

    def _seed(self):
        self._rules = [
            Rule(id=self._rule_seq_next(), name='SSH Brute Force',
                 pattern=r'failed.password|invalid.user|authentication.failure',
                 severity='Critical', category='Authentication',
                 desc='Multiple SSH login failures'),
            Rule(id=self._rule_seq_next(), name='Port Scan Detected',
                 pattern=r'connection.refused|port.scan|nmap',
                 severity='High', category='Reconnaissance',
                 desc='Network port scanning activity'),
            Rule(id=self._rule_seq_next(), name='SQL Injection Attempt',
                 pattern=r'union.select|or.1=1|drop.table|xp_cmdshell',
                 severity='Critical', category='Network',
                 desc='SQL injection pattern in web requests'),
            Rule(id=self._rule_seq_next(), name='Privilege Escalation',
                 pattern=r'sudo.*FAILED|su.*failed|privilege.escalat',
                 severity='High', category='Authentication',
                 desc='Unauthorized privilege escalation attempt'),
            Rule(id=self._rule_seq_next(), name='Malware Execution',
                 pattern=r'malware|virus.detected|trojan|ransomware|\.exe.*blocked',
                 severity='Critical', category='Malware',
                 desc='Malware or virus execution detected'),
            Rule(id=self._rule_seq_next(), name='Data Exfiltration',
                 pattern=r'large.transfer|exfiltrat|unusual.traffic|upload.*MB',
                 severity='High', category='Exfiltration',
                 desc='Potential data exfiltration activity'),
            Rule(id=self._rule_seq_next(), name='Firewall Denied',
                 pattern=r'DENIED|dropped.*packet|blocked.*connection',
                 severity='Medium', category='Network',
                 desc='Firewall blocking suspicious connections'),
            Rule(id=self._rule_seq_next(), name='Web Scanner Detected',
                 pattern=r'nikto|sqlmap|masscan|dirb|gobuster',
                 severity='Medium', category='Reconnaissance',
                 desc='Known web scanner or crawler detected'),
            Rule(id=self._rule_seq_next(), name='Suspicious User Agent',
                 pattern=r'python-requests|curl.*--insecure|wget.*quiet|masscan',
                 severity='Low', category='Network',
                 desc='Automated or suspicious HTTP client',
                 enabled=False),
        ]

        self._sources = [
            LogSource(name='firewall-01', type='Firewall', status='active', eps=42, last='2s ago', total=18420),
            LogSource(name='web-server-prod', type='Apache', status='active', eps=128, last='1s ago', total=54310),
            LogSource(name='auth-server-dc1', type='Active Directory', status='active', eps=31, last='3s ago', total=12750),
            LogSource(name='db-server-pg', type='PostgreSQL', status='active', eps=9, last='5s ago', total=4200),
            LogSource(name='endpoint-mgr', type='EDR', status='warning', eps=0, last='45s ago', total=3100),
            LogSource(name='vpn-gateway', type='VPN', status='active', eps=17, last='2s ago', total=6830),
        ]

        self._incidents = [
            Incident(id='INC-001', title='SSH Brute Force Campaign',
                     severity='Critical', status='Investigating', assigned='J. Smith',
                     created='10:23 today',
                     description='Multiple IPs attempting SSH brute force against auth-server-dc1. Over 400 failed attempts in 10 minutes.',
                     ioc='192.168.1.45, 10.0.0.77, 203.0.113.5',
                     mitre='T1110 - Brute Force', affected='auth-server-dc1',
                     timeline=[
                         TimelineEntry(time='10:23', text='First alerts triggered'),
                         TimelineEntry(time='10:31', text='Pattern confirmed — brute force'),
                         TimelineEntry(time='10:45', text='Source IPs blocked at firewall'),
                     ]),
            Incident(id='INC-002', title='SQL Injection Attempt on API',
                     severity='High', status='Open', assigned='A. Patel',
                     created='08:51 today',
                     description='Web scanner detected performing SQLi against /api/users endpoint.',
                     ioc='198.51.100.22', mitre='T1190 - Exploit Public App',
                     affected='web-server-prod',
                     timeline=[
                         TimelineEntry(time='08:51', text='WAF rule triggered'),
                         TimelineEntry(time='09:10', text='IP added to watchlist'),
                     ]),
            Incident(id='INC-003', title='Outbound Data Transfer Anomaly',
                     severity='High', status='Open', assigned='Unassigned',
                     created='Yesterday',
                     description='Unusual outbound data transfer of 2.3GB to external IP detected from db-server-pg during off-hours.',
                     ioc='203.0.113.99', mitre='T1048 - Exfiltration',
                     affected='db-server-pg',
                     timeline=[
                         TimelineEntry(time='23:04', text='Volume anomaly detected'),
                         TimelineEntry(time='23:07', text='Connection terminated'),
                     ]),
            Incident(id='INC-004', title='Malware Binary Blocked',
                     severity='Critical', status='Resolved', assigned='K. Lee',
                     created='Yesterday',
                     description='EDR blocked execution of malicious binary on endpoint-04.',
                     ioc='SHA256: a1b2c3d4ef', mitre='T1059 - Command Execution',
                     affected='endpoint-04',
                     timeline=[
                         TimelineEntry(time='14:22', text='Binary execution attempted'),
                         TimelineEntry(time='14:22', text='EDR blocked + quarantined'),
                         TimelineEntry(time='15:10', text='Forensic analysis complete'),
                         TimelineEntry(time='16:00', text='Incident resolved'),
                     ]),
        ]
        self._inc_seq = 5

    def _rule_seq_next(self) -> int:
        v = self._rule_seq
        self._rule_seq += 1
        return v

    # ── Logs ───────────────────────────────────────────────────────

    def add_log(self, log: Log):
        self._logs.insert(0, log)
        if len(self._logs) > 10_000:
            self._logs = self._logs[:10_000]

    def filter_logs(self, search=None, source=None, level=None, limit=200) -> list[dict]:
        results = self._logs
        if search:
            s = search.lower()
            results = [l for l in results if s in l.raw.lower()]
        if source:
            results = [l for l in results if l.source == source]
        if level:
            results = [l for l in results if l.level == level]
        return [l.dict() for l in results[:limit]]

    def get_log_sources(self) -> list[str]:
        seen = set()
        out = []
        for l in self._logs:
            if l.source not in seen:
                seen.add(l.source)
                out.append(l.source)
        return out

    # ── Alerts ─────────────────────────────────────────────────────

    def add_alert(self, alert: Alert):
        self._alerts.insert(0, alert)

    def get_alert(self, alert_id: int) -> Alert | None:
        return next((a for a in self._alerts if a.id == alert_id), None)

    def remove_alert(self, alert_id: int):
        self._alerts = [a for a in self._alerts if a.id != alert_id]

    def clear_alerts(self):
        self._alerts = []

    def filter_alerts(self, severity=None, search=None) -> list[dict]:
        results = self._alerts
        if severity:
            results = [a for a in results if a.severity == severity]
        if search:
            s = search.lower()
            results = [a for a in results if s in a.rule.lower() or s in a.message.lower()]
        return [a.dict() for a in results]

    # ── Incidents ──────────────────────────────────────────────────

    def create_incident(self, req: NewIncidentRequest) -> Incident:
        inc_id = f'INC-{str(self._inc_seq).zfill(3)}'
        self._inc_seq += 1
        inc = Incident(
            id=inc_id,
            title=req.title,
            severity=req.severity,
            status='Open',
            assigned=req.assigned,
            description=req.description,
            ioc=req.ioc,
            mitre=req.mitre,
            affected=req.affected,
            timeline=[TimelineEntry(time=datetime.now().strftime('%H:%M'), text='Incident created')]
        )
        self._incidents.insert(0, inc)
        return inc

    def get_incident(self, inc_id: str) -> Optional[Incident]:
        return next((i for i in self._incidents if i.id == inc_id), None)

    def update_incident(self, inc_id: str, req: UpdateIncidentRequest) -> Optional[Incident]:
        inc = self.get_incident(inc_id)
        if not inc:
            return None
        if req.status: inc.status = req.status
        if req.severity: inc.severity = req.severity
        if req.assigned: inc.assigned = req.assigned
        if req.description: inc.description = req.description
        if req.ioc: inc.ioc = req.ioc
        if req.mitre: inc.mitre = req.mitre
        if req.affected: inc.affected = req.affected
        if req.timeline_entry:
            inc.timeline.append(TimelineEntry(
                time=datetime.now().strftime('%H:%M'),
                text=req.timeline_entry
            ))
        return inc

    def escalate_alert_to_incident(self, alert: Alert) -> Incident:
        inc_id = f'INC-{str(self._inc_seq).zfill(3)}'
        self._inc_seq += 1
        inc = Incident(
            id=inc_id,
            title=alert.rule,
            severity=alert.severity,
            status='Open',
            assigned='Unassigned',
            description=alert.message,
            ioc=alert.source,
            affected=alert.source,
            alert_id=alert.id,
            timeline=[
                TimelineEntry(time=datetime.now().strftime('%H:%M'), text=f'Escalated from alert #{alert.id}')
            ]
        )
        self._incidents.insert(0, inc)
        return inc

    def filter_incidents(self, status=None, severity=None, search=None) -> list[dict]:
        results = self._incidents
        if status:
            results = [i for i in results if i.status == status]
        if severity:
            results = [i for i in results if i.severity == severity]
        if search:
            s = search.lower()
            results = [i for i in results if s in i.title.lower() or s in i.id.lower()]
        return [i.dict() for i in results]

    # ── Rules ──────────────────────────────────────────────────────

    def get_all_rules(self) -> list[Rule]:
        return self._rules

    def add_rule(self, req: NewRuleRequest) -> Rule:
        rule = Rule(
            id=self._rule_seq_next(),
            name=req.name,
            pattern=req.pattern,
            severity=req.severity,
            category=req.category,
            desc=req.desc,
            enabled=req.enabled,
        )
        self._rules.append(rule)
        return rule

    def toggle_rule(self, rule_id: int) -> Optional[Rule]:
        rule = next((r for r in self._rules if r.id == rule_id), None)
        if rule:
            rule.enabled = not rule.enabled
        return rule

    def remove_rule(self, rule_id: int):
        self._rules = [r for r in self._rules if r.id != rule_id]

    def filter_rules(self, category=None) -> list[dict]:
        results = self._rules
        if category:
            results = [r for r in results if r.category == category]
        return [r.dict() for r in results]

    # ── Sources ────────────────────────────────────────────────────

    def get_sources(self) -> list[dict]:
        return [s.dict() for s in self._sources]

    # ── Stats ──────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        from collections import Counter
        alert_sevs = Counter(a.severity for a in self._alerts)
        alert_cats = Counter(a.category for a in self._alerts)
        log_levels = Counter(l.level for l in self._logs)
        log_sources = Counter(l.source for l in self._logs)

        return {
            "total_logs": len(self._logs),
            "total_alerts": len(self._alerts),
            "total_incidents": len(self._incidents),
            "active_sources": sum(1 for s in self._sources if s.status == 'active'),
            "alert_by_severity": dict(alert_sevs),
            "alert_by_category": dict(alert_cats),
            "log_by_level": dict(log_levels),
            "top_sources": dict(log_sources.most_common(10)),
            "open_incidents": sum(1 for i in self._incidents if i.status == 'Open'),
            "investigating_incidents": sum(1 for i in self._incidents if i.status == 'Investigating'),
            "resolved_incidents": sum(1 for i in self._incidents if i.status == 'Resolved'),
        }
