"""
SIEM Log Analyzer - Threat Detection Engine
Rule-based pattern matching + basic anomaly detection (burst / repeat IP)
"""

import re
from collections import defaultdict, deque
from typing import Optional
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from models import Alert, Log

if TYPE_CHECKING:
    from store import DataStore


class ThreatDetector:
    def __init__(self, store: "DataStore"):
        self.store = store
        # Per-IP event windows for burst detection (last 60 events per IP)
        self._ip_windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self._alert_seq = 10000   # alert IDs start high to avoid collision with seeded data

    def _next_id(self) -> int:
        self._alert_seq += 1
        return self._alert_seq

    def _extract_ip(self, raw: str) -> Optional[str]:
        m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw)
        return m.group(1) if m else None

    def analyze(self, logs: list[Log]) -> list[Alert]:
        alerts = []
        rules = [r for r in self.store.get_all_rules() if r.enabled]

        for log in logs:
            # 1. Rule-based matching
            for rule in rules:
                try:
                    if re.search(rule.pattern, log.raw, re.IGNORECASE):
                        rule.hits += 1
                        alerts.append(Alert(
                            id=self._next_id(),
                            rule_id=rule.id,
                            rule=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            message=log.message[:150],
                            source=log.source,
                            ts=log.ts,
                            raw=log.raw,
                        ))
                        break   # one alert per log per pass
                except re.error:
                    pass

            # 2. Burst / repeat-IP anomaly detection
            ip = self._extract_ip(log.raw)
            if ip:
                window = self._ip_windows[ip]
                window.append(datetime.utcnow())
                # >10 events from same IP within last 30 seconds → anomaly
                cutoff = datetime.utcnow() - timedelta(seconds=30)
                recent = sum(1 for t in window if t > cutoff)
                if recent == 10:    # fire exactly at threshold, not every event
                    alerts.append(Alert(
                        id=self._next_id(),
                        rule_id=0,
                        rule='IP Burst Anomaly',
                        severity='High',
                        category='Reconnaissance',
                        message=f"High event rate from {ip}: {recent} events in 30s",
                        source=log.source,
                        ts=log.ts,
                        raw=log.raw,
                    ))

        return alerts
