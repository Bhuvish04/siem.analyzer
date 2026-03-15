"""
SIEM Log Analyzer - Multi-Format Log Parser
Supports: Syslog RFC3164/5424, Apache/Nginx combined, JSON, Windows EventLog, generic fallback
"""

import re
import json
from datetime import datetime
from typing import Optional
from models import Log


class LogParser:
    _id_seq = 0

    # ── Format patterns ────────────────────────────────────────────
    SYSLOG_RE = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)'
        r'\s+(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<msg>.+)$'
    )
    SYSLOG5424_RE = re.compile(
        r'^<\d+>\d+\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)'
        r'\s+\S+\s+\S+\s+\S+\s+(?P<msg>.+)$'
    )
    APACHE_RE = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]'
        r'\s+"(?P<req>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\S+)'
    )
    WINDOWS_RE = re.compile(
        r'EventID=(?P<eid>\d+).*?Source=(?P<src>\S+).*?(?:Message=(?P<msg>.+))?$',
        re.IGNORECASE
    )
    GENERIC_RE = re.compile(
        r'^\[?(?P<level>CRIT(?:ICAL)?|ERROR|WARN(?:ING)?|INFO|DEBUG)\]?'
        r'[\s\-|:]+(?P<msg>.+)$',
        re.IGNORECASE
    )

    LEVEL_KEYWORDS = {
        'CRIT': re.compile(
            r'critical|malware|ransomware|trojan|virus|rootkit|exploit|'
            r'sql.inject|command.inject|rce|privilege.escalat',
            re.IGNORECASE
        ),
        'WARN': re.compile(
            r'failed|error|denied|blocked|refused|invalid|unauthorized|'
            r'forbidden|attack|scan|suspicious|anomaly|dropped',
            re.IGNORECASE
        ),
    }

    def _next_id(self) -> int:
        LogParser._id_seq += 1
        return LogParser._id_seq

    def _infer_level(self, text: str) -> str:
        if self.LEVEL_KEYWORDS['CRIT'].search(text):
            return 'CRIT'
        if self.LEVEL_KEYWORDS['WARN'].search(text):
            return 'WARN'
        return 'INFO'

    def parse(self, raw: str) -> Log:
        raw = raw.strip()
        log = None

        # 1. JSON structured
        if raw.startswith('{'):
            log = self._parse_json(raw)

        # 2. Syslog RFC 5424
        if not log:
            m = self.SYSLOG5424_RE.match(raw)
            if m:
                log = Log(
                    id=self._next_id(), raw=raw,
                    ts=m.group('ts')[:19],
                    source=m.group('host'),
                    level=self._infer_level(m.group('msg')),
                    message=m.group('msg'),
                )

        # 3. Syslog RFC 3164
        if not log:
            m = self.SYSLOG_RE.match(raw)
            if m:
                ts = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                msg = m.group('msg')
                log = Log(
                    id=self._next_id(), raw=raw,
                    ts=ts, source=m.group('host'),
                    level=self._infer_level(msg), message=msg,
                )

        # 4. Apache / Nginx combined log
        if not log:
            m = self.APACHE_RE.match(raw)
            if m:
                status = int(m.group('status'))
                level = 'CRIT' if status >= 500 else ('WARN' if status >= 400 else 'INFO')
                level = self._infer_level(m.group('req')) if level == 'INFO' else level
                log = Log(
                    id=self._next_id(), raw=raw,
                    ts=m.group('ts'),
                    source=m.group('ip'),
                    level=level,
                    message=f"{m.group('req')} → {status}",
                )

        # 5. Windows Event Log
        if not log:
            m = self.WINDOWS_RE.match(raw)
            if m:
                msg = m.group('msg') or f"EventID={m.group('eid')}"
                log = Log(
                    id=self._next_id(), raw=raw,
                    ts=datetime.utcnow().strftime("%H:%M:%S"),
                    source=m.group('src'),
                    level=self._infer_level(msg), message=msg,
                )

        # 6. Generic [LEVEL] ...
        if not log:
            m = self.GENERIC_RE.match(raw)
            if m:
                raw_level = m.group('level').upper()
                level_map = {'CRITICAL': 'CRIT', 'ERROR': 'WARN', 'WARNING': 'WARN', 'DEBUG': 'INFO'}
                level = level_map.get(raw_level, raw_level[:4])
                log = Log(
                    id=self._next_id(), raw=raw,
                    ts=datetime.utcnow().strftime("%H:%M:%S"),
                    source='unknown',
                    level=level, message=m.group('msg').strip(),
                )

        # 7. Fallback — store as-is
        if not log:
            log = Log(
                id=self._next_id(), raw=raw,
                ts=datetime.utcnow().strftime("%H:%M:%S"),
                source='unknown',
                level=self._infer_level(raw),
                message=raw[:200],
            )

        return log

    def _parse_json(self, raw: str) -> Optional[Log]:
        try:
            d = json.loads(raw)
            msg = d.get('message') or d.get('msg') or d.get('event') or str(d)
            ts = d.get('timestamp') or d.get('time') or d.get('@timestamp') or \
                 datetime.utcnow().strftime("%H:%M:%S")
            source = d.get('host') or d.get('source') or d.get('hostname') or 'json-ingest'
            level_raw = str(d.get('level') or d.get('severity') or '').upper()
            level_map = {'ERROR': 'WARN', 'WARNING': 'WARN', 'CRITICAL': 'CRIT',
                         'FATAL': 'CRIT', 'DEBUG': 'INFO', 'WARN': 'WARN', 'CRIT': 'CRIT'}
            level = level_map.get(level_raw, self._infer_level(msg))
            return Log(id=self._next_id(), raw=raw, ts=str(ts)[:19],
                       source=source, level=level, message=str(msg)[:300])
        except Exception:
            return None
