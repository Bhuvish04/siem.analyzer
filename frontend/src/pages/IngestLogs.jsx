// src/pages/IngestLogs.jsx
import { useState, useRef } from 'react'
import { useStore } from '../store'

const SAMPLE = `Jan 15 10:22:01 auth-server-dc1 sshd[3211]: Failed password for invalid user admin from 192.168.1.45 port 55123 ssh2
Jan 15 10:22:03 auth-server-dc1 sshd[3212]: Failed password for invalid user root from 192.168.1.45 port 55124 ssh2
Jan 15 10:22:05 auth-server-dc1 sshd[3213]: Failed password for user ubuntu from 192.168.1.45 port 55125 ssh2
Jan 15 10:22:10 firewall-01 kernel: DENIED IN=eth0 OUT= SRC=10.0.0.77 DST=192.168.1.1 PROTO=TCP DPT=22 blocked connection
Jan 15 10:22:15 web-server-prod apache2[1234]: 198.51.100.22 - - "GET /api/users?id=1 UNION SELECT username,password FROM admin--" 403 512
Jan 15 10:22:18 web-server-prod apache2[1235]: 198.51.100.22 - - "POST /login?user=admin&pass=' OR 1=1--" 400 128
Jan 15 10:22:20 db-server-pg postgres[5432]: ERROR: syntax error at or near "DROP TABLE users"
Jan 15 10:23:01 auth-server-dc1 sudo[4421]: pam_unix(sudo:auth): authentication failure; user=apache
Jan 15 10:23:05 endpoint-mgr edr[9012]: MALWARE DETECTED - trojan.exe blocked on endpoint-04 SHA256=a1b2c3d4
Jan 15 10:23:10 firewall-01 fw[100]: DENIED: large transfer 2300MB from db-server-pg to 203.0.113.99 unusual traffic
Jan 15 10:23:15 web-server-prod apache2[1237]: 198.51.100.22 - - "GET /robots.txt" 200 12 nikto/2.1.6 scanner
Jan 15 10:24:30 vpn-gateway openvpn[2211]: 203.0.113.5:4412 TLS handshake failed — port scan activity`

const PARSERS = [
  { name: 'Syslog (RFC 3164/5424)', desc: 'Standard Unix syslog format', pattern: '^(\\w{3}\\s+\\d+\\s+[\\d:]+)\\s+(\\S+)\\s+(\\S+):\\s+(.+)$' },
  { name: 'Apache / Nginx Access', desc: 'Combined log format', pattern: '^(\\S+)\\s+-\\s+-\\s+\\[(.+?)\\]\\s+"(.+?)"' },
  { name: 'JSON Structured', desc: 'JSON object per line', pattern: '^\\{.*"(message|msg|event)".*\\}$' },
  { name: 'Windows Event Log', desc: 'EventID + channel format', pattern: 'EventID=(\\d+).*Source=(\\S+)' },
]

export default function IngestLogs({ notify }) {
  const { ingestLogs, ingestFile, simulate } = useStore()
  const [raw, setRaw] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const fileRef = useRef()

  const handleIngest = async () => {
    if (!raw.trim()) { notify('⚠ No logs to analyze'); return }
    setLoading(true)
    try {
      const res = await ingestLogs(raw)
      setResult(res)
      setRaw('')
      if (res.alerts_triggered > 0) notify(`🚨 ${res.alerts_triggered} alert(s) triggered!`)
      else notify(`✓ ${res.ingested} logs ingested — no threats detected`)
    } finally {
      setLoading(false)
    }
  }

  const handleFile = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setLoading(true)
    try {
      const res = await ingestFile(file)
      setResult(res)
      notify(`✓ ${res.ingested} logs from ${res.filename} · ${res.alerts_triggered} alert(s)`)
    } finally {
      setLoading(false)
    }
  }

  const handleSimulate = async () => {
    await simulate()
    notify('🔔 Simulated live event sent')
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">Ingest Logs</h1>
        <button className="btn" onClick={handleSimulate}>Simulate Live Event</button>
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-title">Paste Raw Logs</div>
          <textarea
            className="log-textarea"
            value={raw}
            onChange={e => setRaw(e.target.value)}
            placeholder={`Paste raw log lines here...\n\nSupported formats:\n• Syslog: Jan 1 12:00:00 host sshd[123]: Failed password...\n• Apache: 1.2.3.4 - - [01/Jan/2024] "GET /path" 200 512\n• JSON: {"timestamp":"...","level":"error","message":"..."}\n• Windows: EventID=4625 Source=Security Message=...`}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
            <button className="btn primary" onClick={handleIngest} disabled={loading}>
              {loading ? 'Analyzing…' : 'Analyze & Ingest'}
            </button>
            <button className="btn" onClick={() => setRaw(SAMPLE)}>Load Sample Attack</button>
            <button className="btn" onClick={() => fileRef.current.click()}>Upload File</button>
            <input ref={fileRef} type="file" accept=".log,.txt,.csv" style={{ display: 'none' }} onChange={handleFile} />
          </div>
          {result && (
            <div className="ingest-result">
              ✓ Ingested <strong>{result.ingested}</strong> lines · Triggered <strong style={{ color: result.alerts_triggered > 0 ? '#E24B4A' : '#3B6D11' }}>{result.alerts_triggered}</strong> alert(s)
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-title">Parser Rules</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {PARSERS.map(p => (
              <div key={p.name} className="rule-card">
                <div style={{ flex: 1 }}>
                  <div className="rule-name">{p.name}</div>
                  <div className="rule-desc">{p.desc}</div>
                  <code className="rule-pattern">{p.pattern}</code>
                </div>
                <span className="badge info">active</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
