// src/pages/Dashboard.jsx
import { useStore } from '../store'
import MetricCard from '../components/MetricCard'
import Badge from '../components/Badge'

export default function Dashboard({ navigate }) {
  const { stats, alerts, incidents } = useStore()

  const threatCats = stats.alert_by_category || {}
  const maxCat = Math.max(...Object.values(threatCats), 1)
  const catColors = {
    Authentication: '#E24B4A', Network: '#EF9F27',
    Malware: '#A32D2D', Exfiltration: '#BA7517', Reconnaissance: '#185FA5'
  }

  const ipCounts = {}
  // derive from alert sources as proxy
  alerts.forEach(a => {
    const m = a.raw?.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/)
    if (m) ipCounts[m[1]] = (ipCounts[m[1]] || 0) + 1
  })
  const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 8)

  const dist = stats.log_by_level || {}

  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">Security Overview</h1>
        <span className="muted">Last updated: {new Date().toLocaleTimeString()}</span>
      </div>

      <div className="metrics-row">
        <MetricCard label="Critical Alerts" value={stats.alert_by_severity?.Critical ?? 0} color="red" sub="Requires action" />
        <MetricCard label="High Severity" value={stats.alert_by_severity?.High ?? 0} color="amber" sub="Under review" />
        <MetricCard label="Total Events" value={stats.total_logs ?? 0} sub="Ingested" />
        <MetricCard label="Active Sources" value={stats.active_sources ?? 0} color="green" sub="Reporting" />
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-title">Threat Activity by Category</div>
          {Object.keys(threatCats).length === 0
            ? <div className="empty-state">No threats detected yet. Ingest logs to start.</div>
            : Object.entries(threatCats).sort((a, b) => b[1] - a[1]).map(([cat, count]) => (
              <div key={cat} className="threat-row">
                <span className="threat-label">{cat}</span>
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${Math.round(count / maxCat * 100)}%`, background: catColors[cat] || '#888' }} />
                </div>
                <span className="threat-count" style={{ color: catColors[cat] || '#888' }}>{count}</span>
              </div>
            ))
          }
        </div>

        <div className="card">
          <div className="card-title">Top Offending IPs</div>
          {topIPs.length === 0
            ? <div className="empty-state">No IPs extracted yet.</div>
            : <div className="ip-grid">
                {topIPs.map(([ip, count]) => (
                  <div key={ip} className="ip-item">
                    <span className="ip-addr">{ip}</span>
                    <span className="ip-count">{count}</span>
                  </div>
                ))}
              </div>
          }
        </div>
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-title">Recent Alerts</div>
          {alerts.length === 0
            ? <div className="empty-state">No alerts yet. Ingest logs to begin.</div>
            : alerts.slice(0, 6).map(a => (
              <div key={a.id} className="alert-row" onClick={() => navigate('alerts')}>
                <div className={`alert-dot dot-${a.severity?.toLowerCase()}`} />
                <div>
                  <div className="alert-name">{a.rule}</div>
                  <div className="alert-sub">{a.source} · {a.ts}</div>
                </div>
                <Badge severity={a.severity} />
              </div>
            ))
          }
        </div>

        <div className="card">
          <div className="card-title">Event Distribution</div>
          {[['Critical', dist.CRIT || 0, '#E24B4A'], ['Warning', dist.WARN || 0, '#EF9F27'], ['Info', dist.INFO || 0, '#639922']].map(([label, count, color]) => {
            const total = (stats.total_logs || 1)
            return (
              <div key={label} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={{ fontSize: 12 }}>{label}</span>
                  <span style={{ fontSize: 12, fontWeight: 500 }}>{count}</span>
                </div>
                <div className="bar-track">
                  <div className="bar-fill" style={{ width: `${Math.round(count / total * 100)}%`, background: color }} />
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="card">
        <div className="card-title">Open Incidents</div>
        <div className="incidents-mini">
          {incidents.filter(i => i.status !== 'Resolved').slice(0, 4).map(i => (
            <div key={i.id} className="incident-mini-row" onClick={() => navigate('incidents')}>
              <span className="mono-id">{i.id}</span>
              <span style={{ flex: 1 }}>{i.title}</span>
              <Badge severity={i.severity} />
              <Badge status={i.status} />
            </div>
          ))}
          {incidents.filter(i => i.status !== 'Resolved').length === 0 &&
            <div className="empty-state">No open incidents.</div>
          }
        </div>
      </div>
    </div>
  )
}
