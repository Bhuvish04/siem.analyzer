// src/pages/Alerts.jsx
import { useState } from 'react'
import { useStore } from '../store'
import Badge from '../components/Badge'
import Modal from '../components/Modal'

export default function Alerts({ notify, navigate }) {
  const { alerts, clearAlerts, deleteAlert, escalateAlert } = useStore()
  const [search, setSearch] = useState('')
  const [sevF, setSevF] = useState('')
  const [selected, setSelected] = useState(null)

  const filtered = alerts.filter(a =>
    (!search || a.rule?.toLowerCase().includes(search.toLowerCase()) || a.message?.toLowerCase().includes(search.toLowerCase())) &&
    (!sevF || a.severity === sevF)
  )

  const handleEscalate = async (alertId) => {
    const inc = await escalateAlert(alertId)
    setSelected(null)
    notify(`🚨 Escalated to ${inc.id}`)
    navigate('incidents')
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">Alert Feed</h1>
        <span className="muted">{alerts.length} total</span>
      </div>

      <div className="card">
        <div className="toolbar">
          <input className="search-input" placeholder="Filter alerts…" value={search} onChange={e => setSearch(e.target.value)} />
          <select className="filter-sel" value={sevF} onChange={e => setSevF(e.target.value)}>
            <option value="">All severities</option>
            <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
          </select>
          <button className="btn" onClick={() => { clearAlerts(); notify('✓ All alerts cleared') }}>Clear all</button>
        </div>

        <div className="alert-feed">
          {filtered.length === 0
            ? <div className="empty-state">No alerts match. Ingest logs first.</div>
            : filtered.map(a => (
              <div key={a.id} className="alert-feed-row" onClick={() => setSelected(a)}>
                <div className={`alert-dot dot-${a.severity?.toLowerCase()}`} />
                <div style={{ flex: 1 }}>
                  <div className="alert-name">{a.rule}</div>
                  <div className="alert-sub">{a.message}</div>
                </div>
                <Badge severity={a.severity} />
                <span className="muted" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{a.source}</span>
                <span className="muted" style={{ fontSize: 10, whiteSpace: 'nowrap' }}>{a.ts}</span>
                <button className="btn sm danger" onClick={e => { e.stopPropagation(); deleteAlert(a.id) }}>✕</button>
              </div>
            ))
          }
        </div>
      </div>

      {selected && (
        <Modal title={`Alert: ${selected.rule}`} onClose={() => setSelected(null)}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <Badge severity={selected.severity} />
            <span className="pill">{selected.category}</span>
          </div>
          <div className="field-label">Message</div>
          <p style={{ fontSize: 12, marginBottom: 10 }}>{selected.message}</p>
          <div className="field-label">Raw Log</div>
          <pre className="raw-log">{selected.raw}</pre>
          <div className="field-grid" style={{ marginTop: 10 }}>
            <div><div className="field-label">Source</div><div className="field-val">{selected.source}</div></div>
            <div><div className="field-label">Timestamp</div><div className="field-val">{selected.ts}</div></div>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <button className="btn primary" onClick={() => handleEscalate(selected.id)}>Escalate to Incident</button>
            <button className="btn" onClick={() => setSelected(null)}>Dismiss</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
