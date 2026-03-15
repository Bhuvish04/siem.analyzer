// src/pages/Incidents.jsx
import { useState } from 'react'
import { useStore } from '../store'
import Badge from '../components/Badge'
import Modal from '../components/Modal'

export default function Incidents({ notify, navigate }) {
  const { incidents, createIncident, updateIncident, escalateAlert } = useStore()
  const [search, setSearch] = useState('')
  const [statusF, setStatusF] = useState('')
  const [sevF, setSevF] = useState('')
  const [selected, setSelected] = useState(null)
  const [newEntry, setNewEntry] = useState('')

  const filtered = incidents.filter(i =>
    (!search || i.title.toLowerCase().includes(search.toLowerCase()) || i.id.toLowerCase().includes(search.toLowerCase())) &&
    (!statusF || i.status === statusF) &&
    (!sevF || i.severity === sevF)
  )

  const handleCreate = async () => {
    const inc = await createIncident({ title: 'New Investigation', severity: 'Medium' })
    notify(`✓ Incident ${inc.id} created`)
  }

  const handleStatusChange = async (id, status) => {
    await updateIncident(id, { status })
    setSelected(s => s?.id === id ? { ...s, status } : s)
    notify('✓ Status updated')
  }

  const handleAddEntry = async () => {
    if (!newEntry.trim() || !selected) return
    const updated = await updateIncident(selected.id, { timeline_entry: newEntry })
    setSelected(updated)
    setNewEntry('')
    notify('✓ Timeline updated')
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">Incident Management</h1>
      </div>

      <div className="card">
        <div className="toolbar">
          <input className="search-input" placeholder="Search incidents…" value={search} onChange={e => setSearch(e.target.value)} />
          <select className="filter-sel" value={statusF} onChange={e => setStatusF(e.target.value)}>
            <option value="">All status</option>
            <option>Open</option><option>Investigating</option><option>Resolved</option>
          </select>
          <select className="filter-sel" value={sevF} onChange={e => setSevF(e.target.value)}>
            <option value="">All severity</option>
            <option>Critical</option><option>High</option><option>Medium</option>
          </select>
          <button className="btn primary" onClick={handleCreate}>+ New Incident</button>
        </div>

        <table className="data-table">
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Assigned</th><th>Created</th><th></th></tr></thead>
          <tbody>
            {filtered.map(i => (
              <tr key={i.id} onClick={() => setSelected(i)} style={{ cursor: 'pointer' }}>
                <td><span className="mono-id">{i.id}</span></td>
                <td>{i.title}</td>
                <td><Badge severity={i.severity} /></td>
                <td><Badge status={i.status} /></td>
                <td>{i.assigned}</td>
                <td className="muted">{i.created}</td>
                <td><button className="btn sm" onClick={e => { e.stopPropagation(); setSelected(i) }}>View</button></td>
              </tr>
            ))}
            {filtered.length === 0 && <tr><td colSpan={7}><div className="empty-state">No incidents match.</div></td></tr>}
          </tbody>
        </table>
      </div>

      {selected && (
        <Modal title={`${selected.id} · ${selected.title}`} onClose={() => setSelected(null)}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <Badge severity={selected.severity} />
            <Badge status={selected.status} />
            {selected.mitre && <span className="pill">{selected.mitre}</span>}
          </div>
          {selected.description && <p style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 12 }}>{selected.description}</p>}
          <div className="field-grid">
            <div><div className="field-label">Affected</div><div className="field-val">{selected.affected || 'N/A'}</div></div>
            <div><div className="field-label">Assigned</div><div className="field-val">{selected.assigned}</div></div>
            <div><div className="field-label">IOCs</div><div className="field-val mono">{selected.ioc || 'None'}</div></div>
            <div><div className="field-label">Created</div><div className="field-val">{selected.created}</div></div>
          </div>
          <div className="field-label" style={{ margin: '12px 0 8px' }}>Timeline</div>
          <div className="timeline">
            {(selected.timeline || []).map((t, i) => (
              <div key={i} className="tl-item">
                <div className="tl-dot" />
                <div className="tl-time">{t.time}</div>
                <div className="tl-text">{t.text}</div>
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <input className="search-input" style={{ flex: 1 }} placeholder="Add timeline entry…" value={newEntry} onChange={e => setNewEntry(e.target.value)} />
            <button className="btn" onClick={handleAddEntry}>Add</button>
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <select className="filter-sel" value={selected.status} onChange={e => handleStatusChange(selected.id, e.target.value)}>
              <option>Open</option><option>Investigating</option><option>Resolved</option>
            </select>
            <button className="btn primary" onClick={() => { notify('✓ Incident saved'); setSelected(null) }}>Close</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
