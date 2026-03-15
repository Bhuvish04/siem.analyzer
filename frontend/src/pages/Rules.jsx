// src/pages/Rules.jsx
import { useState } from 'react'
import { useStore } from '../store'
import Badge from '../components/Badge'
import Modal from '../components/Modal'

export default function Rules({ notify }) {
  const { rules, toggleRule, addRule, deleteRule } = useStore()
  const [catF, setCatF] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [form, setForm] = useState({ name: '', pattern: '', severity: 'Medium', category: 'Authentication', desc: '' })

  const filtered = catF ? rules.filter(r => r.category === catF) : rules

  const handleSave = async () => {
    if (!form.name || !form.pattern) { notify('⚠ Name and pattern required'); return }
    await addRule(form)
    setShowNew(false)
    setForm({ name: '', pattern: '', severity: 'Medium', category: 'Authentication', desc: '' })
    notify(`✓ Rule "${form.name}" added`)
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">Detection Rules</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="filter-sel" value={catF} onChange={e => setCatF(e.target.value)}>
            <option value="">All categories</option>
            <option>Authentication</option><option>Network</option><option>Malware</option>
            <option>Exfiltration</option><option>Reconnaissance</option>
          </select>
          <button className="btn primary" onClick={() => setShowNew(true)}>+ Add Rule</button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {filtered.map(r => (
          <div key={r.id} className="rule-card">
            <div className={`rule-toggle ${r.enabled ? 'on' : ''}`} onClick={() => toggleRule(r.id)} title={r.enabled ? 'Disable' : 'Enable'} />
            <div className="rule-body">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                <span className="rule-name">{r.name}</span>
                <Badge severity={r.severity} />
                <span className="pill">{r.category}</span>
                {r.hits > 0 && <span className="pill danger">{r.hits} hit{r.hits > 1 ? 's' : ''}</span>}
                {!r.enabled && <span className="pill muted">disabled</span>}
              </div>
              <div className="rule-desc">{r.desc}</div>
              <code className="rule-pattern">{r.pattern}</code>
            </div>
            <button className="btn sm danger" onClick={() => { deleteRule(r.id); notify('✓ Rule deleted') }} title="Delete rule">✕</button>
          </div>
        ))}
        {filtered.length === 0 && <div className="empty-state">No rules found.</div>}
      </div>

      {showNew && (
        <Modal title="Add Detection Rule" onClose={() => setShowNew(false)}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label className="field-label">Rule Name</label>
              <input className="search-input" style={{ width: '100%' }} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Brute Force SSH" />
            </div>
            <div>
              <label className="field-label">Pattern (regex)</label>
              <input className="search-input mono" style={{ width: '100%' }} value={form.pattern} onChange={e => setForm(f => ({ ...f, pattern: e.target.value }))} placeholder="e.g. failed.password|invalid.user" />
            </div>
            <div>
              <label className="field-label">Severity</label>
              <select className="filter-sel" style={{ width: '100%' }} value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
              </select>
            </div>
            <div>
              <label className="field-label">Category</label>
              <select className="filter-sel" style={{ width: '100%' }} value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value }))}>
                <option>Authentication</option><option>Network</option><option>Malware</option><option>Exfiltration</option><option>Reconnaissance</option>
              </select>
            </div>
            <div>
              <label className="field-label">Description</label>
              <input className="search-input" style={{ width: '100%' }} value={form.desc} onChange={e => setForm(f => ({ ...f, desc: e.target.value }))} placeholder="What does this rule detect?" />
            </div>
            <button className="btn primary" onClick={handleSave}>Save Rule</button>
          </div>
        </Modal>
      )}
    </div>
  )
}
