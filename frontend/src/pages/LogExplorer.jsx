// src/pages/LogExplorer.jsx
import { useState, useEffect } from 'react'
import { useStore } from '../store'
import Badge from '../components/Badge'

const levelBg = { CRIT: '#FCEBEB', WARN: '#FAEEDA', INFO: '#EAF3DE' }
const levelColor = { CRIT: '#A32D2D', WARN: '#854F0B', INFO: '#3B6D11' }

export default function LogExplorer() {
  const { logs, fetchLogs } = useStore()
  const [search, setSearch] = useState('')
  const [source, setSource] = useState('')
  const [level, setLevel] = useState('')
  const [sources, setSources] = useState([])

  useEffect(() => {
    fetchLogs({})
    fetch('http://localhost:8000/api/logs?limit=1000')
      .then(r => r.json())
      .then(data => {
        const uniq = [...new Set(data.map(l => l.source))]
        setSources(uniq)
      }).catch(() => {})
  }, [])

  const handleSearch = () => {
    const params = {}
    if (search) params.search = search
    if (source) params.source = source
    if (level) params.level = level
    fetchLogs(params)
  }

  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">Log Explorer</h1>
        <span className="muted">{logs.length} events shown</span>
      </div>

      <div className="card">
        <div className="toolbar">
          <input className="search-input" placeholder="Search logs…" value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()} />
          <select className="filter-sel" value={source} onChange={e => setSource(e.target.value)}>
            <option value="">All sources</option>
            {sources.map(s => <option key={s}>{s}</option>)}
          </select>
          <select className="filter-sel" value={level} onChange={e => setLevel(e.target.value)}>
            <option value="">All levels</option>
            <option>CRIT</option><option>WARN</option><option>INFO</option>
          </select>
          <button className="btn primary" onClick={handleSearch}>Search</button>
        </div>

        <div className="log-container">
          {logs.length === 0
            ? <div className="empty-state">No logs yet. Ingest logs first.</div>
            : logs.map(l => (
              <div key={l.id} className="log-row">
                <span className="log-ts">{l.ts}</span>
                <span className="badge" style={{ background: levelBg[l.level], color: levelColor[l.level], width: 42, textAlign: 'center', flexShrink: 0 }}>{l.level}</span>
                <span className="log-src">{l.source}</span>
                <span className="log-msg">{l.message}</span>
              </div>
            ))
          }
        </div>
      </div>
    </div>
  )
}
