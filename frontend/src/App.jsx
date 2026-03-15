// SIEM Log Analyzer - React Frontend
// src/App.jsx

import { useState, useEffect, useRef } from 'react'
import Dashboard from './pages/Dashboard'
import Incidents from './pages/Incidents'
import Alerts from './pages/Alerts'
import LogExplorer from './pages/LogExplorer'
import IngestLogs from './pages/IngestLogs'
import Rules from './pages/Rules'
import Sources from './pages/Sources'
import Notification from './components/Notification'
import { useStore } from './store'
import './App.css'

const NAV = [
  { section: 'Monitor' },
  { id: 'dashboard', label: 'Dashboard', icon: '◼' },
  { id: 'incidents', label: 'Incidents', icon: '⚠' },
  { id: 'alerts', label: 'Alerts', icon: '🔔' },
  { section: 'Analysis' },
  { id: 'logs', label: 'Log Explorer', icon: '≡' },
  { id: 'ingest', label: 'Ingest Logs', icon: '↓' },
  { section: 'Config' },
  { id: 'rules', label: 'Detection Rules', icon: '⚙' },
  { id: 'sources', label: 'Log Sources', icon: '◎' },
]

const PAGES = { dashboard: Dashboard, incidents: Incidents, alerts: Alerts, logs: LogExplorer, ingest: IngestLogs, rules: Rules, sources: Sources }

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [notification, setNotification] = useState(null)
  const { stats, alerts, refreshAll, wsConnected, setWsConnected } = useStore()
  const wsRef = useRef(null)

  // WebSocket for live updates
  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket('ws://localhost:8000/ws')
      wsRef.current = ws

      ws.onopen = () => setWsConnected(true)
      ws.onclose = () => {
        setWsConnected(false)
        setTimeout(connect, 3000) // reconnect
      }
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data)
        if (msg.type === 'metrics') {
          useStore.getState().setStats(msg.data)
        }
        if (msg.type === 'ingest' && msg.alerts?.length) {
          notify(`🚨 ${msg.alerts.length} new alert(s) detected!`)
          refreshAll()
        }
        if (msg.type === 'live_event' && msg.alerts?.length) {
          notify(`🔔 ${msg.alerts[0].rule}`)
          refreshAll()
        }
        if (msg.type === 'incident_created') {
          notify(`🚨 Incident ${msg.incident.id} created`)
          refreshAll()
        }
      }
    }
    connect()
    return () => wsRef.current?.close()
  }, [])

  useEffect(() => { refreshAll() }, [])

  const notify = (msg) => {
    setNotification(msg)
    setTimeout(() => setNotification(null), 3500)
  }

  const Page = PAGES[page] || Dashboard

  return (
    <div className="app">
      <div className="topbar">
        <div className="topbar-logo">SIEM<span className="accent">·</span>Analyzer</div>
        <span className="pill">v2.1.0</span>
        <div className="topbar-right">
          <div className={`status-indicator ${wsConnected ? 'connected' : 'disconnected'}`}>
            <div className="status-dot" />
            {wsConnected ? 'Live monitoring' : 'Reconnecting…'}
          </div>
          <div className={`alert-badge ${alerts.length > 0 ? 'has-alerts' : ''}`}>
            {alerts.length} alert{alerts.length !== 1 ? 's' : ''}
          </div>
        </div>
      </div>

      <div className="sidebar">
        {NAV.map((item, i) =>
          item.section
            ? <div key={i} className="nav-section">{item.section}</div>
            : <div key={item.id} className={`nav-item ${page === item.id ? 'active' : ''}`} onClick={() => setPage(item.id)}>
                <span className="nav-icon">{item.icon}</span>
                {item.label}
              </div>
        )}
        <div className="sidebar-footer">
          <div className="sidebar-footer-label">Events today</div>
          <div className="sidebar-footer-value">{stats.total_logs ?? 0}</div>
        </div>
      </div>

      <div className="main">
        <Page notify={notify} navigate={setPage} />
      </div>

      {notification && <Notification message={notification} />}
    </div>
  )
}
