// src/store.js - Zustand global state
import { create } from 'zustand'

const API = 'http://localhost:8000/api'

export const useStore = create((set, get) => ({
  stats: {},
  logs: [],
  alerts: [],
  incidents: [],
  rules: [],
  sources: [],
  wsConnected: false,

  setStats: (stats) => set({ stats }),
  setWsConnected: (v) => set({ wsConnected: v }),

  refreshAll: async () => {
    const [stats, alerts, incidents, rules, sources] = await Promise.all([
      fetch(`${API}/stats`).then(r => r.json()).catch(() => ({})),
      fetch(`${API}/alerts`).then(r => r.json()).catch(() => []),
      fetch(`${API}/incidents`).then(r => r.json()).catch(() => []),
      fetch(`${API}/rules`).then(r => r.json()).catch(() => []),
      fetch(`${API}/sources`).then(r => r.json()).catch(() => []),
    ])
    set({ stats, alerts, incidents, rules, sources })
  },

  fetchLogs: async (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    const logs = await fetch(`${API}/logs?${qs}`).then(r => r.json()).catch(() => [])
    set({ logs })
    return logs
  },

  ingestLogs: async (raw) => {
    const res = await fetch(`${API}/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw }),
    }).then(r => r.json())
    get().refreshAll()
    return res
  },

  ingestFile: async (file) => {
    const fd = new FormData()
    fd.append('file', file)
    const res = await fetch(`${API}/ingest/file`, { method: 'POST', body: fd }).then(r => r.json())
    get().refreshAll()
    return res
  },

  clearAlerts: async () => {
    await fetch(`${API}/alerts`, { method: 'DELETE' })
    set({ alerts: [] })
  },

  deleteAlert: async (id) => {
    await fetch(`${API}/alerts/${id}`, { method: 'DELETE' })
    set(s => ({ alerts: s.alerts.filter(a => a.id !== id) }))
  },

  createIncident: async (data) => {
    const inc = await fetch(`${API}/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }).then(r => r.json())
    set(s => ({ incidents: [inc, ...s.incidents] }))
    return inc
  },

  updateIncident: async (id, data) => {
    const inc = await fetch(`${API}/incidents/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }).then(r => r.json())
    set(s => ({ incidents: s.incidents.map(i => i.id === id ? inc : i) }))
    return inc
  },

  escalateAlert: async (alertId) => {
    const inc = await fetch(`${API}/incidents/from-alert/${alertId}`, { method: 'POST' }).then(r => r.json())
    set(s => ({ incidents: [inc, ...s.incidents] }))
    get().refreshAll()
    return inc
  },

  toggleRule: async (id) => {
    const rule = await fetch(`${API}/rules/${id}/toggle`, { method: 'PATCH' }).then(r => r.json())
    set(s => ({ rules: s.rules.map(r => r.id === id ? rule : r) }))
  },

  addRule: async (data) => {
    const rule = await fetch(`${API}/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }).then(r => r.json())
    set(s => ({ rules: [...s.rules, rule] }))
    return rule
  },

  deleteRule: async (id) => {
    await fetch(`${API}/rules/${id}`, { method: 'DELETE' })
    set(s => ({ rules: s.rules.filter(r => r.id !== id) }))
  },

  simulate: async () => {
    await fetch(`${API}/simulate`, { method: 'POST' })
  },
}))
