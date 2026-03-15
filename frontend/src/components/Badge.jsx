// src/components/Badge.jsx
export default function Badge({ severity, status }) {
  const val = severity || status
  const cls = val?.toLowerCase().replace(' ', '-') || 'info'
  return <span className={`badge ${cls}`}>{val}</span>
}

// src/components/MetricCard.jsx (exported separately below)
// src/components/Modal.jsx
// src/components/Notification.jsx
