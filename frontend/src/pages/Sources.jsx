// src/pages/Sources.jsx
import { useStore } from '../store'
import Badge from '../components/Badge'

export default function Sources() {
  const { sources } = useStore()

  return (
    <div className="page-content">
      <div className="page-header">
        <h1 className="page-title">Log Sources</h1>
      </div>

      <div className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Source</th><th>Type</th><th>Status</th>
              <th>Events/min</th><th>Last Event</th><th>Total Events</th>
            </tr>
          </thead>
          <tbody>
            {sources.map(s => (
              <tr key={s.name}>
                <td style={{ fontWeight: 500 }}>{s.name}</td>
                <td>{s.type}</td>
                <td>
                  <span className={`badge ${s.status === 'active' ? 'green' : s.status === 'warning' ? 'amber' : 'red'}`}>
                    {s.status}
                  </span>
                </td>
                <td>{s.eps}/min</td>
                <td className="muted">{s.last}</td>
                <td>{s.total.toLocaleString()}</td>
              </tr>
            ))}
            {sources.length === 0 && (
              <tr><td colSpan={6}><div className="empty-state">No sources configured.</div></td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
