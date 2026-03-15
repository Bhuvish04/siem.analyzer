// src/components/MetricCard.jsx
export default function MetricCard({ label, value, color, sub }) {
  const colorMap = { red: '#E24B4A', amber: '#BA7517', green: '#3B6D11' }
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value" style={color ? { color: colorMap[color] } : {}}>{value}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  )
}
