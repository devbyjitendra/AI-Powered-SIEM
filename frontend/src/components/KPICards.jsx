import React from 'react'
import { 
  Database, 
  Bell, 
  ShieldAlert, 
  Target, 
  TrendingUp, 
  TrendingDown 
} from 'lucide-react'

// Simulated sparkline data points
const SPARKLINE_DATA = {
  events: [30, 40, 35, 50, 49, 60, 70, 65, 80],
  alerts: [20, 25, 45, 30, 35, 55, 40, 50, 65],
  incidents: [10, 15, 8, 12, 20, 15, 25, 22, 30],
  critical: [5, 3, 6, 4, 8, 7, 12, 10, 15]
}

// Helper to compile points array into an SVG path
const getSvgPath = (points, width, height) => {
  if (points.length === 0) return ''
  const maxVal = Math.max(...points)
  const minVal = Math.min(...points)
  const range = maxVal - minVal || 1
  
  const stepX = width / (points.length - 1)
  
  return points.map((p, index) => {
    const x = index * stepX
    const y = height - ((p - minVal) / range) * (height - 8) - 4
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')
}

function KPICard({ title, value, trend, isPositive, icon: IconComponent, data, strokeColor, glowColor }) {
  const path = getSvgPath(data, 120, 40)
  
  return (
    <div className="kpi-card glass-panel">
      <div className="kpi-card-header">
        <div className="kpi-icon-wrapper" style={{ backgroundColor: `rgba(${strokeColor}, 0.1)`, color: `rgb(${strokeColor})` }}>
          <IconComponent size={20} />
        </div>
        <div className="kpi-trend" style={{ color: isPositive ? 'hsl(var(--sev-low))' : 'hsl(var(--sev-critical))' }}>
          {isPositive ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
          <span>{trend}</span>
        </div>
      </div>
      
      <div className="kpi-card-body">
        <div className="kpi-stat-info">
          <span className="kpi-title">{title}</span>
          <h3 className="kpi-value">{value}</h3>
        </div>
        
        {/* SVG Sparkline */}
        <div className="kpi-sparkline">
          <svg width="120" height="40">
            <defs>
              <linearGradient id={`glow-${title}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={`rgb(${strokeColor})`} stopOpacity="0.3"/>
                <stop offset="100%" stopColor={`rgb(${strokeColor})`} stopOpacity="0"/>
              </linearGradient>
            </defs>
            {/* Area under the line */}
            <path
              d={`${path} L 120 40 L 0 40 Z`}
              fill={`url(#glow-${title})`}
            />
            {/* Stroke Line */}
            <path
              d={path}
              fill="none"
              stroke={`rgb(${strokeColor})`}
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ filter: `drop-shadow(0px 2px 4px rgba(${strokeColor}, 0.5))` }}
            />
          </svg>
        </div>
      </div>
    </div>
  )
}

function KPICards() {
  return (
    <div className="kpi-grid">
      <KPICard
        title="Total Events"
        value="12.4M"
        trend="18.6% vs yesterday"
        isPositive={true}
        icon={Database}
        data={SPARKLINE_DATA.events}
        strokeColor="47, 128, 237" // Blue
      />
      <KPICard
        title="Alerts"
        value="1,248"
        trend="23.5% vs yesterday"
        isPositive={false} // Shown as concern (upward trend in alerts is negative for network, but matches mockup color)
        icon={Bell}
        data={SPARKLINE_DATA.alerts}
        strokeColor="239, 68, 68" // Red
      />
      <KPICard
        title="Incidents"
        value="45"
        trend="12.5% vs yesterday"
        isPositive={true}
        icon={ShieldAlert}
        data={SPARKLINE_DATA.incidents}
        strokeColor="245, 158, 11" // Orange/Amber
      />
      <KPICard
        title="Critical Incidents"
        value="7"
        trend="75% vs yesterday"
        isPositive={false} // Red warning
        icon={Target}
        data={SPARKLINE_DATA.critical}
        strokeColor="239, 68, 68" // Red
      />
    </div>
  )
}

export default KPICards
