import React, { useEffect, useState } from 'react'
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  Area,
  AreaChart
} from 'recharts'
import { getDashboardStats } from '../services/api'

// Timeline chart data: 00:00 to 24:00
const TIMELINE_DATA = [
  { time: '00:00', events: 350000 },
  { time: '02:00', events: 500000 },
  { time: '04:00', events: 450000 },
  { time: '06:00', events: 700000 },
  { time: '08:00', events: 1100000 },
  { time: '10:00', events: 900000 },
  { time: '12:00', events: 1300000 },
  { time: '14:00', events: 1200000 },
  { time: '16:00', events: 1050000 },
  { time: '18:00', events: 1400000 },
  { time: '20:00', events: 1150000 },
  { time: '22:00', events: 950000 },
  { time: '24:00', events: 800000 },
]

// Category donut data
const CATEGORIES_DATA = [
  { name: 'Authentication', value: 432, percent: '34.6%', color: '#2f80ed' }, // Blue
  { name: 'Malware', value: 312, percent: '25.0%', color: '#ef4444' },        // Red
  { name: 'Suspicious Activity', value: 234, percent: '18.8%', color: '#f59e0b' }, // Amber
  { name: 'Policy Violation', value: 156, percent: '12.5%', color: '#a061ff' },   // Purple
  { name: 'System', value: 114, percent: '9.1%', color: '#10b981' },         // Green
]

function SecurityCharts({ setActiveTab, stats, statsInterval, setStatsInterval }) {
  const [selectedSource, setSelectedSource] = useState('All Sources')

  // Format numbers to short strings (e.g. 1.2M or 500K)
  const formatYAxis = (value) => {
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`
    if (value >= 1000) return `${(value / 1000).toFixed(0)}K`
    return value
  }

  const timelineData = stats && stats.timeline ? stats.timeline : []
  let activeTimeline = timelineData
  if (selectedSource === 'Authentication Only') {
    activeTimeline = stats && stats.timeline_auth ? stats.timeline_auth : []
  } else if (selectedSource === 'Firewall Logs') {
    activeTimeline = stats && stats.timeline_firewall ? stats.timeline_firewall : []
  }

  let categoriesData = [
    { name: 'Authentication', value: 0, percent: '0%', color: '#2f80ed' },
    { name: 'Malware', value: 0, percent: '0%', color: '#ef4444' },
    { name: 'Suspicious Activity', value: 0, percent: '0%', color: '#f59e0b' },
    { name: 'Policy Violation', value: 0, percent: '0%', color: '#a061ff' },
    { name: 'System', value: 0, percent: '0%', color: '#10b981' },
  ]
  let totalLabel = "0"

  if (stats) {
    const authVal = stats.categories.Authentication || 0
    const webVal = stats.categories["Web Application"] || 0
    const sysVal = stats.categories.System || 0
    const malVal = stats.categories.Malware || 0
    const polVal = stats.categories["Policy Violation"] || 0
    const total = authVal + webVal + sysVal + malVal + polVal || 1
    
    categoriesData = [
      { name: 'Authentication', value: authVal, percent: `${((authVal / total) * 100).toFixed(1)}%`, color: '#2f80ed' },
      { name: 'Malware', value: malVal, percent: `${((malVal / total) * 100).toFixed(1)}%`, color: '#ef4444' },
      { name: 'Suspicious Activity', value: webVal, percent: `${((webVal / total) * 100).toFixed(1)}%`, color: '#f59e0b' },
      { name: 'Policy Violation', value: polVal, percent: `${((polVal / total) * 100).toFixed(1)}%`, color: '#a061ff' },
      { name: 'System', value: sysVal, percent: `${((sysVal / total) * 100).toFixed(1)}%`, color: '#10b981' },
    ]
    totalLabel = (authVal + webVal + sysVal + malVal + polVal).toLocaleString()
  }

  return (
    <div className="charts-grid-row">
      
      {/* Events Over Time Line Chart */}
      <div className="chart-container glass-panel events-chart-card">
        <div className="chart-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          <h3>Events Over Time</h3>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <div className="chart-select-wrapper">
              <select 
                className="chart-select" 
                value={selectedSource}
                onChange={(e) => setSelectedSource(e.target.value)}
              >
                <option>All Sources</option>
                <option>Authentication Only</option>
                <option>Firewall Logs</option>
              </select>
            </div>
            <div className="chart-select-wrapper">
              <select 
                className="chart-select" 
                value={statsInterval || '5m'}
                onChange={(e) => setStatsInterval && setStatsInterval(e.target.value)}
                style={{ minWidth: '95px' }}
              >
                <option value="5m">5 Min</option>
                <option value="15m">15 Min</option>
                <option value="30m">30 Min</option>
                <option value="1h">1 Hour</option>
              </select>
            </div>
          </div>
        </div>
        
        <div className="chart-body" style={{ width: '100%', height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={activeTimeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="eventGlow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2f80ed" stopOpacity={0.25}/>
                  <stop offset="95%" stopColor="#2f80ed" stopOpacity={0.0}/>
                </linearGradient>
                <linearGradient id="alertGlow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25}/>
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0}/>
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(34, 42, 76, 0.2)" strokeDasharray="3 3" vertical={false} />
              <XAxis 
                dataKey="time" 
                stroke="hsl(var(--text-muted))" 
                fontSize={10}
                tickLine={false}
                axisLine={false}
              />
              <YAxis 
                tickFormatter={formatYAxis}
                stroke="hsl(var(--text-muted))" 
                fontSize={10}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--bg-card))', 
                  borderColor: 'hsl(var(--border-color))',
                  borderRadius: '8px',
                  color: '#fff',
                  fontSize: '12px'
                }} 
              />
              <Area 
                type="monotone" 
                dataKey="events" 
                name="Security Events"
                stroke="#2f80ed" 
                strokeWidth={2}
                fillOpacity={1} 
                fill="url(#eventGlow)" 
              />
              <Area 
                type="monotone" 
                dataKey="alerts" 
                name="Triggered Alerts"
                stroke="#ef4444" 
                strokeWidth={2}
                fillOpacity={1} 
                fill="url(#alertGlow)" 
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Alert Categories Donut Chart */}
      <div className="chart-container glass-panel donut-chart-card">
        <div className="chart-header">
          <h3>Top Alert Categories</h3>
          <button className="view-all-link" onClick={() => setActiveTab && setActiveTab('Alerts')}>View all</button>
        </div>

        <div className="donut-chart-wrapper">
          {/* Donut graphic */}
          <div className="donut-graphic-container">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={categoriesData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {categoriesData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            {/* Centered Total Counter */}
            <div className="donut-center-label">
              <span className="donut-total-val">{totalLabel}</span>
              <span className="donut-total-lbl">Total</span>
            </div>
          </div>

          {/* Detailed Legend List */}
          <div className="donut-legend-container">
            <ul className="donut-legend-list">
              {categoriesData.map((category) => (
                <li key={category.name} className="donut-legend-item">
                  <div className="legend-item-left">
                    <span className="legend-color-dot" style={{ backgroundColor: category.color }}></span>
                    <span className="legend-name">{category.name}</span>
                  </div>
                  <span className="legend-value">{category.value} <span className="legend-pct">({category.percent})</span></span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      
    </div>
  )
}

export default SecurityCharts
