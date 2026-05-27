import React from 'react'
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

function SecurityCharts() {
  // Format numbers to short strings (e.g. 1.2M or 500K)
  const formatYAxis = (value) => {
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`
    if (value >= 1000) return `${(value / 1000).toFixed(0)}K`
    return value
  }

  return (
    <div className="charts-grid-row">
      
      {/* Events Over Time Line Chart */}
      <div className="chart-container glass-panel events-chart-card">
        <div className="chart-header">
          <h3>Events Over Time</h3>
          <div className="chart-select-wrapper">
            <select className="chart-select">
              <option>All Sources</option>
              <option>Authentication Only</option>
              <option>Firewall Logs</option>
            </select>
          </div>
        </div>
        
        <div className="chart-body" style={{ width: '100%', height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={TIMELINE_DATA} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="eventGlow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2f80ed" stopOpacity={0.25}/>
                  <stop offset="95%" stopColor="#2f80ed" stopOpacity={0.0}/>
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
                stroke="#2f80ed" 
                strokeWidth={2}
                fillOpacity={1} 
                fill="url(#eventGlow)" 
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Alert Categories Donut Chart */}
      <div className="chart-container glass-panel donut-chart-card">
        <div className="chart-header">
          <h3>Top Alert Categories</h3>
          <button className="view-all-link">View all</button>
        </div>

        <div className="donut-chart-wrapper">
          {/* Donut graphic */}
          <div className="donut-graphic-container">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={CATEGORIES_DATA}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {CATEGORIES_DATA.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            {/* Centered Total Counter */}
            <div className="donut-center-label">
              <span className="donut-total-val">1,248</span>
              <span className="donut-total-lbl">Total</span>
            </div>
          </div>

          {/* Detailed Legend List */}
          <div className="donut-legend-container">
            <ul className="donut-legend-list">
              {CATEGORIES_DATA.map((category) => (
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
