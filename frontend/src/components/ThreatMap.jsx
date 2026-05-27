import React from 'react'

// Attacker data matching mockup exactly
const TOP_THREAT_SOURCES = [
  { ip: '185.199.108.153', country: 'United States', flag: '🇺🇸', events: '45,231', risk: 'High', color: 'var(--sev-critical)' },
  { ip: '203.0.113.45', country: 'Netherlands', flag: '🇳🇱', events: '32,987', risk: 'High', color: 'var(--sev-critical)' },
  { ip: '198.51.100.23', country: 'Russia', flag: '🇷🇺', events: '23,456', risk: 'Medium', color: 'var(--sev-high)' },
  { ip: '103.21.244.0', country: 'Singapore', flag: '🇸🇬', events: '16,789', risk: 'Medium', color: 'var(--sev-medium)' },
  { ip: '45.77.32.11', country: 'Brazil', flag: '🇧🇷', events: '12,345', risk: 'Low', color: 'var(--sev-low)' },
]

// Geographical hot spots on our custom SVG coordinate grid
const MAP_HOT_SPOTS = [
  { name: 'US East', cx: 120, cy: 90, risk: 'High', color: 'hsl(var(--sev-critical))' },
  { name: 'Netherlands', cx: 280, cy: 75, risk: 'High', color: 'hsl(var(--sev-critical))' },
  { name: 'Russia', cx: 350, cy: 68, risk: 'Medium', color: 'hsl(var(--sev-high))' },
  { name: 'Singapore', cx: 400, cy: 135, risk: 'Medium', color: 'hsl(var(--sev-medium))' },
  { name: 'Brazil', cx: 195, cy: 165, risk: 'Low', color: 'hsl(var(--sev-low))' }
]

function ThreatMap() {
  return (
    <div className="maps-grid-row">
      
      {/* World Map - Threat Activity Card */}
      <div className="map-card glass-panel threat-map-container">
        <div className="card-title-header">
          <h3>World Map – Threat Activity</h3>
          <div className="map-legend">
            <span className="legend-indicator"><span className="dot" style={{ backgroundColor: 'hsl(var(--sev-critical))' }}></span>High</span>
            <span className="legend-indicator"><span className="dot" style={{ backgroundColor: 'hsl(var(--sev-high))' }}></span>Medium</span>
            <span className="legend-indicator"><span className="dot" style={{ backgroundColor: 'hsl(var(--sev-low))' }}></span>Low</span>
          </div>
        </div>
        
        <div className="svg-map-wrapper">
          <svg viewBox="0 0 500 240" className="futuristic-svg-map">
            {/* Grid Lines for cyber scan look */}
            <defs>
              <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(34, 42, 76, 0.15)" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />

            {/* Stylized vector contours representing world continents */}
            <path 
              d="M 50 80 Q 70 60 90 70 T 130 90 T 150 110 L 140 140 Q 110 150 80 130 Z M 160 140 L 195 190 Q 200 210 185 220 L 170 210 Z M 250 60 Q 280 50 310 60 T 360 80 L 370 120 Q 330 150 280 140 Z M 350 140 Q 380 120 420 135 T 450 160 L 430 190 Z" 
              fill="rgba(34, 42, 76, 0.2)" 
              stroke="rgba(34, 42, 76, 0.4)" 
              strokeWidth="1.5" 
            />

            {/* Pulsing Target Rings & Dots */}
            {MAP_HOT_SPOTS.map((spot, i) => (
              <g key={spot.name}>
                {/* Glowing Pulsing Ring */}
                <circle 
                  cx={spot.cx} 
                  cy={spot.cy} 
                  r="6" 
                  fill="none" 
                  stroke={spot.color} 
                  strokeWidth="1.5"
                  className="pulsing-radar-ring"
                  style={{ animationDelay: `${i * 0.4}s` }}
                />
                {/* Central Solid Point */}
                <circle 
                  cx={spot.cx} 
                  cy={spot.cy} 
                  r="3.5" 
                  fill={spot.color} 
                  style={{ filter: `drop-shadow(0 0 4px ${spot.color})` }}
                />
              </g>
            ))}
          </svg>
        </div>
      </div>

      {/* Top Threat Sources List Card */}
      <div className="sources-card glass-panel threat-sources-container">
        <div className="card-title-header">
          <h3>Top Threat Sources</h3>
          <button className="view-all-link">View all</button>
        </div>
        
        <div className="table-responsive">
          <table className="sources-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Country</th>
                <th>Events</th>
                <th style={{ textAlign: 'right' }}>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {TOP_THREAT_SOURCES.map((source) => (
                <tr key={source.ip}>
                  <td className="ip-cell">{source.ip}</td>
                  <td className="country-cell">
                    <span className="flag-emoji">{source.flag}</span>
                    <span>{source.country}</span>
                  </td>
                  <td className="event-count-cell">{source.events}</td>
                  <td style={{ textAlign: 'right' }}>
                    <span className="risk-badge" style={{ backgroundColor: `rgba(${source.color === 'var(--sev-critical)' ? '239, 68, 68' : source.color === 'var(--sev-high)' ? '249, 115, 22' : source.color === 'var(--sev-medium)' ? '245, 158, 11' : '16, 185, 129'}, 0.15)`, color: source.color }}>
                      {source.risk}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  )
}

export default ThreatMap
