import React, { useEffect, useState } from 'react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from 'recharts'
import { Globe } from 'lucide-react'
import worldMap from './world.svg'
import { getDashboardStats, API_BASE_URL } from '../services/api'

const getFlagUrl = (countryName) => {
  const codes = {
    "United States": "us", "Canada": "ca", "Netherlands": "nl", "Russia": "ru", "Singapore": "sg",
    "Brazil": "br", "Germany": "de", "China": "cn", "India": "in", "United Kingdom": "gb",
    "France": "fr", "Japan": "jp", "Australia": "au", "Italy": "it", "Spain": "es",
    "South Korea": "kr", "Mexico": "mx", "South Africa": "za", "Switzerland": "ch", "Sweden": "se",
    "Norway": "no", "Poland": "pl", "Turkey": "tr", "Saudi Arabia": "sa", "Argentina": "ar",
    "Belgium": "be", "Austria": "at", "Denmark": "dk", "Finland": "fi", "Greece": "gr",
    "Ireland": "ie", "Israel": "il", "Portugal": "pt", "Thailand": "th", "United Arab Emirates": "ae",
    "Vietnam": "vn", "Egypt": "eg", "Nigeria": "ng", "Malaysia": "my", "Indonesia": "id",
    "Philippines": "ph", "New Zealand": "nz", "Colombia": "co", "Chile": "cl", "Peru": "pe",
    "Czech Republic": "cz", "Hungary": "hu", "Romania": "ro", "Ukraine": "ua", "Pakistan": "pk",
    "Bangladesh": "bd", "Iran": "ir", "Iraq": "iq", "Kenya": "ke", "Morocco": "ma",
    "Algeria": "dz", "Venezuela": "ve", "Ecuador": "ec", "Bolivia": "bo", "Paraguay": "py",
    "Uruguay": "uy", "Panama": "pa", "Costa Rica": "cr", "Honduras": "hn", "Guatemala": "gt",
    "El Salvador": "sv", "Nicaragua": "ni", "Cuba": "cu", "Jamaica": "jm", "Dominican Republic": "do",
    "Haiti": "ht", "Kazakhstan": "kz", "Uzbekistan": "uz", "Azerbaijan": "az", "Georgia": "ge", "Armenia": "am",
    "Jordan": "jo", "Lebanon": "lb", "Oman": "om", "Qatar": "qa", "Kuwait": "kw", "Bahrain": "bh", "Yemen": "ye",
    "Sri Lanka": "lk", "Nepal": "np", "Myanmar": "mm", "Cambodia": "kh", "Laos": "la", "Mongolia": "mn",
    "Luxembourg": "lu", "Bulgaria": "bg", "Croatia": "hr", "Slovakia": "sk", "Slovenia": "si", "Estonia": "ee",
    "Latvia": "lv", "Lithuania": "lt", "Cyprus": "cy", "Malta": "mt", "Monaco": "mc", "Andorra": "ad",
    "Liechtenstein": "li", "San Marino": "sm", "Ghana": "gh", "Senegal": "sn", "Cameroon": "cm", "Angola": "ao",
    "Ethiopia": "et", "Tanzania": "tz", "Uganda": "ug", "Zimbabwe": "zw", "Zambia": "zm", "Botswana": "bw",
    "Namibia": "na", "Madagascar": "mg", "Mauritius": "mu", "Tunisia": "tn", "Libya": "ly", "Sudan": "sd",
    "Ivory Coast": "ci", "Mali": "ml", "Guinea": "gn", "Sierra Leone": "sl", "Liberia": "lr", "Togo": "tg",
    "Benin": "bj", "Niger": "ne", "Chad": "td", "Eritrea": "er", "Djibouti": "dj", "Somalia": "so", "Rwanda": "rw",
    "Burundi": "bi", "Malawi": "mw", "Mozambique": "mz", "Eswatini": "sz", "Lesotho": "ls", "Fiji": "fj",
    "Papua New Guinea": "pg", "Solomon Islands": "sb", "Vanuatu": "vu", "Samoa": "ws", "Tonga": "to",
    "Kiribati": "ki", "Tuvalu": "tv", "Nauru": "nr", "Palau": "pw", "Micronesia": "fm", "Marshall Islands": "mh",
    "Bahamas": "bs", "Barbados": "bb", "Trinidad and Tobago": "tt", "Guyana": "gy", "Suriname": "sr",
    "Russian Federation": "ru"
  }
  const code = codes[countryName]
  if (code) {
    return `https://flagcdn.com/w40/${code}.png`
  }
  return null
}

const APT_GROUPS_DATA = [
  { name: 'Lazarus Group', attacks: 142, origin: 'North Korea', target: 'Crypto/Finance' },
  { name: 'APT28 (Fancy Bear)', attacks: 98, origin: 'Russia', target: 'Government' },
  { name: 'APT41 (Double Dragon)', attacks: 88, origin: 'China', target: 'Tech/Health' },
  { name: 'Cozy Bear (APT29)', attacks: 75, origin: 'Russia', target: 'NGOs/Gov' },
  { name: 'Sandworm', attacks: 54, origin: 'Russia', target: 'Infrastructure' }
]

function ThreatMap({ setActiveTab, stats }) {
  const [lastEventsCount, setLastEventsCount] = useState(0)
  const [mountTimestamp] = useState(() => Date.now())
  const [mapView, setMapView] = useState('events')

  // Post stats updates directly to the iframe for instant, silent silent-sync
  useEffect(() => {
    if (stats) {
      const iframe = document.getElementById('threat-map-iframe')
      if (iframe && iframe.contentWindow) {
        iframe.contentWindow.postMessage({
          type: 'siem-stats-update',
          stats: stats,
          mapView: mapView
        }, '*')
      }
    }
  }, [stats, mapView])

  const handleIframeLoad = () => {
    if (stats) {
      const iframe = document.getElementById('threat-map-iframe')
      if (iframe && iframe.contentWindow) {
        iframe.contentWindow.postMessage({
          type: 'siem-stats-update',
          stats: stats,
          mapView: mapView
        }, '*')
      }
    }
  }

  const threatSources = stats && stats.threat_sources ? stats.threat_sources : []
  const targetedPorts = stats && stats.targeted_ports ? stats.targeted_ports : []
  const maliciousIocs = stats && stats.malicious_iocs ? stats.malicious_iocs : []

  return (
    <div className="threat-intelligence-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

      {/* World Map - Threat Activity Card */}
      <div className="maps-grid-row">
        <div className="map-card glass-panel threat-map-container">
          <div className="card-title-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h3 style={{ margin: 0 }}>World Map – Threat Activity</h3>
              <span className="sync-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.72rem', color: 'hsl(var(--text-secondary))', backgroundColor: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: '12px' }}>
                <span className="sync-dot" style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#10b981', display: 'inline-block', animation: 'sync-pulse-breathing 1.5s infinite' }}></span>
                Live Sync
              </span>
            </div>
            <style>{`
              @keyframes sync-pulse-breathing {
                0% { transform: scale(0.85); opacity: 0.5; }
                50% { transform: scale(1.2); opacity: 1; }
                100% { transform: scale(0.85); opacity: 0.5; }
              }
            `}</style>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <div className="chart-select-wrapper">
                <select 
                  className="chart-select" 
                  value={mapView}
                  onChange={(e) => setMapView(e.target.value)}
                  style={{ minWidth: '150px', background: 'hsl(var(--bg-dark))', border: '1px solid hsl(var(--border-color))', borderRadius: '6px', color: 'hsl(var(--text-secondary))', padding: '4px 8px', fontSize: '0.8rem', outline: 'none', cursor: 'pointer' }}
                >
                  <option value="events">Threat Events Map</option>
                  <option value="alerts">Security Alerts Map</option>
                </select>
              </div>
              <div className="map-legend" style={{ display: 'flex', gap: '10px' }}>
                <span className="legend-indicator"><span className="dot" style={{ backgroundColor: 'hsl(var(--sev-critical))' }}></span>High</span>
                <span className="legend-indicator"><span className="dot" style={{ backgroundColor: 'hsl(var(--sev-high))' }}></span>Medium</span>
                <span className="legend-indicator"><span className="dot" style={{ backgroundColor: 'hsl(var(--sev-low))' }}></span>Low</span>
              </div>
            </div>
          </div>

          <div className="svg-map-wrapper" style={{ padding: '0', overflow: 'hidden', height: '260px' }}>
            <iframe
              id="threat-map-iframe"
              src={`${API_BASE_URL}/logs/map?mount=${mountTimestamp}`}
              title="Threat Map Feed"
              onLoad={handleIframeLoad}
              style={{
                width: '100%',
                height: '100%',
                border: 'none',
                backgroundColor: '#0f1322'
              }}
            />
          </div>
        </div>

        {/* Top Threat Sources List Card */}
        <div className="sources-card glass-panel threat-sources-container">
          <div className="card-title-header">
            <h3>Top Threat Sources</h3>
            <button className="view-all-link" onClick={() => setActiveTab && setActiveTab('Threat Intelligence')}>View all</button>
          </div>

          <div className="table-responsive" style={{ maxHeight: '280px', overflowY: 'auto' }}>
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
                {threatSources.map((source, idx) => (
                  <tr key={`${source.ip}-${source.country}-${idx}`}>
                    <td className="ip-cell">{source.ip}</td>
                    <td className="country-cell" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {getFlagUrl(source.country) ? (
                        <img 
                          src={getFlagUrl(source.country)} 
                          alt={source.country} 
                          style={{ width: '18px', height: '12px', objectFit: 'cover', borderRadius: '2px', boxShadow: '0 1px 2px rgba(0,0,0,0.3)' }} 
                        />
                      ) : (
                        <Globe size={14} style={{ color: 'hsl(var(--color-primary))' }} />
                      )}
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
                {threatSources.length === 0 && (
                  <tr>
                    <td colSpan="4" style={{ textAlign: 'center', color: 'hsl(var(--text-muted))', padding: '20px' }}>
                      No external threat logs recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* New Graphs & Tables Row */}
      <div className="maps-grid-row">

        {/* Targeted Ports Card */}
        <div className="chart-container glass-panel" style={{ flex: 1, padding: '20px', minHeight: '300px' }}>
          <div className="card-title-header" style={{ marginBottom: '16px' }}>
            <h3>Top Targeted Ports</h3>
          </div>
          <div style={{ width: '100%', height: '220px' }}>
            {targetedPorts.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={targetedPorts} layout="vertical" margin={{ left: 10, right: 10, top: 10, bottom: 10 }}>
                  <XAxis type="number" stroke="rgba(255,255,255,0.4)" fontSize={10} />
                  <YAxis dataKey="name" type="category" stroke="rgba(255,255,255,0.4)" fontSize={10} width={80} />
                  <Tooltip
                    contentStyle={{ backgroundColor: 'rgba(15, 19, 34, 0.95)', borderColor: 'rgba(34, 42, 76, 0.8)', color: '#fff' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={12}>
                    {targetedPorts.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'hsl(var(--text-muted))' }}>
                No targeted port activity recorded.
              </div>
            )}
          </div>
        </div>

        {/* Active Threat Groups Card */}
        <div className="sources-card glass-panel" style={{ flex: 1, padding: '20px' }}>
          <div className="card-title-header" style={{ marginBottom: '16px' }}>
            <h3>Active APT Threat Groups</h3>
          </div>
          <div className="table-responsive">
            <table className="sources-table">
              <thead>
                <tr>
                  <th>Threat Group</th>
                  <th>Origin</th>
                  <th>Primary Target</th>
                  <th style={{ textAlign: 'right' }}>Campaigns</th>
                </tr>
              </thead>
              <tbody>
                {APT_GROUPS_DATA.map((group) => (
                  <tr key={group.name} className="alert-row">
                    <td className="alert-title-cell" style={{ color: '#fff', fontWeight: '600' }}>{group.name}</td>
                    <td className="source-cell">{group.origin}</td>
                    <td className="category-cell">{group.target}</td>
                    <td style={{ textAlign: 'right', fontWeight: '700', color: 'hsl(var(--sev-critical))' }}>{group.attacks}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Malicious IOCs Feed Table Card */}
      <div className="alerts-grid-card glass-panel" style={{ padding: '20px' }}>
        <div className="card-title-header" style={{ marginBottom: '16px' }}>
          <h3>Global Indicators of Compromise (IOC) Feed</h3>
        </div>
        <div className="table-responsive">
          <table className="sources-table">
            <thead>
              <tr>
                <th>Indicator / Pattern</th>
                <th>Type</th>
                <th>Threat Score</th>
                <th>Associated Threat</th>
                <th style={{ textAlign: 'right' }}>Detected Date</th>
              </tr>
            </thead>
            <tbody>
              {maliciousIocs.map((ioc, idx) => (
                <tr key={idx} className="alert-row">
                  <td className="ip-cell" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{ioc.indicator}</td>
                  <td className="category-cell">
                    <span style={{
                      backgroundColor: 'rgba(255, 255, 255, 0.05)',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      color: 'hsl(var(--text-secondary))'
                    }}>
                      {ioc.type}
                    </span>
                  </td>
                  <td>
                    <span className="risk-badge" style={{ backgroundColor: 'rgba(239, 68, 68, 0.15)', color: 'var(--sev-critical)' }}>
                      {ioc.score}
                    </span>
                  </td>
                  <td className="source-cell" style={{ color: '#fff' }}>{ioc.threat}</td>
                  <td style={{ textAlign: 'right' }} className="time-cell">{ioc.date}</td>
                </tr>
              ))}
              {maliciousIocs.length === 0 && (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', color: 'hsl(var(--text-muted))', padding: '20px' }}>
                    No malicious indicators of compromise found in active database alerts.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default ThreatMap
