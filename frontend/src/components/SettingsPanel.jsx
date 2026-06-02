import React, { useState, useEffect } from 'react'
import { Settings, ShieldAlert, Wifi, Plus, Trash2, CheckCircle2 } from 'lucide-react'
import { getRules, updateRule } from '../services/api'

const DEFAULT_INTEL_FEEDS = [
  { ip: '198.51.100.45', country: 'United States', severity: 'HIGH' },
  { ip: '203.0.113.82', country: 'Netherlands', severity: 'CRITICAL' },
  { ip: '185.190.140.40', country: 'Russian Federation', severity: 'HIGH' }
]

function SettingsPanel() {
  const [rules, setRules] = useState([])
  const [intelFeeds, setIntelFeeds] = useState(DEFAULT_INTEL_FEEDS)
  const [loadingRules, setLoadingRules] = useState(true)

  // Input states
  const [newIp, setNewIp] = useState('')
  const [newCountry, setNewCountry] = useState('')
  const [newSeverity, setNewSeverity] = useState('HIGH')

  const loadRules = async () => {
    setLoadingRules(true)
    const data = await getRules()
    if (data && data.length > 0) {
      setRules(data)
    } else {
      // Fallback fallback rule templates
      setRules([
        { id: 'RULE-AUTH-BRUTEFORCE', name: 'Failed Login Brute Force', severity: 'HIGH', pattern: 'Failed password', is_active: true },
        { id: 'RULE-WEB-SQLI', name: 'SQL Injection Attack', severity: 'CRITICAL', pattern: 'UNION SELECT', is_active: true }
      ])
    }
    setLoadingRules(false)
  }

  useEffect(() => {
    loadRules()
  }, [])

  const handleToggleRule = async (ruleId, currentStatus) => {
    const nextStatus = !currentStatus
    // Update local state first
    setRules(prev => prev.map(r => r.id === ruleId ? { ...r, is_active: nextStatus } : r))
    
    // Call server PUT if not a mock fallback
    const matched = rules.find(r => r.id === ruleId)
    if (matched && matched.created_at) {
      await updateRule(ruleId, { is_active: nextStatus })
    }
  }

  const handleAddFeed = (e) => {
    e.preventDefault()
    if (!newIp.trim()) return
    
    const newFeed = {
      ip: newIp,
      country: newCountry || 'Unknown Origin',
      severity: newSeverity
    }
    setIntelFeeds(prev => [...prev, newFeed])
    setNewIp('')
    setNewCountry('')
  }

  const handleRemoveFeed = (index) => {
    setIntelFeeds(prev => prev.filter((_, i) => i !== index))
  }

  return (
    <div className="settings-layout">
      {/* Header */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
          Threat Configurations & Rules
        </h1>
        <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
          Configure live correlation signatures, threat feeds, and security command controls.
        </span>
      </div>

      <div className="simulator-grid">
        {/* Left - Active Correlation Rules */}
        <div className="simulator-card-column">
          <div className="glass-panel simulator-card">
            <h3 className="card-title">
              <ShieldAlert size={18} className="card-icon" /> Threat Detection Rules
            </h3>
            
            {loadingRules ? (
              <div className="grid-loading" style={{ padding: '20px 0' }}>Querying active rule engine...</div>
            ) : (
              <div className="settings-form" style={{ gap: '14px' }}>
                {rules.map((rule) => (
                  <div key={rule.id} className="toggle-switch-wrapper" style={{ justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', paddingBottom: '12px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxWidth: '80%' }}>
                      <span style={{ fontSize: '0.9rem', color: '#fff', fontWeight: '600' }}>
                        {rule.name}
                      </span>
                      <code style={{ fontSize: '0.7rem', color: 'hsl(var(--color-primary))', fontFamily: 'monospace' }}>
                        Pattern: "{rule.pattern}"
                      </code>
                    </div>
                    
                    <div className="toggle-switch-wrapper" onClick={() => handleToggleRule(rule.id, rule.is_active)}>
                      <div className={`toggle-track ${rule.is_active ? 'active' : ''}`}>
                        <div className="toggle-thumb" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right - Threat Intelligence Feeds */}
        <div className="simulator-card-column">
          <div className="glass-panel simulator-card">
            <h3 className="card-title">
              <Wifi size={18} className="card-icon" /> Live Threat Intelligence Feeds
            </h3>
            
            {/* Intel Form */}
            <form onSubmit={handleAddFeed} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '12px', marginBottom: '20px', alignItems: 'end' }}>
              <div className="form-group">
                <label className="form-label" htmlFor="feed-ip">Intel Source IP</label>
                <input 
                  type="text" 
                  id="feed-ip"
                  className="search-input" 
                  placeholder="e.g. 185.220.101.5"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  style={{ borderRadius: '6px', padding: '8px 12px', fontSize: '0.8rem' }}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label" htmlFor="feed-country">Geo Origin</label>
                <input 
                  type="text" 
                  id="feed-country"
                  className="search-input" 
                  placeholder="e.g. Netherlands"
                  value={newCountry}
                  onChange={(e) => setNewCountry(e.target.value)}
                  style={{ borderRadius: '6px', padding: '8px 12px', fontSize: '0.8rem' }}
                />
              </div>
              <button type="submit" className="ai-gradient-btn run-simulation-btn" style={{ height: '36px', padding: '0 16px', borderRadius: '6px' }}>
                <Plus size={14} />
              </button>
            </form>

            {/* Intel Feed list */}
            <div className="table-responsive">
              <table className="sources-table" style={{ fontSize: '0.8rem' }}>
                <thead>
                  <tr>
                    <th>Malicious IP</th>
                    <th>Geo Origin</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {intelFeeds.map((feed, index) => (
                    <tr key={index} className="alert-row">
                      <td className="ip-cell" style={{ fontSize: '0.8rem' }}>{feed.ip}</td>
                      <td className="source-cell">{feed.country}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button 
                          className="drawer-close-btn" 
                          onClick={() => handleRemoveFeed(index)}
                          style={{ display: 'inline-flex', padding: '4px' }}
                          title="Remove Threat IP"
                        >
                          <Trash2 size={12} style={{ color: 'hsl(var(--sev-critical))' }} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default SettingsPanel
