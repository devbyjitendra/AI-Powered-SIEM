import React, { useEffect, useState } from 'react'
import { getDashboardStats, getAlerts } from '../services/api'
import { ShieldAlert, AlertTriangle, Cpu, Users, Layers, ShieldCheck, ArrowRight } from 'lucide-react'

function IncidentsPanel({ setActiveTab }) {
  const [stats, setStats] = useState(null)
  const [criticalAlerts, setCriticalAlerts] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function loadIncidentData() {
      setLoading(true)
      try {
        const statsData = await getDashboardStats()
        if (statsData) {
          setStats(statsData)
        }
        
        const alertsData = await getAlerts()
        if (alertsData) {
          // Filter to get only High and Critical severity active alerts
          const criticalOnly = alertsData.filter(
            alert => (alert.severity === 'CRITICAL' || alert.severity === 'HIGH') && alert.status !== 'RESOLVED'
          )
          setCriticalAlerts(criticalOnly.slice(0, 10))
        }
      } catch (err) {
        console.error("Error loading incident workspace data:", err)
      } finally {
        setLoading(false)
      }
    }

    loadIncidentData()
    const interval = setInterval(loadIncidentData, 6000)
    return () => clearInterval(interval)
  }, [])

  const formatTime = (isoString) => {
    try {
      const date = new Date(isoString)
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    } catch {
      return '10:24 AM'
    }
  }

  return (
    <div className="incidents-panel-layout" style={{ color: '#fff', fontFamily: "'Inter', sans-serif" }}>
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
          Active Threat Incidents
        </h1>
        <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
          Real-time correlated attack campaigns and target compromises requiring immediate triage
        </span>
      </div>

      {loading && !stats ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'hsl(var(--text-muted))' }}>
          Loading live security incidents...
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Active Campaigns Row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
            
            {/* Critical Correlated Alarms Card */}
            <div className="alerts-grid-card glass-panel" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldAlert size={18} style={{ color: '#ef4444' }} /> Active Attacks ({criticalAlerts.length})
                </h3>
                <button 
                  onClick={() => setActiveTab && setActiveTab('Alerts')}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'hsl(var(--color-ai-cyan))',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontWeight: 600
                  }}
                >
                  View Triage <ArrowRight size={12} />
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '340px', overflowY: 'auto' }}>
                {criticalAlerts.map(alert => (
                  <div 
                    key={alert.id} 
                    style={{
                      backgroundColor: 'rgba(239, 68, 68, 0.04)',
                      border: '1px solid rgba(239, 68, 68, 0.15)',
                      borderRadius: '8px',
                      padding: '12px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: '700', color: alert.severity === 'CRITICAL' ? '#ef4444' : '#f97316' }}>
                        {alert.severity}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>
                        {formatTime(alert.timestamp)}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.85rem', fontWeight: '600', color: '#fff' }}>{alert.title}</span>
                    <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>{alert.description}</span>
                  </div>
                ))}

                {criticalAlerts.length === 0 && (
                  <div style={{ textAlign: 'center', padding: '40px 20px', color: 'hsl(var(--text-muted))', fontSize: '0.8rem' }}>
                    <ShieldCheck size={28} style={{ color: '#10b981', marginBottom: '8px' }} />
                    <div>No active critical or high threats detected.</div>
                  </div>
                )}
              </div>
            </div>

            {/* Target Assets Under Attack */}
            <div className="alerts-grid-card glass-panel" style={{ padding: '20px' }}>
              <h3 style={{ margin: 0, marginBottom: '16px', fontSize: '1rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Cpu size={18} style={{ color: 'hsl(var(--color-ai-cyan))' }} /> Compromised Assets
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {stats?.risky_resources && stats.risky_resources.map((asset, i) => {
                  const isCritical = asset.severity === 'critical' || asset.severity === 'high';
                  return (
                    <div 
                      key={i} 
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        paddingBottom: '10px',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.05)'
                      }}
                    >
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                        <span style={{ fontSize: '0.85rem', fontWeight: '600', color: '#fff' }}>{asset.host}</span>
                        <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>
                          Active threat: <span style={{ color: '#f59e0b' }}>{asset.anomaly}</span>
                        </span>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <span 
                          style={{
                            fontSize: '0.75rem',
                            padding: '3px 8px',
                            borderRadius: '4px',
                            backgroundColor: isCritical ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                            color: isCritical ? '#ef4444' : '#f59e0b',
                            fontWeight: '600'
                          }}
                        >
                          Score: {asset.score}
                        </span>
                      </div>
                    </div>
                  )
                })}
                
                {(!stats?.risky_resources || stats.risky_resources.length === 0) && (
                  <div style={{ textAlign: 'center', padding: '40px 20px', color: 'hsl(var(--text-muted))', fontSize: '0.8rem' }}>
                    No assets currently flagged as compromised.
                  </div>
                )}
              </div>
            </div>

          </div>

          {/* Lower Row: Threat Actors and User Risks */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
            
            {/* Risky Accounts (UEBA Profiles) */}
            <div className="alerts-grid-card glass-panel" style={{ padding: '20px' }}>
              <h3 style={{ margin: 0, marginBottom: '16px', fontSize: '1rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Users size={18} style={{ color: '#a061ff' }} /> Risky User Accounts
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {stats?.user_risk_profiles && stats.user_risk_profiles.map((user, i) => (
                  <div 
                    key={i} 
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      paddingBottom: '10px',
                      borderBottom: '1px solid rgba(255, 255, 255, 0.05)'
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                      <span style={{ fontSize: '0.85rem', fontWeight: '600', color: '#fff' }}>{user.id}</span>
                      <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>
                        Dept: {user.department} | Status: <span style={{ color: '#f59e0b' }}>{user.status}</span>
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '0.8rem', color: '#ef4444', fontWeight: '700' }}>
                        Score: {user.riskScore}
                      </span>
                    </div>
                  </div>
                ))}

                {(!stats?.user_risk_profiles || stats.user_risk_profiles.length === 0) && (
                  <div style={{ textAlign: 'center', padding: '40px 20px', color: 'hsl(var(--text-muted))', fontSize: '0.8rem' }}>
                    No risky user profiles flagged.
                  </div>
                )}
              </div>
            </div>

            {/* Live Indicators of Compromise (IoCs) */}
            <div className="alerts-grid-card glass-panel" style={{ padding: '20px' }}>
              <h3 style={{ margin: 0, marginBottom: '16px', fontSize: '1rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={18} style={{ color: '#e5e7eb' }} /> Blocked Indicators of Compromise (IoC)
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {stats?.malicious_iocs && stats.malicious_iocs.slice(0, 5).map((ioc, i) => (
                  <div 
                    key={i} 
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      paddingBottom: '10px',
                      borderBottom: '1px solid rgba(255, 255, 255, 0.05)'
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                      <span style={{ fontSize: '0.85rem', fontWeight: '600', color: '#fff', fontFamily: 'monospace' }}>{ioc.indicator}</span>
                      <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>
                        Type: <span style={{ textTransform: 'capitalize' }}>{ioc.type}</span> | Risk Score: <span style={{ color: '#ef4444' }}>{ioc.score}</span>
                      </span>
                    </div>
                    <div>
                      <span style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))' }}>
                        {ioc.date || 'Active'}
                      </span>
                    </div>
                  </div>
                ))}

                {(!stats?.malicious_iocs || stats.malicious_iocs.length === 0) && (
                  <div style={{ textAlign: 'center', padding: '40px 20px', color: 'hsl(var(--text-muted))', fontSize: '0.8rem' }}>
                    No malicious Indicators of Compromise recorded.
                  </div>
                )}
              </div>
            </div>

          </div>

        </div>
      )}
    </div>
  )
}

export default IncidentsPanel
