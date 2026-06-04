import React, { useEffect, useState } from 'react'
import { UserCheck, AlertTriangle, ShieldCheck, ShieldAlert, Users, Server } from 'lucide-react'
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts'
import { getDashboardStats } from '../services/api'

function UEBA() {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    async function loadStats() {
      const data = await getDashboardStats()
      if (data) {
        setStats(data)
      }
    }
    loadStats()
    
    const interval = setInterval(loadStats, 5000)
    return () => clearInterval(interval)
  }, [])

  const userRiskProfiles = stats && stats.user_risk_profiles ? stats.user_risk_profiles : []
  const anomalousActivities = stats && stats.anomalous_activities ? stats.anomalous_activities : []
  const riskyResources = stats && stats.risky_resources ? stats.risky_resources : []

  // Dynamic anomaly breakdown from categories stats
  const totalAlerts = stats ? (stats.categories.Authentication + stats.categories["Web Application"] + stats.categories.System + stats.categories.Malware + stats.categories["Policy Violation"]) : 0
  const anomalyBreakdown = stats && totalAlerts > 0 ? [
    { name: 'Credential Abuse', value: Math.round(((stats.categories.Authentication || 0) / totalAlerts) * 100), color: '#ef4444' },
    { name: 'Suspicious Activity', value: Math.round(((stats.categories["Web Application"] || 0) / totalAlerts) * 100), color: '#f59e0b' },
    { name: 'Policy Violation', value: Math.round(((stats.categories["Policy Violation"] || 0) / totalAlerts) * 100), color: '#2f80ed' },
    { name: 'System Anomaly', value: Math.round(((stats.categories.System || 0) / totalAlerts) * 100), color: '#a061ff' }
  ] : [
    { name: 'Credential Abuse', value: 0, color: '#ef4444' },
    { name: 'Suspicious Activity', value: 0, color: '#f59e0b' },
    { name: 'Policy Violation', value: 0, color: '#2f80ed' },
    { name: 'System Anomaly', value: 0, color: '#a061ff' }
  ]

  return (
    <div className="ueba-layout" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ marginBottom: '10px' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
          User & Entity Behavior Analytics (UEBA)
        </h1>
        <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
          Evaluate employee credentials risk index, flag anomalous access activities, and pinpoint compromised assets.
        </span>
      </div>

      {/* Two Column Workspace Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px', alignItems: 'start' }}>
        {/* Left Column: Tables stacked vertically */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* User Risk Indexes */}
          <div className="glass-panel simulator-card" style={{ padding: '20px' }}>
            <h3 className="card-title" style={{ margin: 0, marginBottom: '16px' }}>
              <Users size={18} className="card-icon" /> User Risk Indexes
            </h3>
            
            <div className="table-responsive">
              <table className="sources-table">
                <thead>
                  <tr>
                    <th>Identity</th>
                    <th>Group / Dept</th>
                    <th>Risk Index</th>
                    <th style={{ textAlign: 'right' }}>Security Status</th>
                  </tr>
                </thead>
                <tbody>
                  {userRiskProfiles.map((profile) => (
                    <tr key={profile.id} className="alert-row">
                      <td className="ip-cell" style={{ color: '#fff' }}>{profile.id}</td>
                      <td className="source-cell">{profile.department}</td>
                      <td>
                        <span className={`severity-tag label-${profile.severity}`} style={{ fontWeight: '700' }}>
                          Score: {profile.riskScore}%
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <span style={{ 
                          fontSize: '0.75rem', 
                          fontWeight: '600', 
                          color: profile.severity === 'critical' ? 'hsl(var(--sev-critical))' : 
                                 profile.severity === 'high' ? 'hsl(var(--sev-high))' : 
                                 profile.severity === 'medium' ? 'hsl(var(--sev-medium))' : 'hsl(var(--sev-low))'
                        }}>
                          {profile.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {userRiskProfiles.length === 0 && (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', color: 'hsl(var(--text-muted))', padding: '20px' }}>
                        No user credential risks identified.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Highly Compromised Assets / Entities */}
          <div className="glass-panel simulator-card" style={{ padding: '20px' }}>
            <h3 className="card-title" style={{ margin: 0, marginBottom: '16px' }}>
              <Server size={18} className="card-icon" /> Highly Compromised Assets / Entities
            </h3>
            
            <div className="table-responsive">
              <table className="sources-table">
                <thead>
                  <tr>
                    <th>Asset Name</th>
                    <th>Identified Anomaly</th>
                    <th>Risk Index</th>
                    <th style={{ textAlign: 'right' }}>Owner</th>
                  </tr>
                </thead>
                <tbody>
                  {riskyResources.map((resource, idx) => (
                    <tr key={idx} className="alert-row">
                      <td className="ip-cell" style={{ color: '#fff', fontFamily: 'monospace' }}>{resource.host}</td>
                      <td className="source-cell">{resource.anomaly}</td>
                      <td>
                        <span className={`severity-tag label-${resource.severity}`} style={{ fontWeight: '700' }}>
                          Score: {resource.score}%
                        </span>
                      </td>
                      <td style={{ textAlign: 'right', color: 'hsl(var(--text-secondary))' }}>
                        {resource.owner}
                      </td>
                    </tr>
                  ))}
                  {riskyResources.length === 0 && (
                    <tr>
                      <td colSpan="4" style={{ textAlign: 'center', color: 'hsl(var(--text-muted))', padding: '20px' }}>
                        No assets flagged as compromised.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>

        {/* Right Column: Behavioral Anomalies Feed */}
        <div className="glass-panel simulator-card" style={{ padding: '20px' }}>
          <h3 className="card-title" style={{ margin: 0, marginBottom: '16px' }}>
            <AlertTriangle size={18} className="card-icon" /> Behavioral Anomalies Feed
          </h3>
          
          <div className="settings-form" style={{ gap: '16px' }}>
            {anomalousActivities.map((activity, idx) => (
              <div key={idx} style={{ 
                borderBottom: idx < anomalousActivities.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none', 
                paddingBottom: '12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.85rem', color: '#fff', fontWeight: '700' }}>
                    {activity.type} ({activity.user})
                  </span>
                  <span style={{ fontSize: '0.7rem', color: 'hsl(var(--text-muted))' }}>
                    {activity.time}
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', lineHeight: 1.4, margin: 0 }}>
                  {activity.description}
                </p>
                <span className={`risk-badge severity-${activity.risk.toLowerCase()}`} style={{ 
                  fontSize: '0.65rem', 
                  fontWeight: '700', 
                  width: 'fit-content',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  backgroundColor: activity.risk === 'CRITICAL' ? 'rgba(239, 68, 68, 0.15)' : 
                                  activity.risk === 'HIGH' ? 'rgba(249, 115, 22, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                  color: activity.risk === 'CRITICAL' ? 'hsl(var(--sev-critical))' : 
                         activity.risk === 'HIGH' ? 'hsl(var(--sev-high))' : 'hsl(var(--sev-medium))'
                }}>
                  {activity.risk}
                </span>
              </div>
            ))}
            {anomalousActivities.length === 0 && (
              <div style={{ textAlign: 'center', color: 'hsl(var(--text-muted))', padding: '20px' }}>
                No anomalous activity alerts triggered.
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  )
}

export default UEBA
