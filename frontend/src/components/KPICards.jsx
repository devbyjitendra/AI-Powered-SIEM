import React, { useEffect, useState } from 'react'
import { 
  Database, 
  Bell, 
  ShieldAlert, 
  Target, 
  TrendingUp, 
  TrendingDown 
} from 'lucide-react'
import { getDashboardStats } from '../services/api'

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

function KPICard({ title, value, trend, isPositive, icon: IconComponent, data, strokeColor, warning }) {
  const path = getSvgPath(data, 120, 40)
  
  return (
    <div className="kpi-card glass-panel" style={{ opacity: warning ? 0.85 : 1 }}>
      {warning && (
        <style>{`
          @keyframes warning-pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(0.97); }
          }
          .pulse-warning-badge {
            animation: warning-pulse 2s infinite ease-in-out;
          }
        `}</style>
      )}
      <div className="kpi-card-header">
        <div className="kpi-icon-wrapper" style={{ backgroundColor: warning ? 'rgba(239, 68, 68, 0.1)' : `rgba(${strokeColor}, 0.1)`, color: warning ? 'rgb(239, 68, 68)' : `rgb(${strokeColor})` }}>
          <IconComponent size={20} />
        </div>
        <div className="kpi-trend" style={{ color: warning ? 'rgb(239, 68, 68)' : (isPositive ? 'hsl(var(--sev-low))' : 'hsl(var(--sev-critical))') }}>
          {warning ? '⚠️' : (isPositive ? <TrendingUp size={14} /> : <TrendingDown size={14} />)}
          <span>{warning ? 'OFFLINE' : trend}</span>
        </div>
      </div>
      
      <div className="kpi-card-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '4px' }}>
        <div className="kpi-stat-info" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <span className="kpi-title" style={{ fontSize: '1.1rem', color: '#fff', fontWeight: '600', fontFamily: "'Outfit', sans-serif" }}>{title}</span>
          {warning && (
            <div style={{ marginTop: '2px' }}>
              <span className="pulse-warning-badge" style={{
                fontSize: '0.6rem',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                color: 'rgb(239, 68, 68)',
                padding: '2px 6px',
                borderRadius: '4px',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                {warning}
              </span>
            </div>
          )}
        </div>
        
        <h3 className="kpi-value" style={{ margin: 0, fontSize: '1.75rem', fontWeight: '700' }}>{value}</h3>
      </div>
    </div>
  )
}

function KPICards({ integrationStates, stats }) {
  const simulatorActive = integrationStates?.simulator !== false

  const totalEvents = simulatorActive ? (stats ? stats.total_events.toLocaleString() : "...") : "SUSPENDED"
  const totalAlerts = stats ? stats.total_alerts.toLocaleString() : "..."
  const totalCases = stats ? stats.total_cases.toLocaleString() : "..."
  const criticalIncidents = stats ? stats.critical_incidents.toLocaleString() : "..."

  const eventsTrend = stats && stats.events_trend ? stats.events_trend : "0.0% vs yesterday"
  const eventsIsPositive = stats && stats.events_is_positive !== undefined ? stats.events_is_positive : true

  const alertsTrend = stats && stats.alerts_trend ? stats.alerts_trend : "0.0% vs yesterday"
  const alertsIsPositive = stats && stats.alerts_is_positive !== undefined ? stats.alerts_is_positive : false

  const casesTrend = stats && stats.cases_trend ? stats.cases_trend : "0.0% vs yesterday"
  const casesIsPositive = stats && stats.cases_is_positive !== undefined ? stats.cases_is_positive : true

  const criticalTrend = stats && stats.critical_trend ? stats.critical_trend : "0.0% vs yesterday"
  const criticalIsPositive = stats && stats.critical_is_positive !== undefined ? stats.critical_is_positive : false

  // Generate dynamic sparklines scaled to actual counts
  const timelineEvents = stats && stats.timeline ? stats.timeline.map(t => t.events) : [0, 0, 0, 0, 0]
  const totalEv = stats ? stats.total_events : 1
  const eventsSparkline = timelineEvents
  const alertsSparkline = timelineEvents.map(e => Math.round(e * ((stats ? stats.total_alerts : 0) / (totalEv || 1))))
  const casesSparkline = timelineEvents.map(e => Math.round(e * ((stats ? stats.total_cases : 0) / (totalEv || 1))))
  const criticalSparkline = timelineEvents.map(e => Math.round(e * ((stats ? stats.critical_incidents : 0) / (totalEv || 1))))

  return (
    <div className="kpi-grid">
      <KPICard
        title="Total Events"
        value={totalEvents}
        trend={eventsTrend}
        isPositive={eventsIsPositive}
        icon={Database}
        data={eventsSparkline}
        strokeColor="47, 128, 237" // Blue
        warning={!simulatorActive ? "Ingestion Suspended" : undefined}
      />
      <KPICard
        title="Alerts"
        value={totalAlerts}
        trend={alertsTrend}
        isPositive={alertsIsPositive}
        icon={Bell}
        data={alertsSparkline}
        strokeColor="239, 68, 68" // Red
      />
      <KPICard
        title="Total Cases Registered"
        value={totalCases}
        trend={casesTrend}
        isPositive={casesIsPositive}
        icon={ShieldAlert}
        data={casesSparkline}
        strokeColor="245, 158, 11" // Orange/Amber
      />
      <KPICard
        title="Critical Incidents"
        value={criticalIncidents}
        trend={criticalTrend}
        isPositive={criticalIsPositive}
        icon={Target}
        data={criticalSparkline}
        strokeColor="239, 68, 68" // Red
      />
    </div>
  )
}

export default KPICards
