import React, { useEffect, useState } from 'react'
import { getAlerts, updateAlertStatus } from '../services/api'
import { ShieldAlert, AlertCircle, CheckCircle, Clock, Bell } from 'lucide-react'
import AIPlaybookDrawer from './AIPlaybookDrawer.jsx'

// Mock fallback list matching mockup exactly
const MOCK_ALERTS = [
  {
    id: 101,
    timestamp: new Date().toISOString(),
    title: 'Multiple failed login attempts',
    source_ip: '192.168.1.45',
    rule_id: 'RULE-AUTH-BRUTEFORCE',
    severity: 'High',
    status: 'NEW',
    category: 'Authentication'
  }
]

function AlertsGrid() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState({ visible: false, title: '', message: '', severity: '' })
  const [selectedAlertId, setSelectedAlertId] = useState(null)


  const loadAlerts = async () => {
    setLoading(true)
    const data = await getAlerts()
    
    if (data && data.length > 0) {
      // Map API fields
      const formatted = data.map(item => ({
        id: item.id,
        timestamp: item.timestamp,
        title: item.title,
        source_ip: item.trigger_log ? item.trigger_log.source_ip : 'Unknown Source',
        category: item.rule_id.includes('AUTH') ? 'Authentication' : 
                  item.rule_id.includes('SQL') ? 'Web Application' : 'System',
        severity: item.severity,
        status: item.status
      }))
      setAlerts(formatted)
    } else {
      setAlerts(MOCK_ALERTS)
    }
    setLoading(false)
  }

  const triggerToast = (title, message, severity) => {
    setToast({ visible: true, title, message, severity })
    setTimeout(() => {
      setToast(prev => ({ ...prev, visible: false }))
    }, 4500)
  }

  const handleStatusChange = async (alertId, newStatus) => {
    // If it's the mock alert, just update state locally
    if (alertId === 101) {
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a))
      return
    }

    const updated = await updateAlertStatus(alertId, newStatus)
    if (updated) {
      loadAlerts()
    }
  }

  useEffect(() => {
    loadAlerts()
    
    // Set up WebSocket connection for real-time streaming
    const wsUrl = 'ws://127.0.0.1:8000/ws/alerts'
    let socket
    let reconnectTimeout

    const connectWebSocket = () => {
      console.log('Connecting to WebSocket alert stream...')
      socket = new WebSocket(wsUrl)

      socket.onopen = () => {
        console.log('WebSocket client successfully connected.')
      }

      socket.onmessage = (event) => {
        try {
          const newAlert = JSON.parse(event.data)
          console.log('Real-time alert streamed:', newAlert)
          
          const formatted = {
            id: newAlert.id,
            timestamp: newAlert.timestamp,
            title: newAlert.title,
            source_ip: newAlert.trigger_log ? newAlert.trigger_log.source_ip : 'Unknown Source',
            category: newAlert.rule_id.includes('AUTH') ? 'Authentication' : 
                      newAlert.rule_id.includes('SQL') ? 'Web Application' : 'System',
            severity: newAlert.severity,
            status: newAlert.status
          }

          // Prepend the new alert to show it instantly in the table
          setAlerts(prev => {
            if (prev.some(a => a.id === formatted.id)) return prev
            return [formatted, ...prev]
          })

          // Trigger screen toast
          triggerToast(
            formatted.title,
            `Alert source IP: ${formatted.source_ip} | Category: ${formatted.category}`,
            formatted.severity
          )
        } catch (err) {
          console.error('WebSocket payload error:', err)
        }
      }

      socket.onclose = () => {
        console.warn('WebSocket connection lost. Retrying in 5 seconds...')
        reconnectTimeout = setTimeout(connectWebSocket, 5000)
      }

      socket.onerror = (err) => {
        console.error('WebSocket encountered an error:', err)
      }
    }

    connectWebSocket()

    return () => {
      if (socket) socket.close()
      if (reconnectTimeout) clearTimeout(reconnectTimeout)
    }
  }, [])

  const formatTime = (isoString) => {
    try {
      const date = new Date(isoString)
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    } catch {
      return '10:24:32 AM'
    }
  }

  return (
    <>
      {/* Toast Alert Pop-Up */}
      <div className={`toast-notification ${toast.visible ? 'visible' : ''} ${toast.severity ? `severity-${toast.severity.toLowerCase()}` : ''}`}>
        <div className="toast-icon-wrapper">
          {toast.severity && (
            <Bell size={18} className="sparkle-icon" style={{ color: `var(--sev-${toast.severity.toLowerCase()})` }} />
          )}
        </div>
        <div className="toast-content">
          <span className="toast-title">{toast.title}</span>
          <span className="toast-message">{toast.message}</span>
        </div>
      </div>

      <div className="alerts-grid-card glass-panel">
        <div className="card-title-header">
          <h3>Recent Alerts</h3>
          <div className="grid-controls">
            <button className="grid-refresh-btn" onClick={loadAlerts}>Refresh Feed</button>
          </div>
        </div>

        <div className="table-responsive">
          {loading && alerts.length === 0 ? (
            <div className="grid-loading">Loading alerts database...</div>
          ) : (
            <table className="sources-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Alert Name</th>
                  <th>Source</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th style={{ textAlign: 'right' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => {
                  const sev = alert.severity ? alert.severity.toLowerCase() : 'medium'
                  const statusLower = alert.status ? alert.status.toLowerCase() : 'new'
                  
                  return (
                    <tr key={alert.id} className={`alert-row severity-${sev}`}>
                      <td className="time-cell">{formatTime(alert.timestamp)}</td>
                      <td 
                        className="alert-title-cell" 
                        style={{ cursor: 'pointer' }} 
                        onClick={() => setSelectedAlertId(alert.id)}
                        title="Click to view AI playbook insights"
                      >
                        <span className="alert-dot" style={{ backgroundColor: `var(--sev-${sev})` }}></span>
                        <span style={{ textDecoration: 'underline', textDecorationStyle: 'dotted' }}>{alert.title}</span>
                      </td>
                      <td className="source-cell">{alert.source_ip}</td>
                      <td className="category-cell">{alert.category || 'Security'}</td>
                      <td>
                        <span className={`severity-tag label-${sev}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <select
                          className={`status-select status-${statusLower}`}
                          value={alert.status}
                          onChange={(e) => handleStatusChange(alert.id, e.target.value)}
                        >
                          <option value="NEW">New</option>
                          <option value="ACKNOWLEDGED">Acknowledged</option>
                          <option value="RESOLVED">Resolved</option>
                        </select>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {selectedAlertId && (
        <AIPlaybookDrawer alertId={selectedAlertId} onClose={() => setSelectedAlertId(null)} />
      )}
    </>
  )
}

export default AlertsGrid

