import React, { useEffect, useState } from 'react'
import { getAlerts, updateAlertStatus, createCase, linkAlertToCase } from '../services/api'
import { ShieldAlert, AlertCircle, CheckCircle, Clock, Bell } from 'lucide-react'
import AIPlaybookDrawer from './AIPlaybookDrawer.jsx'

// Helper to convert wildcard patterns (e.g. *login*, SQL*) to regular expressions
const wildcardToRegex = (query) => {
  const escaped = query.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  const regexStr = escaped.replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp(`^${regexStr}$`, 'i')
}

const matchesSearch = (text, query) => {
  if (!query) return true
  if (!query.includes('*') && !query.includes('?')) {
    return text.toLowerCase().includes(query.toLowerCase())
  }
  try {
    const regex = wildcardToRegex(query)
    return regex.test(text)
  } catch {
    return false
  }
}

function AlertsGrid({ 
  integrationStates,
  alerts: propAlerts,
  setAlerts: propSetAlerts,
  filterSeverity: propFilterSeverity,
  setFilterSeverity: propSetFilterSeverity,
  filterCategory: propFilterCategory,
  setFilterCategory: propSetFilterCategory,
  filterStatus: propFilterStatus,
  setFilterStatus: propSetFilterStatus,
  filterStartTime: propFilterStartTime,
  setFilterStartTime: propSetFilterStartTime,
  filterEndTime: propFilterEndTime,
  setFilterEndTime: propSetFilterEndTime,
  searchQuery: propSearchQuery,
  setSearchQuery: propSetSearchQuery,
  currentPage: propCurrentPage,
  setCurrentPage: propSetCurrentPage,
  setActiveTab
}) {
  const [localAlerts, setLocalAlerts] = useState([])
  const alerts = propAlerts !== undefined ? propAlerts : localAlerts
  const setAlerts = propSetAlerts !== undefined ? propSetAlerts : setLocalAlerts

  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(null)

  const [selectedAlertId, setSelectedAlertId] = useState(null)

  const [localFilterSeverity, setLocalFilterSeverity] = useState('ALL')
  const filterSeverity = propFilterSeverity !== undefined ? propFilterSeverity : localFilterSeverity
  const setFilterSeverity = propSetFilterSeverity !== undefined ? propSetFilterSeverity : setLocalFilterSeverity

  const [localFilterCategory, setLocalFilterCategory] = useState('ALL')
  const filterCategory = propFilterCategory !== undefined ? propFilterCategory : localFilterCategory
  const setFilterCategory = propSetFilterCategory !== undefined ? propSetFilterCategory : setLocalFilterCategory

  const [localFilterStatus, setLocalFilterStatus] = useState('ALL')
  const filterStatus = propFilterStatus !== undefined ? propFilterStatus : localFilterStatus
  const setFilterStatus = propSetFilterStatus !== undefined ? propSetFilterStatus : setLocalFilterStatus

  const [localFilterStartTime, setLocalFilterStartTime] = useState('')
  const filterStartTime = propFilterStartTime !== undefined ? propFilterStartTime : localFilterStartTime
  const setFilterStartTime = propSetFilterStartTime !== undefined ? propSetFilterStartTime : setLocalFilterStartTime

  const [localFilterEndTime, setLocalFilterEndTime] = useState('')
  const filterEndTime = propFilterEndTime !== undefined ? propFilterEndTime : localFilterEndTime
  const setFilterEndTime = propSetFilterEndTime !== undefined ? propSetFilterEndTime : setLocalFilterEndTime

  const [localSearchQuery, setLocalSearchQuery] = useState('')
  const searchQuery = propSearchQuery !== undefined ? propSearchQuery : localSearchQuery
  const setSearchQuery = propSetSearchQuery !== undefined ? propSetSearchQuery : setLocalSearchQuery

  const [wsStatus, setWsStatus] = useState('connecting')

  const [localCurrentPage, setLocalCurrentPage] = useState(1)
  const currentPage = propCurrentPage !== undefined ? propCurrentPage : localCurrentPage
  const setCurrentPage = propSetCurrentPage !== undefined ? propSetCurrentPage : setLocalCurrentPage

  const itemsPerPage = 50

  const isFirstRender = React.useRef(true)

  // Reset to first page when search filters change
  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false
      return
    }
    setCurrentPage(1)
  }, [filterSeverity, filterCategory, filterStatus, searchQuery, filterStartTime, filterEndTime])

  const loadAlerts = async (isInitial = false) => {
    if (isInitial && alerts.length === 0) setLoading(true)
    try {
      const startIso = filterStartTime || ''
      const endIso = filterEndTime || ''

      const data = await getAlerts(
        filterStatus === 'ALL' ? '' : filterStatus,
        filterSeverity === 'ALL' ? '' : filterSeverity,
        startIso,
        endIso
      )
      
      if (data && data.length > 0) {
        // Map API fields
        const formatted = data.map(item => {
          const ruleId = item.rule_id || '';
          return {
            id: item.id,
            timestamp: item.timestamp,
            title: item.title,
            source_ip: item.trigger_log ? item.trigger_log.source_ip : 'Unknown Source',
            category: (typeof ruleId === 'string' && ruleId.includes('AUTH')) ? 'Authentication' : 
                      (typeof ruleId === 'string' && ruleId.includes('SQL')) ? 'Web Application' : 'System',
            severity: item.severity || 'MEDIUM',
            status: item.status || 'NEW'
          };
        })
        setAlerts(formatted)
        setFetchError(null)
      } else {
        setAlerts([])
        setFetchError(data ? "API returned empty array" : "API returned null/undefined")
      }
    } catch (error) {
      console.error('Error loading alerts in grid:', error)
      setAlerts([])
      setFetchError(error.message || String(error))
    } finally {
      if (isInitial) setLoading(false)
    }
  }

  const downloadAlertsCSV = () => {
    if (!filterStartTime && !filterEndTime) return

    // Convert filteredAlerts to CSV format
    const headers = ['ID', 'Timestamp', 'Title', 'Source IP', 'Category', 'Severity', 'Status']
    const rows = filteredAlerts.map(alert => [
      alert.id,
      alert.timestamp,
      `"${(alert.title || '').replace(/"/g, '""')}"`,
      alert.source_ip,
      alert.category || 'Security',
      alert.severity,
      alert.status
    ])

    const csvContent = [headers.join(','), ...rows.map(e => e.join(','))].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.setAttribute('href', url)
    link.setAttribute('download', `siem_alerts_export_${Date.now()}.csv`)
    link.style.visibility = 'hidden'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }



  const handleStatusChange = async (alertId, newStatus) => {
    // Update local state instantly for optimal responsiveness
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a))

    if (alertId === 101) return

    try {
      const updated = await updateAlertStatus(alertId, newStatus)
      if (!updated) {
        loadAlerts(false)
      }
    } catch (error) {
      console.error('Error updating status:', error)
      loadAlerts(false)
    }
  }

  const handleCreateCase = async (alertItem) => {
    if (integrationStates?.cases === false) {
      alert("⚠️ Action Blocked: Case Management Sync is disconnected. Please re-enable it in the Integrations Console.");
      return;
    }
    try {
      const caseData = {
        title: `Escalated Alert: ${alertItem.title || 'Security Threat Alert'}`,
        severity: (alertItem.severity || 'MEDIUM').toUpperCase(),
        assigned_to: 'Unassigned'
      }
      const newCase = await createCase(caseData)
      if (newCase) {
        const linkResult = await linkAlertToCase(newCase.id, alertItem.id)
        if (linkResult) {
          alert(`📁 Case File #${newCase.id} successfully initialized for:\n${alertItem.title}`)
          if (setActiveTab) setActiveTab('Case Management')
        } else {
          alert('Case created successfully, but failed to link the alert to it.')
        }
      } else {
        alert('Failed to escalate alert to case management.')
      }
    } catch (err) {
      console.error(err)
      alert('Error creating case: ' + err.message)
    }
  }

  // 1. Initial and filter-change fetch
  useEffect(() => {
    loadAlerts(true)
  }, [filterSeverity, filterStatus, filterStartTime, filterEndTime])

  // 2. Periodic polling
  useEffect(() => {
    if (integrationStates?.correlation === false) return
    const pollInterval = setInterval(() => loadAlerts(false), 5000)
    return () => clearInterval(pollInterval)
  }, [integrationStates?.correlation, filterSeverity, filterStatus, filterStartTime, filterEndTime])

  // 3. WebSocket subscription
  useEffect(() => {
    if (integrationStates?.correlation === false) {
      setWsStatus('DISABLED')
      return
    }

    // Set up WebSocket connection targeting current hostname to bypass localhost/IPv6/IPv4 mismatch blocks
    let wsHost = window.location.hostname || '127.0.0.1'
    if (wsHost === 'localhost') {
      wsHost = '127.0.0.1'
    }
    const wsUrl = `ws://${wsHost}:8000/ws/alerts`
    let socket
    let reconnectTimeout

    const connectWebSocket = () => {
      console.log('Connecting to WebSocket alert stream...')
      socket = new WebSocket(wsUrl)

      socket.onopen = () => {
        console.log('WebSocket client successfully connected.')
        setWsStatus('connected')
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
            category: (newAlert.rule_id && typeof newAlert.rule_id === 'string' && newAlert.rule_id.includes('AUTH')) ? 'Authentication' : 
                      (newAlert.rule_id && typeof newAlert.rule_id === 'string' && newAlert.rule_id.includes('SQL')) ? 'Web Application' : 'System',
            severity: newAlert.severity || 'MEDIUM',
            status: newAlert.status || 'NEW'
          }

          // Prepend the new alert to show it instantly in the table
          setAlerts(prev => {
            if (prev.some(a => a.id === formatted.id)) return prev
            return [formatted, ...prev]
          })


        } catch (err) {
          console.error('WebSocket payload error:', err)
        }
      }

      socket.onclose = () => {
        console.warn('WebSocket connection lost. Retrying in 5 seconds...')
        setWsStatus('reconnecting')
        reconnectTimeout = setTimeout(connectWebSocket, 5000)
      }

      socket.onerror = (err) => {
        console.error('WebSocket encountered an error:', err)
        setWsStatus('error')
      }
    }

    connectWebSocket()

    return () => {
      if (socket) {
        socket.onclose = null
        socket.onerror = null
        socket.close()
      }
      if (reconnectTimeout) clearTimeout(reconnectTimeout)
    }
  }, [integrationStates?.correlation])

  const ensureNaiveDate = (isoString) => {
    if (!isoString) return new Date()
    let clean = isoString
    if (typeof clean === 'string') {
      clean = clean.replace('Z', '')
      if (clean.includes('+')) {
        clean = clean.split('+')[0]
      }
    }
    return new Date(clean)
  }

  const formatTime = (isoString) => {
    try {
      const date = ensureNaiveDate(isoString)
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true })
    } catch {
      return '10:24:32 AM'
    }
  }

  const formatDate = (isoString) => {
    try {
      const date = ensureNaiveDate(isoString)
      return date.toLocaleDateString()
    } catch {
      return ''
    }
  }

  const filteredAlerts = alerts.filter(alert => {
    // 1. Severity filter
    const alertSev = alert.severity ? alert.severity.toUpperCase() : 'MEDIUM'
    if (filterSeverity !== 'ALL' && alertSev !== filterSeverity) {
      return false
    }
    // 2. Category filter
    const alertCat = alert.category || 'System'
    if (filterCategory !== 'ALL' && alertCat !== filterCategory) {
      return false
    }
    // Status filter
    const alertStatusVal = alert.status ? alert.status.toUpperCase() : 'NEW'
    if (filterStatus !== 'ALL' && alertStatusVal !== filterStatus) {
      return false
    }
    // 3. Time filter (Client-side sync for WebSocket & Polling stability)
    if (filterStartTime) {
      const startMs = new Date(filterStartTime).getTime()
      const alertMs = ensureNaiveDate(alert.timestamp).getTime()
      if (!isNaN(startMs) && alertMs < startMs) {
        return false
      }
    }
    if (filterEndTime) {
      const endMs = new Date(filterEndTime).getTime()
      const alertMs = ensureNaiveDate(alert.timestamp).getTime()
      if (!isNaN(endMs) && alertMs > endMs) {
        return false
      }
    }
    // 4. Search query wildcard filter
    if (!matchesSearch(alert.title || '', searchQuery)) {
      return false
    }
    return true
  })

  const totalPages = Math.ceil(filteredAlerts.length / itemsPerPage)
  const indexOfLastItem = currentPage * itemsPerPage
  const indexOfFirstItem = indexOfLastItem - itemsPerPage
  const currentItems = filteredAlerts.slice(indexOfFirstItem, indexOfLastItem)

  return (
    <>


      {integrationStates?.correlation === false && (
        <div style={{
          backgroundColor: 'rgba(245, 158, 11, 0.12)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          borderRadius: '8px',
          padding: '14px 20px',
          marginBottom: '16px',
          color: '#f59e0b',
          fontSize: '0.85rem',
          fontWeight: 600,
          display: 'flex',
          alignItems: 'center',
          gap: '10px'
        }}>
          <span style={{ fontSize: '16px' }}>⚠️</span>
          <span>CORRELATION ENGINE OFFLINE (Detection rules disabled in Integrations Console. Threat analysis is paused.)</span>
        </div>
      )}

      <div className="alerts-grid-card glass-panel" style={{ opacity: integrationStates?.correlation === false ? 0.6 : 1 }}>
        <div className="card-title-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h3>Recent Alerts</h3>
            <span 
              className={`ws-status-badge ${wsStatus}`} 
              style={{
                fontSize: '0.7rem',
                padding: '3px 8px',
                borderRadius: '12px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                backgroundColor: wsStatus === 'connected' ? 'rgba(16, 185, 129, 0.1)' : 
                                 wsStatus === 'reconnecting' ? 'rgba(245, 158, 11, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                color: wsStatus === 'connected' ? '#10b981' : 
                       wsStatus === 'reconnecting' ? '#f59e0b' : '#ef4444',
                border: `1px solid ${
                  wsStatus === 'connected' ? 'rgba(16, 185, 129, 0.2)' : 
                  wsStatus === 'reconnecting' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(239, 68, 68, 0.2)'
                }`,
                fontFamily: 'monospace',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}
            >
              <span 
                style={{ 
                  width: '6px', 
                  height: '6px', 
                  borderRadius: '50%', 
                  backgroundColor: wsStatus === 'connected' ? '#10b981' : 
                                  wsStatus === 'reconnecting' ? '#f59e0b' : '#ef4444',
                  boxShadow: wsStatus === 'connected' ? '0 0 8px #10b981' : 
                             wsStatus === 'reconnecting' ? '0 0 8px #f59e0b' : '0 0 8px #ef4444'
                }}
              ></span>
              {wsStatus}
            </span>
          </div>
          <div className="grid-controls" style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>Start:</span>
              <input
                type="datetime-local"
                value={filterStartTime}
                onChange={(e) => setFilterStartTime(e.target.value)}
                style={{
                  backgroundColor: 'rgba(7, 10, 19, 0.6)',
                  border: '1px solid hsl(var(--border-color))',
                  borderRadius: '6px',
                  padding: '4px 8px',
                  color: '#fff',
                  fontSize: '0.75rem',
                  outline: 'none',
                  cursor: 'pointer'
                }}
                disabled={integrationStates?.correlation === false}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-secondary))' }}>End:</span>
              <input
                type="datetime-local"
                value={filterEndTime}
                onChange={(e) => setFilterEndTime(e.target.value)}
                style={{
                  backgroundColor: 'rgba(7, 10, 19, 0.6)',
                  border: '1px solid hsl(var(--border-color))',
                  borderRadius: '6px',
                  padding: '4px 8px',
                  color: '#fff',
                  fontSize: '0.75rem',
                  outline: 'none',
                  cursor: 'pointer'
                }}
                disabled={integrationStates?.correlation === false}
              />
            </div>

            <button
              onClick={downloadAlertsCSV}
              disabled={!filterStartTime && !filterEndTime}
              className="ai-gradient-btn"
              style={{
                padding: '4px 10px',
                fontSize: '0.75rem',
                borderRadius: '6px',
                cursor: (!filterStartTime && !filterEndTime) ? 'not-allowed' : 'pointer',
                opacity: (!filterStartTime && !filterEndTime) ? 0.4 : 1,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                fontWeight: 600,
                border: 'none',
                height: '28px'
              }}
              title={(!filterStartTime && !filterEndTime) ? "Apply a time filter to enable download" : "Download filtered alerts as CSV"}
            >
              <span>📥</span>
              <span>Export CSV</span>
            </button>

            <button className="grid-refresh-btn" onClick={() => loadAlerts(true)} disabled={integrationStates?.correlation === false} style={{ height: '28px', padding: '4px 12px', fontSize: '0.75rem' }}>Refresh Feed</button>
          </div>
        </div>


        {/* Filters and Search Bar */}
        <div className="alerts-filter-bar" style={{ display: 'flex', gap: '16px', padding: '16px 20px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: '200px', position: 'relative' }}>
            <input
              type="text"
              placeholder="Search alert name (e.g. *login*, SQL*)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
              style={{ paddingLeft: '16px', borderRadius: '8px' }}
              disabled={integrationStates?.correlation === false}
            />
          </div>
          
          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>Severity:</span>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                style={{
                  backgroundColor: 'rgba(7, 10, 19, 0.6)',
                  border: '1px solid hsl(var(--border-color))',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.8rem',
                  outline: 'none',
                  cursor: 'pointer'
                }}
                disabled={integrationStates?.correlation === false}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>Category:</span>
              <select
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
                style={{
                  backgroundColor: 'rgba(7, 10, 19, 0.6)',
                  border: '1px solid hsl(var(--border-color))',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.8rem',
                  outline: 'none',
                  cursor: 'pointer'
                }}
                disabled={integrationStates?.correlation === false}
              >
                <option value="ALL">All Categories</option>
                <option value="Authentication">Authentication</option>
                <option value="Web Application">Web Application</option>
                <option value="System">System</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>Status:</span>
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                style={{
                  backgroundColor: 'rgba(7, 10, 19, 0.6)',
                  border: '1px solid hsl(var(--border-color))',
                  borderRadius: '6px',
                  padding: '8px 12px',
                  color: '#fff',
                  fontSize: '0.8rem',
                  outline: 'none',
                  cursor: 'pointer'
                }}
                disabled={integrationStates?.correlation === false}
              >
                <option value="ALL">All Statuses</option>
                <option value="NEW">New</option>
                <option value="ACKNOWLEDGED">Acknowledged</option>
                <option value="RESOLVED">Resolved</option>
              </select>
            </div>
            <button
              onClick={() => {
                setSearchQuery('')
                setFilterSeverity('ALL')
                setFilterCategory('ALL')
                setFilterStatus('ALL')
                setFilterStartTime('')
                setFilterEndTime('')
              }}
              style={{
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                borderRadius: '6px',
                padding: '8px 12px',
                color: '#ef4444',
                fontSize: '0.8rem',
                cursor: 'pointer',
                outline: 'none',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px'
              }}
              disabled={integrationStates?.correlation === false}
            >
              <span>✕</span>
              <span>Clear Filters</span>
            </button>
          </div>
        </div>

        <div className="table-responsive">
          {loading && alerts.length === 0 ? (
            <div className="grid-loading">{integrationStates?.correlation === false ? 'No alerts to display (correlation engine disconnected)' : 'Loading alerts database...'}</div>
          ) : (
            <table className="sources-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Alert Name</th>
                  <th>Source</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {currentItems.map((alert) => {
                  const sev = alert.severity ? alert.severity.toLowerCase() : 'medium'
                  const statusLower = alert.status ? alert.status.toLowerCase() : 'new'
                  
                  return (
                    <tr key={alert.id} className={`alert-row severity-${sev}`}>
                      <td className="time-cell" style={{ whiteSpace: 'nowrap' }}>{formatDate(alert.timestamp)}</td>
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
                      <td>
                        <select
                          className={`status-select status-${statusLower}`}
                          value={alert.status}
                          onChange={(e) => handleStatusChange(alert.id, e.target.value)}
                          disabled={integrationStates?.correlation === false}
                        >
                          <option value="NEW">New</option>
                          <option value="ACKNOWLEDGED">Acknowledged</option>
                          <option value="RESOLVED">Resolved</option>
                        </select>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          onClick={() => handleCreateCase(alert)}
                          className="ai-gradient-btn"
                          style={{
                            padding: '5px 10px',
                            fontSize: '0.75rem',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            fontWeight: 600
                          }}
                          disabled={integrationStates?.correlation === false}
                          title="Escalate and initialize incident case ticket"
                        >
                          <span>📁</span>
                          <span>Open Case</span>
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
          {totalPages > 1 && (
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '16px 20px',
              borderTop: '1px solid rgba(255, 255, 255, 0.05)',
              background: 'rgba(255, 255, 255, 0.01)',
              flexWrap: 'wrap',
              gap: '12px'
            }}>
              <span style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))' }}>
                Showing {indexOfFirstItem + 1}-{Math.min(indexOfLastItem, filteredAlerts.length)} of {filteredAlerts.length} alerts
              </span>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <button
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  style={{
                    backgroundColor: 'rgba(7, 10, 19, 0.6)',
                    border: '1px solid hsl(var(--border-color))',
                    borderRadius: '6px',
                    padding: '6px 12px',
                    color: '#fff',
                    fontSize: '0.8rem',
                    cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                    opacity: currentPage === 1 ? 0.4 : 1
                  }}
                >
                  Previous
                </button>
                <span style={{ fontSize: '0.8rem', color: '#fff', padding: '0 8px' }}>
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  style={{
                    backgroundColor: 'rgba(7, 10, 19, 0.6)',
                    border: '1px solid hsl(var(--border-color))',
                    borderRadius: '6px',
                    padding: '6px 12px',
                    color: '#fff',
                    fontSize: '0.8rem',
                    cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                    opacity: currentPage === totalPages ? 0.4 : 1
                  }}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {selectedAlertId && (
        <AIPlaybookDrawer alertId={selectedAlertId} onClose={() => setSelectedAlertId(null)} integrationStates={integrationStates} />
      )}
    </>
  )
}

export default AlertsGrid
