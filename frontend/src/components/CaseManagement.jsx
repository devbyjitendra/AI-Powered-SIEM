import React, { useState, useEffect } from 'react'
import { FolderLock, Plus, Edit, User, ShieldAlert, CheckCircle, Clock, Trash2, FileText } from 'lucide-react'
import { getCases, createCase, updateCase, deleteCase } from '../services/api'

const ASSIGNEES = ["Unassigned", "alice.smith", "john.doe", "bob.johnson", "charlie.brown", "david.miller"]

// Helper to convert wildcard patterns (e.g. *SSH*, Brute*) to regular expressions
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

function CaseManagement({ integrationStates, onTransferToReports }) {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [filterSeverity, setFilterSeverity] = useState('ALL')
  const [filterStatus, setFilterStatus] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const itemsPerPage = 50
  
  // Closed History & PDF Report Builder States
  const [showClosedHistory, setShowClosedHistory] = useState(false)
  const [activeReportCase, setActiveReportCase] = useState(null)
  const [closureRootCause, setClosureRootCause] = useState('Credential Abuse / Brute Force')
  const [closureResolution, setClosureResolution] = useState('Enforced lockout policies, rotation of credentials, and blocked attacking IP on the perimeter router.')
  const [closureLessons, setClosureLessons] = useState('Enforce strict SSH key access, deploy rate limiting, and review user logs on credential changes.')
  const [closureStatus, setClosureStatus] = useState('Fully Mitigated & Resolved')
  const [closureApprovedBy, setClosureApprovedBy] = useState('alice.smith')
  const [pdfLoading, setPdfLoading] = useState(false)

  // Reset to first page when search filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [filterSeverity, filterStatus, searchQuery, showClosedHistory])

  // Dynamically load html2pdf from CDN
  useEffect(() => {
    if (!window.html2pdf) {
      console.log('Loading html2pdf for case closures...')
      const script = document.createElement('script')
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js'
      script.async = true
      document.body.appendChild(script)
    }
  }, [])
  
  // Form State
  const [newTitle, setNewTitle] = useState('')
  const [newSeverity, setNewSeverity] = useState('HIGH')
  const [newAssignee, setNewAssignee] = useState('Unassigned')

  const loadCases = async () => {
    setLoading(true)
    const data = await getCases()
    if (data) {
      setCases(data)
    }
    setLoading(false)
  }

  useEffect(() => {
    loadCases()
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!newTitle.trim()) return

    const payload = {
      title: newTitle,
      severity: newSeverity,
      assigned_to: newAssignee
    }

    const created = await createCase(payload)
    if (created) {
      loadCases()
      setNewTitle('')
      setNewSeverity('HIGH')
      setNewAssignee('Unassigned')
      setShowCreateForm(false)
    } else {
      // Fallback update state locally for demo if API fails/offline
      const mockNew = {
        id: cases.length + 1,
        title: newTitle,
        severity: newSeverity,
        status: 'OPEN',
        assigned_to: newAssignee,
        created_at: new Date().toISOString()
      }
      setCases(prev => [mockNew, ...prev])
      setNewTitle('')
      setShowCreateForm(false)
    }
  }

  const handleDeleteCase = async (caseId) => {
    if (window.confirm("Are you sure you want to delete this incident case ticket?")) {
      const success = await deleteCase(caseId)
      if (success) {
        setCases(prev => prev.filter(c => c.id !== caseId))
      } else {
        // Fallback update state locally for demo
        setCases(prev => prev.filter(c => c.id !== caseId))
      }
    }
  }

  const handleFieldUpdate = async (caseId, field, value) => {
    const updatePayload = {
      [field]: value
    }
    
    // Update local state first for instant responsiveness
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, [field]: value } : c))

    // Call API (ignores mock case updates to server if needed, but let's always try)
    await updateCase(caseId, updatePayload)
  }

  const formatTime = (isoString) => {
    try {
      const date = new Date(isoString)
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    } catch {
      return '06/15/2026 10:24 AM'
    }
  }

  const filteredCases = cases.filter(item => {
    const statusUpper = (item.status || '').toUpperCase()
    if (showClosedHistory) {
      if (statusUpper !== 'CLOSED') {
        return false
      }
    } else {
      if (statusUpper === 'CLOSED') {
        return false
      }
    }
    if (filterSeverity !== 'ALL' && (item.severity || '').toUpperCase() !== filterSeverity) {
      return false
    }
    if (!showClosedHistory && filterStatus !== 'ALL' && statusUpper !== filterStatus) {
      return false
    }
    if (!matchesSearch(item.title, searchQuery)) {
      return false
    }
    return true
  })

  const totalPages = Math.ceil(filteredCases.length / itemsPerPage)
  const indexOfLastItem = currentPage * itemsPerPage
  const indexOfFirstItem = indexOfLastItem - itemsPerPage
  const currentItems = filteredCases.slice(indexOfFirstItem, indexOfLastItem)

  const isDisconnected = integrationStates?.cases === false

  return (
    <div className="case-management-layout" style={{ position: 'relative', minHeight: '400px' }}>
      {isDisconnected && (
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(7, 10, 19, 0.65)',
          backdropFilter: 'blur(10px)',
          zIndex: 100,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '12px',
          border: '1px solid rgba(255, 255, 255, 0.05)',
          textAlign: 'center',
          padding: '40px'
        }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔒</div>
          <h2 style={{ color: '#fff', fontSize: '1.4rem', fontWeight: 700, margin: '0 0 10px 0', fontFamily: "'Outfit', sans-serif" }}>
            Case Database Disconnected
          </h2>
          <p style={{ color: 'hsl(var(--text-secondary))', fontSize: '0.9rem', maxWidth: '450px', lineHeight: 1.5, margin: 0 }}>
            Re-enable Case Management Sync in the <strong style={{ color: 'hsl(var(--color-ai-cyan))' }}>Integrations Command Console</strong> to view, edit, or triage operational incident tickets.
          </p>
        </div>
      )}

      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', filter: isDisconnected ? 'blur(3px)' : 'none' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
            Case Management & Tickets
          </h1>
          <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
            Investigate ongoing security events and assign incidents to security responders.
          </span>
        </div>
        <button className="ai-gradient-btn ask-ai-btn" onClick={() => setShowCreateForm(!showCreateForm)} disabled={isDisconnected}>
          <Plus size={16} />
          <span>New Case File</span>
        </button>
      </div>

      {/* New Case Creator Panel */}
      <div style={{ filter: isDisconnected ? 'blur(4px)' : 'none', pointerEvents: isDisconnected ? 'none' : 'auto', transition: 'all 0.3s ease' }}>
        {showCreateForm && (
          <div className="glass-panel simulator-card" style={{ marginBottom: '24px', padding: '20px' }}>
          <h3 className="card-title" style={{ margin: 0, marginBottom: '16px' }}>
            <FolderLock size={18} className="card-icon" /> Initialize Case File
          </h3>
          <form onSubmit={handleSubmit} className="settings-form" style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr auto', gap: '16px', alignItems: 'end' }}>
            <div className="form-group">
              <label className="form-label" htmlFor="case-title">Incident Title / Summary</label>
              <input 
                type="text" 
                id="case-title"
                className="search-input" 
                placeholder="e.g. Target User root Brute Force from Russian IP"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                style={{ borderRadius: '8px', padding: '10px 14px' }}
                required
              />
            </div>
            
            <div className="form-group">
              <label className="form-label" htmlFor="case-severity">Initial Severity</label>
              <select 
                id="case-severity"
                className="chart-select" 
                value={newSeverity} 
                onChange={(e) => setNewSeverity(e.target.value)}
                style={{ height: '40px', background: 'hsl(var(--bg-dark))', border: '1px solid hsl(var(--border-color))', borderRadius: '8px' }}
              >
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="case-assignee">Assign Security Analyst</label>
              <select 
                id="case-assignee"
                className="chart-select" 
                value={newAssignee} 
                onChange={(e) => setNewAssignee(e.target.value)}
                style={{ height: '40px', background: 'hsl(var(--bg-dark))', border: '1px solid hsl(var(--border-color))', borderRadius: '8px', padding: '0 12px' }}
              >
                {ASSIGNEES.map(name => (
                  <option key={name} value={name}>{name}</option>
                ))}
              </select>
            </div>

            <button type="submit" className="ai-gradient-btn run-simulation-btn" style={{ height: '40px', padding: '0 24px' }}>
              Create Ticket
            </button>
          </form>
        </div>
      )}

      {/* Cases Listing Table */}
      <div className="alerts-grid-card glass-panel">
        {/* Active vs Closed Tabs */}
        <div style={{ display: 'flex', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', background: 'rgba(255, 255, 255, 0.02)' }}>
          <button 
            onClick={() => setShowClosedHistory(false)}
            style={{
              padding: '14px 24px',
              background: 'none',
              border: 'none',
              borderBottom: !showClosedHistory ? '2px solid hsl(var(--color-ai-cyan))' : '2px solid transparent',
              color: !showClosedHistory ? '#fff' : 'hsl(var(--text-secondary))',
              fontWeight: '600',
              cursor: 'pointer',
              fontSize: '0.85rem',
              transition: 'all 0.2s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            <span>Active Cases</span>
            <span style={{ 
              fontSize: '0.75rem', 
              background: !showClosedHistory ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255,255,255,0.05)', 
              color: !showClosedHistory ? 'hsl(var(--color-ai-cyan))' : 'inherit',
              padding: '2px 8px', 
              borderRadius: '12px' 
            }}>
              {cases.filter(c => (c.status || '').toUpperCase() !== 'CLOSED').length}
            </span>
          </button>
          <button 
            onClick={() => setShowClosedHistory(true)}
            style={{
              padding: '14px 24px',
              background: 'none',
              border: 'none',
              borderBottom: showClosedHistory ? '2px solid hsl(var(--color-ai-cyan))' : '2px solid transparent',
              color: showClosedHistory ? '#fff' : 'hsl(var(--text-secondary))',
              fontWeight: '600',
              cursor: 'pointer',
              fontSize: '0.85rem',
              transition: 'all 0.2s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            <span>Closed History</span>
            <span style={{ 
              fontSize: '0.75rem', 
              background: showClosedHistory ? 'rgba(0, 242, 254, 0.15)' : 'rgba(255,255,255,0.05)', 
              color: showClosedHistory ? 'hsl(var(--color-ai-cyan))' : 'inherit',
              padding: '2px 8px', 
              borderRadius: '12px' 
            }}>
              {cases.filter(c => (c.status || '').toUpperCase() === 'CLOSED').length}
            </span>
          </button>
        </div>

        {/* Filters and Search Bar */}
        <div className="cases-filter-bar" style={{ display: 'flex', gap: '16px', padding: '16px 20px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: '200px', position: 'relative' }}>
            <input
              type="text"
              placeholder="Search case name (e.g. *SSH*, Brute*)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
              style={{ paddingLeft: '16px', borderRadius: '8px' }}
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
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {!showClosedHistory && (
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
                >
                  <option value="ALL">All Statuses</option>
                  <option value="OPEN">Open</option>
                  <option value="IN_PROGRESS">In Progress</option>
                  <option value="CLOSED">Closed</option>
                </select>
              </div>
            )}
          </div>
        </div>

        <div className="table-responsive">
          {loading && cases.length === 0 ? (
            <div className="grid-loading">Loading incident cases database...</div>
          ) : (
            <table className="sources-table">
              <thead>
                <tr>
                  <th>S.N.</th>
                  <th>Incident Case Details</th>
                  <th>Created Date</th>
                  <th>Severity</th>
                  <th>Assignee</th>
                  <th>Status</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {currentItems.map((item, idx) => {
                  const sev = item.severity ? item.severity.toLowerCase() : 'medium'
                  const statusLower = item.status ? item.status.toLowerCase() : 'open'
                  
                  return (
                    <tr key={item.id} className="alert-row">
                      <td className="time-cell" style={{ fontWeight: '700' }}>{indexOfFirstItem + idx + 1}</td>
                      <td className="alert-title-cell" style={{ color: '#fff', fontWeight: '600' }}>
                        <span>{item.title}</span>
                      </td>
                      <td className="source-cell">{formatTime(item.created_at)}</td>
                      <td>
                        <select
                          className="chart-select"
                          value={item.severity}
                          onChange={(e) => handleFieldUpdate(item.id, 'severity', e.target.value)}
                          style={{
                            background: 'rgba(7, 10, 19, 0.8)',
                            border: '1px solid rgba(255,255,255,0.08)',
                            color: `var(--sev-${sev})`,
                            fontWeight: '700',
                            borderRadius: '4px',
                            padding: '2px 6px',
                            cursor: 'pointer'
                          }}
                        >
                          <option value="LOW" style={{ backgroundColor: '#070a13', color: '#fff' }}>LOW</option>
                          <option value="MEDIUM" style={{ backgroundColor: '#070a13', color: '#fff' }}>MEDIUM</option>
                          <option value="HIGH" style={{ backgroundColor: '#070a13', color: '#fff' }}>HIGH</option>
                          <option value="CRITICAL" style={{ backgroundColor: '#070a13', color: '#fff' }}>CRITICAL</option>
                        </select>
                      </td>
                      <td>
                        <select
                          className="chart-select"
                          value={item.assigned_to || 'Unassigned'}
                          onChange={(e) => handleFieldUpdate(item.id, 'assigned_to', e.target.value)}
                          disabled={showClosedHistory}
                          style={{
                            background: 'rgba(7, 10, 19, 0.8)',
                            border: '1px solid rgba(255,255,255,0.08)',
                            color: 'hsl(var(--text-secondary))',
                            borderRadius: '4px',
                            padding: '4px 8px',
                            cursor: showClosedHistory ? 'not-allowed' : 'pointer',
                            opacity: showClosedHistory ? 0.6 : 1,
                            fontSize: '0.85rem',
                            width: '100%',
                            maxWidth: '145px'
                          }}
                        >
                          {ASSIGNEES.map(name => (
                            <option key={name} value={name} style={{ backgroundColor: '#070a13', color: '#fff' }}>{name}</option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <select
                          className={`status-select status-${statusLower === 'open' ? 'new' : statusLower === 'in_progress' ? 'acknowledged' : 'resolved'}`}
                          value={item.status}
                          onChange={(e) => handleFieldUpdate(item.id, 'status', e.target.value)}
                          disabled={showClosedHistory}
                          style={{ 
                            cursor: showClosedHistory ? 'not-allowed' : 'pointer',
                            opacity: showClosedHistory ? 0.6 : 1 
                          }}
                        >
                          {statusLower === 'in_progress' ? (
                            <>
                              <option value="IN_PROGRESS" style={{ backgroundColor: '#070a13', color: '#fff' }}>In Progress</option>
                              <option value="CLOSED" style={{ backgroundColor: '#070a13', color: '#fff' }}>Closed</option>
                            </>
                          ) : (
                            <>
                              <option value="OPEN" style={{ backgroundColor: '#070a13', color: '#fff' }}>Open</option>
                              <option value="IN_PROGRESS" style={{ backgroundColor: '#070a13', color: '#fff' }}>In Progress</option>
                              <option value="CLOSED" style={{ backgroundColor: '#070a13', color: '#fff' }}>Closed</option>
                            </>
                          )}
                        </select>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', alignItems: 'center' }}>
                          {statusLower === 'closed' && (
                            <button
                              onClick={() => onTransferToReports && onTransferToReports(item)}
                              style={{
                                background: 'none',
                                border: 'none',
                                color: 'rgba(0, 242, 254, 0.4)',
                                cursor: 'pointer',
                                padding: '6px',
                                borderRadius: '4px',
                                transition: 'all 0.2s ease',
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center'
                              }}
                              onMouseOver={(e) => {
                                e.currentTarget.style.color = 'hsl(var(--color-ai-cyan))'
                                e.currentTarget.style.background = 'rgba(0, 242, 254, 0.1)'
                              }}
                              onMouseOut={(e) => {
                                e.currentTarget.style.color = 'rgba(0, 242, 254, 0.4)'
                                e.currentTarget.style.background = 'none'
                              }}
                              title="Transfer Case to Report Generator"
                            >
                              <FileText size={14} />
                            </button>
                          )}
                          <button
                            onClick={() => handleDeleteCase(item.id)}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: 'rgba(255, 255, 255, 0.2)',
                              cursor: 'pointer',
                              padding: '6px',
                              borderRadius: '4px',
                              transition: 'all 0.2s ease',
                              display: 'inline-flex',
                              alignItems: 'center',
                              justifyContent: 'center'
                            }}
                            onMouseOver={(e) => {
                              e.currentTarget.style.color = 'hsl(var(--sev-critical))'
                              e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'
                            }}
                            onMouseOut={(e) => {
                              e.currentTarget.style.color = 'rgba(255, 255, 255, 0.2)'
                              e.currentTarget.style.background = 'none'
                            }}
                            title="Delete case file"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
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
                Showing {indexOfFirstItem + 1}-{Math.min(indexOfLastItem, filteredCases.length)} of {filteredCases.length} cases
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
    </div>
  </div>
)
}

export default CaseManagement
