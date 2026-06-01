import React, { useState, useEffect } from 'react'
import { FolderLock, Plus, Edit, User, ShieldAlert, CheckCircle, Clock } from 'lucide-react'
import { getCases, createCase, updateCase } from '../services/api'

const MOCK_CASES = [
  {
    id: 1,
    title: 'Potential SSH Brute Force Incident',
    severity: 'HIGH',
    status: 'OPEN',
    assigned_to: 'John Doe',
    created_at: new Date().toISOString()
  }
]

function CaseManagement() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreateForm, setShowCreateForm] = useState(false)
  
  // Form State
  const [newTitle, setNewTitle] = useState('')
  const [newSeverity, setNewSeverity] = useState('HIGH')
  const [newAssignee, setNewAssignee] = useState('Unassigned')

  const loadCases = async () => {
    setLoading(true)
    const data = await getCases()
    if (data && data.length > 0) {
      setCases(data)
    } else {
      setCases(MOCK_CASES)
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

  const handleFieldUpdate = async (caseId, field, value) => {
    const updatePayload = {
      [field]: value
    }
    
    // Update local state first for instant responsiveness
    setCases(prev => prev.map(c => c.id === caseId ? { ...c, [field]: value } : c))

    // Call API (ignores 101/mock case updates to server)
    if (caseId > 1) {
      await updateCase(caseId, updatePayload)
    }
  }

  const formatTime = (isoString) => {
    try {
      const date = new Date(isoString)
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    } catch {
      return '06/15/2026 10:24 AM'
    }
  }

  return (
    <div className="case-management-layout">
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
            Case Management & Tickets
          </h1>
          <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
            Investigate ongoing security events and assign incidents to security responders.
          </span>
        </div>
        <button className="ai-gradient-btn ask-ai-btn" onClick={() => setShowCreateForm(!showCreateForm)}>
          <Plus size={16} />
          <span>New Case File</span>
        </button>
      </div>

      {/* New Case Creator Panel */}
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
              <input 
                type="text" 
                id="case-assignee"
                className="search-input" 
                placeholder="Name"
                value={newAssignee}
                onChange={(e) => setNewAssignee(e.target.value)}
                style={{ borderRadius: '8px', padding: '10px 14px' }}
              />
            </div>

            <button type="submit" className="ai-gradient-btn run-simulation-btn" style={{ height: '40px', padding: '0 24px' }}>
              Create Ticket
            </button>
          </form>
        </div>
      )}

      {/* Cases Listing Table */}
      <div className="alerts-grid-card glass-panel">
        <div className="table-responsive">
          {loading && cases.length === 0 ? (
            <div className="grid-loading">Loading incident cases database...</div>
          ) : (
            <table className="sources-table">
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>Incident Case Details</th>
                  <th>Created Date</th>
                  <th>Severity</th>
                  <th>Assignee</th>
                  <th style={{ textAlign: 'right' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((item) => {
                  const sev = item.severity ? item.severity.toLowerCase() : 'medium'
                  const statusLower = item.status ? item.status.toLowerCase() : 'open'
                  
                  return (
                    <tr key={item.id} className="alert-row">
                      <td className="time-cell" style={{ fontWeight: '700' }}>#{item.id}</td>
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
                            background: 'transparent',
                            border: '1px solid rgba(255,255,255,0.08)',
                            color: `var(--sev-${sev})`,
                            fontWeight: '700',
                            borderRadius: '4px',
                            padding: '2px 6px'
                          }}
                        >
                          <option value="LOW">LOW</option>
                          <option value="MEDIUM">MEDIUM</option>
                          <option value="HIGH">HIGH</option>
                          <option value="CRITICAL">CRITICAL</option>
                        </select>
                      </td>
                      <td>
                        <input
                          type="text"
                          className="search-input"
                          value={item.assigned_to || ''}
                          onChange={(e) => handleFieldUpdate(item.id, 'assigned_to', e.target.value)}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                            color: 'hsl(var(--text-secondary))',
                            borderRadius: '0',
                            padding: '4px 0',
                            fontSize: '0.85rem',
                            maxWidth: '120px'
                          }}
                        />
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <select
                          className={`status-select status-${statusLower === 'open' ? 'new' : statusLower === 'in_progress' ? 'acknowledged' : 'resolved'}`}
                          value={item.status}
                          onChange={(e) => handleFieldUpdate(item.id, 'status', e.target.value)}
                        >
                          <option value="OPEN">Open</option>
                          <option value="IN_PROGRESS">In Progress</option>
                          <option value="CLOSED">Closed</option>
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
    </div>
  )
}

export default CaseManagement
