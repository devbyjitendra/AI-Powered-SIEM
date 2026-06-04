import React, { useState, useEffect, useRef } from 'react'
import { FileText, Download, Cpu, ToggleLeft, ToggleRight, Check, Link, ExternalLink, Zap, Layers, RefreshCw, ShieldAlert, Calendar, User, Eye } from 'lucide-react'
import { getAlerts, getDashboardStats } from '../services/api'

function SecurityWorkspace({ tabName, integrationStates, setIntegrationStates, transferCaseData, clearTransferCaseData }) {
  const [copiedIndex, setCopiedIndex] = useState(null)
  
  // Automation Toggles State
  const [playbooks, setPlaybooks] = useState([
    { name: 'IP Auto-Block Firewall Mitigation', trigger: 'Brute Force Alert', active: true, desc: 'Instantly injects an iptables drop rule for threat IPs breaching auth thresholds.' },
    { name: 'Slack Incident Coordinator Broadcast', trigger: 'Critical Severity Match', active: true, desc: 'Pushes high-priority payload descriptions into #security-incidents channel.' },
    { name: 'AWS Host Isolation (Sandbox)', trigger: 'SQL Injection / WAF signature', active: false, desc: 'Applies AWS Security Group blocking outbound traffic on infected web servers.' }
  ])

  // Integrations State
  const [integrations, setIntegrations] = useState([
    { 
      name: 'Security Log Simulator Daemon', 
      category: 'Log Ingestion Source', 
      connected: true, 
      status: 'Active Ingesting',
      desc: 'Generates benign events and attack signatures to test pipeline resilience and verify dashboard counters.',
      eps: 1,
      latency: '0.2s',
      importance: 'Streams live simulated authentication logs, firewall blocks, web hits, and malware activities in real-time.'
    },
    { 
      name: 'Gemini AI Analyst Agent', 
      category: 'AI Security Assistance', 
      connected: true, 
      status: 'Active Syncing',
      desc: 'Powers the interactive Ask AI chat drawer and generates automated threat response playbooks.',
      eps: 2,
      latency: '1.4s',
      importance: 'Performs on-demand analysis of triggered alerts, drafting custom mitigation steps and firewalls.'
    },
    { 
      name: 'Threat Correlation Engine', 
      category: 'Signature Match Rules', 
      connected: true, 
      status: 'Active Filtering',
      desc: 'Compares incoming logs against active database rules to detect SQLi, XSS, and Brute Force patterns.',
      eps: 25,
      latency: '0.1s',
      importance: 'Identifies attack paths instantly, saving alerts and dispatching WebSockets to the Alerts grid.'
    },
    { 
      name: 'Case Management Database', 
      category: 'Operational Incidents Sync', 
      connected: true, 
      status: 'Active Syncing',
      desc: 'Syncs critical alerts and auto-creates incident tickets inside the Case Management SQLite database tables.',
      eps: 1,
      latency: '0.5s',
      importance: 'Organizes critical severity alerts into structured investigation cases for tracking and resolution.'
    }
  ])

  // Report Builder Form State
  const [reportTitle, setReportTitle] = useState('SIEM Security Incident Summary')
  const [reportType, setReportType] = useState('Incident Summary')
  const [preparedBy, setPreparedBy] = useState('Security Operations Center')
  const [startDate, setStartDate] = useState('2026-06-15')
  const [endDate, setEndDate] = useState('2026-06-20')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [execSummary, setExecSummary] = useState('This document provides an audit summary of ingested security logs and matching rules for the specified timeframe. Several attack patterns including SQLi, Brute Force, and Trojan activities were detected and mitigated successfully by the correlation engine.')
  const [includeAlerts, setIncludeAlerts] = useState(true)
  const [includeStats, setIncludeStats] = useState(true)
  const [includeRecommendations, setIncludeRecommendations] = useState(true)
  const [recommendations, setRecommendations] = useState("1. Enforce multi-factor authentication across all active SSH gateway nodes.\n2. Implement firewall rate limits for repeatedly flagged brute-force IPs.\n3. Inspect antivirus logs for Trojan reverse shell payloads on host 10.0.0.15.")
  
  // Case Closure Specific States
  const [closureRootCause, setClosureRootCause] = useState('Credential Abuse / Brute Force')
  const [closureResolution, setClosureResolution] = useState('Enforced lockout policies, rotation of credentials, and blocked attacking IP on the perimeter router.')
  const [closureLessons, setClosureLessons] = useState('Enforce strict SSH key access, deploy rate limiting, and review user logs on credential changes.')
  const [closureStatus, setClosureStatus] = useState('Fully Mitigated & Resolved')
  const [closureApprovedBy, setClosureApprovedBy] = useState('alice.smith')
  const [caseSeverity, setCaseSeverity] = useState('HIGH')
  const [caseCreatedAt, setCaseCreatedAt] = useState('')

  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [caseAlerts, setCaseAlerts] = useState([])

  // Prefill hook when a case details transfer happens
  useEffect(() => {
    if (tabName === 'Reports' && transferCaseData) {
      setReportTitle(`Case Closure Report: ${transferCaseData.title}`)
      setReportType('Case Closure Report')
      setPreparedBy(transferCaseData.assigned_to && transferCaseData.assigned_to !== 'Unassigned' ? transferCaseData.assigned_to : 'alice.smith')
      if (transferCaseData.alerts) {
        setCaseAlerts(transferCaseData.alerts)
      } else {
        setCaseAlerts([])
      }
      setCaseSeverity(transferCaseData.severity || 'HIGH')
      setCaseCreatedAt(transferCaseData.created_at || new Date().toISOString())
      
      const titleLower = (transferCaseData.title || '').toLowerCase()
      if (titleLower.includes('ssh') || titleLower.includes('brute') || titleLower.includes('credential')) {
        setClosureRootCause('Credential Abuse / SSH Brute Force Attack')
        setClosureResolution('Enforced SSH gateway rate limiting, revoked unauthorized session tokens, rotated compromised credentials, and blacklisted attacker source IP.')
        setClosureLessons('Require certificate-based SSH keys instead of passwords, enforce multi-factor authentication, and monitor failed login spikes.')
      } else if (titleLower.includes('sql') || titleLower.includes('injection') || titleLower.includes('web')) {
        setClosureRootCause('SQL Injection Vulnerability Exploitation Attempt')
        setClosureResolution('Implemented prepared statement parameterization on the affected API routes and updated WAF firewall rule blockings.')
        setClosureLessons('Ensure developer secure coding education, carry out automated static application security testing, and maintain WAF signature updates.')
      } else if (titleLower.includes('trojan') || titleLower.includes('malware') || titleLower.includes('shell')) {
        setClosureRootCause('Trojan Horse Execution & Reverse Command Shell')
        setClosureResolution('Quarantined host instance, terminated execution process, deleted malicious script binary, and refreshed host file structures.')
        setClosureLessons('Restrict user administration privileges, enforce application whitelisting, and maintain real-time host antivirus scanning.')
      } else {
        setClosureRootCause('Unusual Access Patterns / Compliance Anomaly')
        setClosureResolution('Triaged audit log sequence, verified authorization permissions, and closed ticket after verifying system integrity.')
        setClosureLessons('Tune correlation rules to improve signal-to-noise ratio and optimize rule scopes.')
      }
      
      setClosureApprovedBy(transferCaseData.assigned_to && transferCaseData.assigned_to !== 'Unassigned' ? transferCaseData.assigned_to : 'alice.smith')
      
      if (clearTransferCaseData) {
        clearTransferCaseData()
      }
    }
  }, [tabName, transferCaseData])

  // Dynamically load html2pdf from CDN
  useEffect(() => {
    if (tabName === 'Reports') {
      if (!window.html2pdf) {
        console.log('Loading html2pdf library...')
        const script = document.createElement('script')
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js'
        script.async = true
        document.body.appendChild(script)
      }
      
      // Load real DB data for report rendering
      async function loadData() {
        try {
          const alertData = await getAlerts()
          if (alertData) setAlerts(alertData)
          
          const statData = await getDashboardStats()
          if (statData) setStats(statData)
        } catch (err) {
          console.error('Error loading report database sources:', err)
        }
      }
      loadData()
    }
  }, [tabName])

  const togglePlaybook = (idx) => {
    setPlaybooks(prev => prev.map((p, i) => i === idx ? { ...p, active: !p.active } : p))
  }

  const toggleIntegration = (idx) => {
    const keys = ['simulator', 'gemini', 'correlation', 'cases']
    const key = keys[idx]
    if (key && setIntegrationStates) {
      setIntegrationStates(prev => ({
        ...prev,
        [key]: !prev[key]
      }))
    }
  }

  // Filter alerts matching the form criteria
  const filteredReportAlerts = alerts.filter(a => {
    if (severityFilter !== 'ALL' && (a.severity || '').toUpperCase() !== severityFilter) {
      return false
    }
    return true
  }).slice(0, 40) // Limit to 40 alerts to allow multi-page overflow when needed

  const handleDownloadPDF = () => {
    if (!window.html2pdf) {
      alert('The PDF generation library is still loading from CDN. Please wait a moment and try again.')
      return
    }
    setPdfLoading(true)
    const element = document.getElementById('report-pdf-sheet')
    const opt = {
      margin: [0.4, 0.4, 0.4, 0.4],
      filename: `${reportTitle.toLowerCase().replace(/[^a-z0-9]+/g, '_')}.pdf`,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, letterRendering: true },
      jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' },
      pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
    }
    window.html2pdf()
      .from(element)
      .set(opt)
      .save()
      .then(() => setPdfLoading(false))
      .catch((err) => {
        console.error('Failed to generate PDF:', err)
        setPdfLoading(false)
      })
  }

  const renderReports = () => (
    <div className="report-workspace-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', alignItems: 'start' }}>
      {/* Left Column: Form Builder Controls */}
      <div className="glass-panel simulator-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <h3 className="card-title" style={{ margin: 0, borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '12px' }}>
          <FileText size={18} className="card-icon" /> Security Report Builder
        </h3>
        
        <div className="settings-form" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label className="login-label">Report Document Title</label>
            <input
              type="text"
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              className="login-input"
              style={{ paddingLeft: '14px', marginTop: '6px' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
            <div>
              <label className="login-label">Report Category</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                style={{
                  backgroundColor: 'rgba(7, 10, 19, 0.6)',
                  border: '1px solid hsl(var(--border-color))',
                  borderRadius: '8px',
                  padding: '12px',
                  color: '#fff',
                  width: '100%',
                  marginTop: '6px',
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                <option value="Incident Summary">Incident Summary</option>
                <option value="Case Closure Report">Case Closure Report</option>
                <option value="Compliance Audit">Compliance Audit</option>
                <option value="Threat Intelligence">Threat Intelligence</option>
                <option value="System Ingestion Summary">System Ingest Summary</option>
              </select>
            </div>
            
            <div>
              <label className="login-label">Prepared By (Analyst)</label>
              <input
                type="text"
                value={preparedBy}
                onChange={(e) => setPreparedBy(e.target.value)}
                className="login-input"
                style={{ paddingLeft: '14px', marginTop: '6px' }}
              />
            </div>
          </div>

          {reportType === 'Case Closure Report' ? (
            <>
              <div>
                <label className="login-label">Root Cause Analysis</label>
                <input
                  type="text"
                  value={closureRootCause}
                  onChange={(e) => setClosureRootCause(e.target.value)}
                  className="login-input"
                  style={{ paddingLeft: '14px', marginTop: '6px' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div>
                  <label className="login-label">Closure Status</label>
                  <select
                    value={closureStatus}
                    onChange={(e) => setClosureStatus(e.target.value)}
                    style={{
                      backgroundColor: 'rgba(7, 10, 19, 0.6)',
                      border: '1px solid hsl(var(--border-color))',
                      borderRadius: '8px',
                      padding: '12px',
                      color: '#fff',
                      width: '100%',
                      marginTop: '6px',
                      outline: 'none',
                      cursor: 'pointer'
                    }}
                  >
                    <option value="Fully Mitigated & Resolved">Fully Mitigated & Resolved</option>
                    <option value="Partially Mitigated - Monitoring">Partially Mitigated</option>
                    <option value="Workaround Implemented">Workaround Implemented</option>
                  </select>
                </div>
                
                <div>
                  <label className="login-label">Approved By (Sign-off)</label>
                  <select
                    value={closureApprovedBy}
                    onChange={(e) => setClosureApprovedBy(e.target.value)}
                    style={{
                      backgroundColor: 'rgba(7, 10, 19, 0.6)',
                      border: '1px solid hsl(var(--border-color))',
                      borderRadius: '8px',
                      padding: '12px',
                      color: '#fff',
                      width: '100%',
                      marginTop: '6px',
                      outline: 'none',
                      cursor: 'pointer'
                    }}
                  >
                    {['alice.smith', 'john.doe', 'bob.johnson', 'charlie.brown', 'david.miller'].map(name => (
                      <option key={name} value={name}>{name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="login-label">Mitigation & Resolution Summary</label>
                <textarea
                  rows="3"
                  value={closureResolution}
                  onChange={(e) => setClosureResolution(e.target.value)}
                  style={{
                    backgroundColor: 'rgba(7, 10, 19, 0.6)',
                    border: '1px solid hsl(var(--border-color))',
                    borderRadius: '8px',
                    padding: '12px',
                    color: '#fff',
                    width: '100%',
                    marginTop: '6px',
                    outline: 'none',
                    fontFamily: 'inherit',
                    fontSize: '0.82rem',
                    lineHeight: 1.4,
                    resize: 'none',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div>
                <label className="login-label">Preventative Hardening / Lessons Learned</label>
                <textarea
                  rows="3"
                  value={closureLessons}
                  onChange={(e) => setClosureLessons(e.target.value)}
                  style={{
                    backgroundColor: 'rgba(7, 10, 19, 0.6)',
                    border: '1px solid hsl(var(--border-color))',
                    borderRadius: '8px',
                    padding: '12px',
                    color: '#fff',
                    width: '100%',
                    marginTop: '6px',
                    outline: 'none',
                    fontFamily: 'inherit',
                    fontSize: '0.82rem',
                    lineHeight: 1.4,
                    resize: 'none',
                    boxSizing: 'border-box'
                  }}
                />
              </div>
            </>
          ) : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                <div>
                  <label className="login-label">Period Start Date</label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => setStartDate(e.target.value)}
                    className="login-input"
                    style={{ paddingLeft: '14px', marginTop: '6px' }}
                  />
                </div>
                
                <div>
                  <label className="login-label">Period End Date</label>
                  <input
                    type="date"
                    value={endDate}
                    onChange={(e) => setEndDate(e.target.value)}
                    className="login-input"
                    style={{ paddingLeft: '14px', marginTop: '6px' }}
                  />
                </div>
              </div>

              <div>
                <label className="login-label">Alert Severity Level</label>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={{
                    backgroundColor: 'rgba(7, 10, 19, 0.6)',
                    border: '1px solid hsl(var(--border-color))',
                    borderRadius: '8px',
                    padding: '12px',
                    color: '#fff',
                    width: '100%',
                    marginTop: '6px',
                    outline: 'none',
                    cursor: 'pointer'
                  }}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical Only</option>
                  <option value="HIGH">High & Critical</option>
                  <option value="MEDIUM">Medium & Above</option>
                </select>
              </div>

              <div>
                <label className="login-label">Executive Summary</label>
                <textarea
                  rows="3"
                  value={execSummary}
                  onChange={(e) => setExecSummary(e.target.value)}
                  style={{
                    backgroundColor: 'rgba(7, 10, 19, 0.6)',
                    border: '1px solid hsl(var(--border-color))',
                    borderRadius: '8px',
                    padding: '12px',
                    color: '#fff',
                    width: '100%',
                    marginTop: '6px',
                    outline: 'none',
                    fontFamily: 'inherit',
                    fontSize: '0.82rem',
                    lineHeight: 1.4,
                    resize: 'none',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div>
                <label className="login-label">Action Recommendations</label>
                <textarea
                  rows="3"
                  value={recommendations}
                  onChange={(e) => setRecommendations(e.target.value)}
                  style={{
                    backgroundColor: 'rgba(7, 10, 19, 0.6)',
                    border: '1px solid hsl(var(--border-color))',
                    borderRadius: '8px',
                    padding: '12px',
                    color: '#fff',
                    width: '100%',
                    marginTop: '6px',
                    outline: 'none',
                    fontFamily: 'inherit',
                    fontSize: '0.82rem',
                    lineHeight: 1.4,
                    resize: 'none',
                    boxSizing: 'border-box'
                  }}
                />
              </div>
            </>
          )}

          {/* Checklist Sections */}
          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginTop: '4px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem', color: '#9ca3af', cursor: 'pointer' }}>
              <input type="checkbox" checked={includeStats} onChange={(e) => setIncludeStats(e.target.checked)} />
              Include Key Metrics
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem', color: '#9ca3af', cursor: 'pointer' }}>
              <input type="checkbox" checked={includeAlerts} onChange={(e) => setIncludeAlerts(e.target.checked)} />
              Include Alert Table
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.78rem', color: '#9ca3af', cursor: 'pointer' }}>
              <input type="checkbox" checked={includeRecommendations} onChange={(e) => setIncludeRecommendations(e.target.checked)} />
              Include Remediation
            </label>
          </div>

          <button 
            className="ai-gradient-btn" 
            onClick={handleDownloadPDF} 
            disabled={pdfLoading}
            style={{ width: '100%', justifyContent: 'center', gap: '8px', padding: '14px', fontSize: '0.85rem', fontWeight: 600, marginTop: '10px' }}
          >
            <Download size={16} />
            {pdfLoading ? 'Compiling PDF File...' : 'Download PDF Report'}
          </button>
        </div>
      </div>

      {/* Right Column: PDF Print Previewer (Branded A4 Sheet) */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 4px' }}>
          <span style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Eye size={14} /> LIVE A4 PRINT DOCUMENT PREVIEW
          </span>
        </div>

        {/* Paper Container */}
        <div className="pdf-preview-viewport" style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '720px', borderRadius: '12px', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid rgba(255,255,255,0.05)', padding: '16px' }}>
          <div 
            id="report-pdf-sheet" 
            className="pdf-page-sheet"
            style={{
              width: '100%',
              minWidth: '600px',
              maxWidth: '700px',
              minHeight: '842px',
              height: 'auto',
              backgroundColor: '#ffffff',
              color: '#111827',
              padding: '40px',
              fontFamily: "'Inter', sans-serif",
              boxSizing: 'border-box',
              display: 'flex',
              flexDirection: 'column',
              gap: '20px',
              borderRadius: '6px',
              boxShadow: '0 10px 25px rgba(0,0,0,0.5)'
            }}
          >
            {/* Header / Logo */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid #111827', paddingBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div style={{ width: '32px', height: '32px', backgroundColor: '#111827', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center' }}>
                  <ShieldAlert style={{ color: '#fff' }} size={18} />
                </div>
                <div>
                  <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 800, letterSpacing: '0.05em', color: '#111827' }}>AI SIEM</h2>
                  <span style={{ fontSize: '0.55rem', textTransform: 'uppercase', color: '#4b5563', fontWeight: 600 }}>Security Ingestion Audit Gateway</span>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: '0.62rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#6b7280', fontWeight: 600 }}>Audit Report</span>
                <h3 style={{ margin: '2px 0 0 0', fontSize: '0.85rem', fontWeight: 700, color: '#374151' }}>{reportType}</h3>
              </div>
            </div>

            {/* Document Metadata */}
            {reportType === 'Case Closure Report' ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', backgroundColor: '#f3f4f6', borderRadius: '6px', padding: '12px 16px', fontSize: '0.72rem' }}>
                <div>
                  <span style={{ color: '#6b7280', display: 'block', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600 }}>PREPARED BY</span>
                  <strong style={{ color: '#1f2937' }}>{preparedBy}</strong>
                </div>
                <div>
                  <span style={{ color: '#6b7280', display: 'block', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600 }}>TICKET SEVERITY</span>
                  <strong style={{ color: caseSeverity === 'CRITICAL' || caseSeverity === 'HIGH' ? '#ef4444' : '#f59e0b', fontWeight: 700 }}>{caseSeverity}</strong>
                </div>
                <div>
                  <span style={{ color: '#6b7280', display: 'block', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600 }}>TICKET OPENED</span>
                  <strong style={{ color: '#1f2937' }}>{new Date(caseCreatedAt || Date.now()).toLocaleDateString()}</strong>
                </div>
                <div>
                  <span style={{ color: '#6b7280', display: 'block', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600 }}>CLOSURE DATE</span>
                  <strong style={{ color: '#1f2937' }}>{new Date().toLocaleDateString()}</strong>
                </div>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', backgroundColor: '#f3f4f6', borderRadius: '6px', padding: '12px 16px', fontSize: '0.72rem' }}>
                <div>
                  <span style={{ color: '#6b7280', display: 'block', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600 }}>PREPARED BY</span>
                  <strong style={{ color: '#1f2937' }}>{preparedBy}</strong>
                </div>
                <div>
                  <span style={{ color: '#6b7280', display: 'block', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600 }}>TIMEFRAME</span>
                  <strong style={{ color: '#1f2937' }}>{startDate} - {endDate}</strong>
                </div>
                <div>
                  <span style={{ color: '#6b7280', display: 'block', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600 }}>GENERATED DATE</span>
                  <strong style={{ color: '#1f2937' }}>{new Date().toLocaleDateString()}</strong>
                </div>
              </div>
            )}

            {reportType === 'Case Closure Report' ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', flex: 1 }}>
                {/* Case Subject & Title */}
                <div style={{ borderLeft: '4px solid #111827', paddingLeft: '12px', marginTop: '10px' }}>
                  <span style={{ color: '#6b7280', fontSize: '0.62rem', textTransform: 'uppercase', fontWeight: 600, display: 'block' }}>INCIDENT CASE</span>
                  <h1 style={{ margin: '2px 0 0 0', fontSize: '1.2rem', fontWeight: 800, color: '#111827', fontFamily: "'Outfit', sans-serif" }}>
                    {reportTitle.replace('Case Closure Report: ', '')}
                  </h1>
                </div>

                {/* Root Cause Details */}
                <div>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#111827', borderBottom: '1.5px solid #111827', paddingBottom: '4px' }}>
                    Root Cause Analysis (RCA)
                  </h4>
                  <p style={{ margin: 0, fontSize: '0.75rem', color: '#374151', lineHeight: 1.45 }}>
                    {closureRootCause}
                  </p>
                </div>

                {/* Resolution Summary */}
                <div>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#111827', borderBottom: '1.5px solid #111827', paddingBottom: '4px' }}>
                    Mitigation & Resolution Summary
                  </h4>
                  <p style={{ margin: 0, fontSize: '0.75rem', color: '#374151', lineHeight: 1.45, whiteSpace: 'pre-line' }}>
                    {closureResolution}
                  </p>
                </div>

                {/* Lessons Learned */}
                <div>
                  <h4 style={{ margin: '0 0 6px 0', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#111827', borderBottom: '1.5px solid #111827', paddingBottom: '4px' }}>
                    Preventative Hardening & Lessons Learned
                  </h4>
                  <p style={{ margin: 0, fontSize: '0.75rem', color: '#374151', lineHeight: 1.45, whiteSpace: 'pre-line' }}>
                    {closureLessons}
                  </p>
                </div>

                {/* Associated Case Alerts Table */}
                {includeAlerts && caseAlerts && caseAlerts.length > 0 && (
                  <div style={{ marginTop: '10px' }}>
                    <h4 style={{ margin: '0 0 6px 0', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#111827', borderBottom: '1.5px solid #111827', paddingBottom: '4px' }}>
                      Associated Security Alerts ({caseAlerts.length})
                    </h4>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.65rem', marginTop: '6px' }}>
                      <thead>
                        <tr style={{ borderBottom: '1.5px solid #111827', color: '#374151', textAlign: 'left', fontWeight: 'bold' }}>
                          <th style={{ padding: '4px' }}>Time</th>
                          <th style={{ padding: '4px' }}>Alert Title</th>
                          <th style={{ padding: '4px', textAlign: 'right' }}>Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {caseAlerts.map((alert) => (
                          <tr key={alert.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
                            <td style={{ padding: '4px', color: '#4b5563' }}>
                              {new Date(alert.timestamp).toLocaleDateString()} {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            </td>
                            <td style={{ padding: '4px', fontWeight: 600, color: '#111827' }}>{alert.title}</td>
                            <td style={{ padding: '4px', textAlign: 'right', fontWeight: 700, color: alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? '#ef4444' : '#f59e0b' }}>
                              {alert.severity}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Sign-off signature box */}
                <div style={{ marginTop: 'auto', display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px', paddingTop: '20px', borderTop: '1px dashed #e5e7eb' }}>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.62rem', color: '#6b7280', textTransform: 'uppercase', fontWeight: 600 }}>TICKET CLOSE NOTES AUTHORIZED BY</span>
                    <strong style={{ fontSize: '0.8rem', color: '#111827' }}>{closureApprovedBy}</strong>
                    <span style={{ display: 'block', fontSize: '0.62rem', color: '#9ca3af', marginTop: '2px' }}>SOC Senior Operations Sign-Off</span>
                  </div>
                  <div style={{ borderBottom: '1px solid #9ca3af', display: 'flex', alignItems: 'flex-end', justifyContent: 'flex-end', paddingBottom: '4px' }}>
                    <span style={{ fontSize: '0.62rem', color: '#9ca3af', fontStyle: 'italic' }}>Authorized Electronic Signature</span>
                  </div>
                </div>
              </div>
            ) : (
              <>
                {/* Title / Summary */}
                <div>
                  <h1 style={{ margin: '0 0 8px 0', fontSize: '1.25rem', fontWeight: 800, color: '#111827', fontFamily: "'Outfit', sans-serif" }}>{reportTitle}</h1>
                  <p style={{ margin: 0, fontSize: '0.75rem', color: '#374151', lineHeight: 1.4, textAlign: 'justify' }}>{execSummary}</p>
                </div>

                {/* Ingestion & Incident Statistics */}
                {includeStats && stats && (
                  <div>
                    <h4 style={{ margin: '0 0 8px 0', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#111827', borderBottom: '1px solid #e5e7eb', paddingBottom: '4px' }}>
                      System Metrics & Activity Counts
                    </h4>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', textAlign: 'center' }}>
                      <div style={{ border: '1px solid #e5e7eb', borderRadius: '6px', padding: '10px 4px' }}>
                        <span style={{ display: 'block', fontSize: '0.55rem', color: '#6b7280', textTransform: 'uppercase' }}>Ingested Events</span>
                        <strong style={{ fontSize: '1rem', color: '#111827' }}>{stats.total_events.toLocaleString()}</strong>
                      </div>
                      <div style={{ border: '1px solid #e5e7eb', borderRadius: '6px', padding: '10px 4px' }}>
                        <span style={{ display: 'block', fontSize: '0.55rem', color: '#6b7280', textTransform: 'uppercase' }}>Correlated Alerts</span>
                        <strong style={{ fontSize: '1rem', color: '#111827' }}>{stats.total_alerts.toLocaleString()}</strong>
                      </div>
                      <div style={{ border: '1px solid #e5e7eb', borderRadius: '6px', padding: '10px 4px' }}>
                        <span style={{ display: 'block', fontSize: '0.55rem', color: '#6b7280', textTransform: 'uppercase' }}>Incident Tickets</span>
                        <strong style={{ fontSize: '1rem', color: '#111827' }}>{stats.total_cases.toLocaleString()}</strong>
                      </div>
                      <div style={{ border: '1px solid #e5e7eb', borderRadius: '6px', padding: '10px 4px' }}>
                        <span style={{ display: 'block', fontSize: '0.55rem', color: '#6b7280', textTransform: 'uppercase' }}>Critical Threats</span>
                        <strong style={{ fontSize: '1rem', color: '#ef4444' }}>{stats.critical_incidents.toLocaleString()}</strong>
                      </div>
                    </div>
                  </div>
                )}

                {/* Alert List Table */}
                {includeAlerts && (
                  <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
                    <h4 style={{ margin: '0 0 8px 0', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#111827', borderBottom: '1px solid #e5e7eb', paddingBottom: '4px' }}>
                      Correlated Alerts Log (Severity: {severityFilter})
                    </h4>
                    {filteredReportAlerts.length === 0 ? (
                      <p style={{ margin: 0, fontSize: '0.7rem', color: '#6b7280', fontStyle: 'italic' }}>No alerts triggered matching the filter.</p>
                    ) : (
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.65rem' }}>
                        <thead>
                          <tr style={{ borderBottom: '1.5px solid #111827', color: '#374151', textAlign: 'left', fontWeight: 'bold' }}>
                            <th style={{ padding: '6px 4px' }}>Time</th>
                            <th style={{ padding: '6px 4px' }}>Alert Name</th>
                            <th style={{ padding: '6px 4px' }}>Source IP</th>
                            <th style={{ padding: '6px 4px', textAlign: 'right' }}>Severity</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredReportAlerts.map((alert) => (
                            <tr key={alert.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
                              <td style={{ padding: '6px 4px', color: '#4b5563' }}>
                                {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                              </td>
                              <td style={{ padding: '6px 4px', fontWeight: 600, color: '#111827' }}>{alert.title}</td>
                              <td style={{ padding: '6px 4px', color: '#4b5563' }}>
                                {alert.trigger_log ? alert.trigger_log.source_ip : ((alert.description || '').match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)?.[0] || 'Unknown')}
                              </td>
                              <td style={{ padding: '6px 4px', textAlign: 'right', fontWeight: 700, color: alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? '#ef4444' : '#f59e0b' }}>
                                {alert.severity}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}

                {/* Recommendations */}
                {includeRecommendations && (
                  <div style={{ marginTop: 'auto', borderTop: '1.5px solid #111827', paddingTop: '12px' }}>
                    <h4 style={{ margin: '0 0 6px 0', fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: '#111827' }}>
                      Remediation Recommendations
                    </h4>
                    <div style={{ fontSize: '0.72rem', color: '#374151', whiteSpace: 'pre-line', lineHeight: 1.4 }}>
                      {recommendations}
                    </div>
                  </div>
                )}
              </>
            )}

            {/* Page Footer */}
            <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid #e5e7eb', paddingTop: '8px', marginTop: 'auto', fontSize: '0.58rem', color: '#9ca3af' }}>
              <span>CONFIDENTIAL - SYSTEM AUDIT FILE</span>
              <span>Page 1 of 1</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )

  const renderAutomation = () => (
    <div className="simulator-grid" style={{ gridTemplateColumns: '1fr' }}>
      <div className="glass-panel simulator-card">
        <h3 className="card-title"><Cpu size={18} className="card-icon" /> Live Active Playbooks & Actions</h3>
        <div className="settings-form" style={{ gap: '16px' }}>
          {playbooks.map((p, idx) => (
            <div key={idx} style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center', 
              borderBottom: idx < playbooks.length - 1 ? '1px solid rgba(255, 255, 255, 0.05)' : 'none',
              paddingBottom: '14px'
            }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxWidth: '80%' }}>
                <span style={{ fontSize: '0.9rem', color: '#fff', fontWeight: '700' }}>{p.name}</span>
                <span style={{ fontSize: '0.75rem', color: 'hsl(var(--color-ai-cyan))' }}>Trigger Event: {p.trigger}</span>
                <p style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', lineHeight: 1.4, marginTop: '4px' }}>{p.desc}</p>
              </div>
              <button onClick={() => togglePlaybook(idx)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: p.active ? 'hsl(var(--color-primary))' : 'hsl(var(--text-muted))' }}>
                {p.active ? <ToggleRight size={36} style={{ color: 'hsl(var(--color-ai-cyan))' }} /> : <ToggleLeft size={36} />}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )

  const renderIntegrations = () => {
    const keys = ['simulator', 'gemini', 'correlation', 'cases']
    const updatedIntegrations = integrations.map((int, idx) => {
      const key = keys[idx]
      const isConnected = integrationStates ? !!integrationStates[key] : int.connected
      return {
        ...int,
        connected: isConnected,
        status: isConnected ? (idx === 0 ? 'Active Ingesting' : idx === 2 ? 'Active Filtering' : 'Active Syncing') : 'Disconnected'
      }
    })

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        {/* Informational Banner showing Importance */}
        <div className="glass-panel" style={{ padding: '20px', borderLeft: '4px solid hsl(var(--color-ai-cyan))', background: 'rgba(165, 180, 252, 0.03)' }}>
          <h4 style={{ margin: '0 0 6px 0', fontSize: '0.95rem', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap size={16} style={{ color: 'hsl(var(--color-ai-cyan))' }} /> Core API Integration Layer
          </h4>
          <p style={{ margin: 0, fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', lineHeight: 1.4 }}>
            Integrations bridge your SIEM security core with external platforms. They ingest audit logs from cloud accounts, orchestrate Slack messaging alerts, forward compliance data, and link ticketing playbooks to centralize security operations.
          </p>
        </div>

        <div className="simulator-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
          {updatedIntegrations.map((int, idx) => (
            <div key={idx} className="glass-panel simulator-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '24px', boxSizing: 'border-box' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))', fontWeight: '700', textTransform: 'uppercase' }}>
                  {int.category}
                </span>
                <span style={{ 
                  fontSize: '0.7rem', 
                  fontWeight: '600',
                  padding: '2px 8px',
                  borderRadius: '20px',
                  backgroundColor: int.connected ? 'rgba(16, 185, 129, 0.12)' : 'rgba(255, 255, 255, 0.05)',
                  color: int.connected ? 'hsl(var(--sev-low))' : 'hsl(var(--text-muted))'
                }}>
                  {int.status}
                </span>
              </div>
              
              <div>
                <h4 style={{ fontSize: '1.05rem', color: '#fff', fontWeight: '700', margin: '0 0 8px 0' }}>{int.name}</h4>
                <p style={{ fontSize: '0.8rem', color: 'hsl(var(--text-secondary))', lineHeight: 1.4, margin: 0 }}>
                  {int.desc}
                </p>
              </div>

              {/* Performance Indicators */}
              {int.connected && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', backgroundColor: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.03)' }}>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.62rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Ingestion Rate</span>
                    <strong style={{ fontSize: '0.8rem', color: 'hsl(var(--color-ai-cyan))' }}>{int.eps} EPS</strong>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.62rem', color: 'hsl(var(--text-muted))', textTransform: 'uppercase' }}>Latency</span>
                    <strong style={{ fontSize: '0.8rem', color: '#fff' }}>{int.latency}</strong>
                  </div>
                </div>
              )}

              {/* SECURITY IMPORTANCE DETAILS */}
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '12px' }}>
                <span style={{ display: 'block', fontSize: '0.7rem', color: 'hsl(var(--text-muted))', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  🛡️ Security Importance
                </span>
                <p style={{ fontSize: '0.75rem', color: 'hsl(var(--color-ai-cyan))', fontStyle: 'italic', margin: 0, lineHeight: 1.35 }}>
                  {int.importance}
                </p>
              </div>

              <div style={{ marginTop: 'auto', display: 'flex', gap: '10px', paddingTop: '10px' }}>
                <button 
                  className={`grid-refresh-btn ${int.connected ? '' : 'ai-gradient-btn'}`} 
                  onClick={() => toggleIntegration(idx)}
                  style={{ flex: 1, padding: '10px', fontSize: '0.8rem', justifyContent: 'center', fontWeight: '600' }}
                >
                  {int.connected ? 'Disconnect Feed' : 'Establish Connection'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="workspace-layout">
      {/* Header */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
          {tabName} Command Console
        </h1>
        <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
          {tabName === 'Reports' && 'Compile, customize, preview, and download secure security summaries.'}
          {tabName === 'Automation' && 'Configure automated playbooks and active-response rules.'}
          {tabName === 'Integrations' && 'Bridge logs collection feeds and sync alerts with third-party APIs.'}
        </span>
      </div>

      {tabName === 'Reports' && renderReports()}
      {tabName === 'Automation' && renderAutomation()}
      {tabName === 'Integrations' && renderIntegrations()}
    </div>
  )
}

export default SecurityWorkspace
