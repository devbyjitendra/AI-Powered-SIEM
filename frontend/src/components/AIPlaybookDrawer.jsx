import React, { useState, useEffect } from 'react'
import { X, Sparkles, ShieldAlert, Check, Copy, AlertTriangle, ShieldCheck } from 'lucide-react'

function AIPlaybookDrawer({ alertId, onClose, integrationStates }) {
  const [playbook, setPlaybook] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!alertId) return

    if (integrationStates?.gemini === false) {
      setLoading(false)
      return
    }

    const fetchPlaybook = async () => {
      setLoading(true)
      setError(null)
      try {
        const response = await fetch(`http://127.0.0.1:8000/api/v1/alerts/${alertId}/analyze`, {
          method: 'POST'
        })
        if (!response.ok) {
          throw new Error('Failed to run AI playbook generation.')
        }
        const alertData = await response.json()
        
        // Parse the ai_playbook JSON string if present
        if (alertData.ai_playbook) {
          try {
            const parsedPlaybook = JSON.parse(alertData.ai_playbook)
            setPlaybook(parsedPlaybook)
          } catch {
            // Fallback in case raw text got stored
            setPlaybook({
              threat_level: alertData.severity,
              analysis_summary: alertData.ai_summary,
              remediation_steps: ["Perform standard host investigations.", "Review triggering log messages."],
              suggested_firewall_rule: "N/A"
            })
          }
        } else {
          throw new Error('AI analysis succeeded but no playbook playbook was returned.')
        }
      } catch (err) {
        console.error(err)
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }

    fetchPlaybook()
  }, [alertId, integrationStates?.gemini])

  const handleCopy = () => {
    if (!playbook || !playbook.suggested_firewall_rule) return
    navigator.clipboard.writeText(playbook.suggested_firewall_rule)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (!alertId) return null

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-container glass-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="drawer-header">
          <div className="drawer-title-wrapper">
            <Sparkles size={20} className="ai-glow-icon" />
            <h2 className="ai-gradient-text">Gemini Incident Insights</h2>
          </div>
          <button className="drawer-close-btn" onClick={onClose} title="Close drawer">
            <X size={18} />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="drawer-body">
          {integrationStates?.gemini === false ? (
            <div className="drawer-error-state" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: '40px 20px', gap: '16px' }}>
              <div style={{ fontSize: '48px' }}>🔒</div>
              <h4 style={{ color: 'hsl(var(--sev-critical))', margin: 0, fontSize: '1.1rem' }}>AI Playbook Agent Offline</h4>
              <p style={{ color: 'hsl(var(--text-secondary))', fontSize: '0.85rem', lineHeight: 1.5, margin: 0 }}>
                The Gemini AI Analyst Agent integration is currently disconnected. Re-enable the connection inside the Integrations Command Console to unlock AI security analysis.
              </p>
            </div>
          ) : loading ? (
            <div className="drawer-loader-container">
              <div className="glowing-spinner" />
              <span className="loader-text">Gemini is analyzing threat payload...</span>
            </div>
          ) : error ? (
            <div className="drawer-error-state">
              <AlertTriangle size={36} className="error-icon" />
              <h4>Analysis Failed</h4>
              <p>{error}</p>
            </div>
          ) : playbook ? (
            <div className="playbook-content">
              {/* Threat Alert Overview */}
              <div className="playbook-section alert-overview-section">
                <div className={`threat-badge severity-${playbook.threat_level?.toLowerCase()}`}>
                  <ShieldAlert size={14} />
                  <span>Threat Level: {playbook.threat_level}</span>
                </div>
              </div>

              {/* Analysis Summary */}
              <div className="playbook-section">
                <h3 className="section-title">Incident Summary</h3>
                <div className="summary-box">
                  <p>{playbook.analysis_summary}</p>
                </div>
              </div>

              {/* Remediation Steps */}
              <div className="playbook-section">
                <h3 className="section-title">Recommended Playbook</h3>
                <ul className="remediation-list">
                  {playbook.remediation_steps?.map((step, index) => (
                    <li key={index} className="remediation-item">
                      <div className="step-check-icon">
                        <ShieldCheck size={16} />
                      </div>
                      <span className="step-text">{step}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Suggested Firewall Rules */}
              {playbook.suggested_firewall_rule && playbook.suggested_firewall_rule !== 'N/A' && (
                <div className="playbook-section">
                  <h3 className="section-title">Block Mitigation Command</h3>
                  <div className="code-block-wrapper">
                    <pre className="code-block-content">
                      <code>{playbook.suggested_firewall_rule}</code>
                    </pre>
                    <button className="copy-code-btn" onClick={handleCopy} title="Copy command">
                      {copied ? <Check size={14} className="copy-success" /> : <Copy size={14} />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="drawer-empty-state">No playbook loaded.</div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AIPlaybookDrawer
