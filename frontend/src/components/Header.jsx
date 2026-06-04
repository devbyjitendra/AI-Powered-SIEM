import React, { useState, useEffect } from 'react'
import { 
  Search, 
  Menu, 
  Sparkles, 
  Bell, 
  HelpCircle, 
  Sun, 
  Moon 
} from 'lucide-react'
import { getAlerts } from '../services/api'

function Header({ searchQuery, setSearchQuery, onAskAI, integrationStates }) {
  const [recentAlerts, setRecentAlerts] = useState([])
  const [totalCount, setTotalCount] = useState(0)
  const [isOpen, setIsOpen] = useState(false)
  const [isHelpOpen, setIsHelpOpen] = useState(false)

  useEffect(() => {
    async function loadRecentAlerts() {
      const data = await getAlerts('NEW')
      if (data) {
        setTotalCount(data.length)
        setRecentAlerts(data.slice(0, 5))
      }
    }
    loadRecentAlerts()
    
    // Poll alerts every 5 seconds to sync the notification count live
    const interval = setInterval(loadRecentAlerts, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <header className="dashboard-header glass-panel">
      {/* Search Input Bar */}
      <div className="header-left">
        <button className="menu-toggle-btn">
          <Menu size={20} />
        </button>
        <div className="search-bar-wrapper">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="Search incidents, alerts, users, IPs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
      </div>

      {/* Control Panels */}
      <div className="header-right">
        {/* Ask AI Action Button */}
        {integrationStates?.gemini !== false ? (
          <button className="ai-gradient-btn ask-ai-btn" onClick={onAskAI}>
            <Sparkles size={16} className="sparkle-icon" />
            <span>Ask AI</span>
          </button>
        ) : (
          <button 
            className="ask-ai-btn-locked" 
            onClick={onAskAI}
            style={{
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              color: 'rgba(255, 255, 255, 0.4)',
              cursor: 'not-allowed',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '10px 16px',
              borderRadius: '8px',
              fontSize: '0.85rem',
              fontWeight: 600,
              transition: 'all 0.3s ease'
            }}
            title="Gemini AI Analyst Agent is Offline (Disconnected in Integrations)"
          >
            <span style={{ fontSize: '14px' }}>🔒</span>
            <span>Ask AI (Offline)</span>
          </button>
        )}

        {/* Notifications Alert Bell */}
        <div className="notification-bell-container">
          <button className="header-icon-btn" onClick={() => setIsOpen(!isOpen)}>
            <Bell size={20} />
            {totalCount > 0 && <span className="bell-badge"></span>}
          </button>

          {isOpen && (
            <div className="notifications-dropdown glass-panel">
              <div className="dropdown-header">
                <h4>Recent Notifications</h4>
              </div>
              <div className="dropdown-body">
                {recentAlerts.length === 0 ? (
                   <p className="no-notifications">No new notifications</p>
                ) : (
                  <ul className="notifications-list">
                    {recentAlerts.map((alert) => (
                      <li key={alert.id} className={`notification-item severity-${alert.severity.toLowerCase()}`}>
                        <span className="notification-title">{alert.title}</span>
                        <span className="notification-time">
                          {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Support Link & Help Toolkit */}
        <div className="help-toolkit-container" style={{ position: 'relative' }}>
          <button className="header-icon-btn" onClick={() => setIsHelpOpen(!isHelpOpen)} title="Show SIEM Toolkit Info">
            <HelpCircle size={20} />
          </button>

          {isHelpOpen && (
            <div className="help-toolkit-modal glass-panel" style={{
              position: 'absolute',
              top: '50px',
              right: '0',
              width: '320px',
              padding: '20px',
              zIndex: 1000,
              textAlign: 'left',
              boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.4)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: '12px',
              background: 'rgba(10, 15, 30, 0.95)',
              backdropFilter: 'blur(20px)',
              color: '#f3f4f6'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', paddingBottom: '8px' }}>
                <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: '#a5b4fc' }}>SIEM Advisor Toolkit</h4>
                <button 
                  onClick={() => setIsHelpOpen(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#9ca3af',
                    cursor: 'pointer',
                    fontSize: '0.8rem',
                    padding: '2px 6px'
                  }}
                >
                  ✕
                </button>
              </div>
              <div style={{ fontSize: '0.78rem', lineHeight: '1.5', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <p style={{ margin: 0, color: '#9ca3af' }}>
                  A next-generation Security Information and Event Management (SIEM) dashboard powered by Google Gemini AI.
                </p>
                <div>
                  <strong style={{ color: '#fff' }}>🛡️ Ingestion & Correlation</strong>
                  <p style={{ margin: '2px 0 0 0', color: '#9ca3af' }}>Parses logs dynamically, matching active threat regex signatures in real-time.</p>
                </div>
                <div>
                  <strong style={{ color: '#fff' }}>🤖 AI Playbook Analysis</strong>
                  <p style={{ margin: '2px 0 0 0', color: '#9ca3af' }}>Click any alert title to generate automated threat response guidelines using AI.</p>
                </div>
                <div>
                  <strong style={{ color: '#fff' }}>💬 Interactive Security AI</strong>
                  <p style={{ margin: '2px 0 0 0', color: '#9ca3af' }}>Open "Ask AI" in the header to chat with an analyst for advice, query writing, or ssh firewall rules.</p>
                </div>
                <div>
                  <strong style={{ color: '#fff' }}>📈 SIEM Simulation Sandbox</strong>
                  <p style={{ margin: '2px 0 0 0', color: '#9ca3af' }}>Runs background traffic containing Brute Force, SQL Injection, XSS, and Malware vectors.</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}

export default Header
