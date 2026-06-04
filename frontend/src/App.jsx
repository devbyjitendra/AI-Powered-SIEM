import React, { useState, useEffect, useRef } from 'react'
import Sidebar from './components/Sidebar.jsx'
import Header from './components/Header.jsx'
import KPICards from './components/KPICards.jsx'
import SecurityCharts from './components/SecurityCharts.jsx'
import ThreatMap from './components/ThreatMap.jsx'
import AlertsGrid from './components/AlertsGrid.jsx'
import Simulator from './components/Simulator.jsx'
import CaseManagement from './components/CaseManagement.jsx'
import IncidentsPanel from './components/IncidentsPanel.jsx'
import SettingsPanel from './components/SettingsPanel.jsx'
import UEBA from './components/UEBA.jsx'
import SecurityWorkspace from './components/SecurityWorkspace.jsx'
import { getDashboardStats } from './services/api'
import AIChatDrawer from './components/AIChatDrawer.jsx'
import LoginPage from './components/LoginPage.jsx'
import { Bell } from 'lucide-react'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('siem_session_user') !== null
  })
  const [activeTab, setActiveTab] = useState('Dashboard')
  const [searchQuery, setSearchQuery] = useState('')
  const [alertsCount, setAlertsCount] = useState(undefined)
  const [isChatOpen, setIsChatOpen] = useState(false)
  const [integrationsActive, setIntegrationsActive] = useState({
    simulator: true,
    gemini: true,
    correlation: true,
    cases: true
  })

  const [transferCaseData, setTransferCaseData] = useState(null)
  
  // Lifted dashboard statistics state and interval selection
  const [stats, setStats] = useState(null)
  const [statsInterval, setStatsInterval] = useState('5m')
  const statsIntervalRef = useRef(statsInterval)
  statsIntervalRef.current = statsInterval
  
  // Lifted AlertsGrid states to preserve them across tab switches
  const [alertsGridData, setAlertsGridData] = useState([])
  const [alertsGridSeverity, setAlertsGridSeverity] = useState('ALL')
  const [alertsGridCategory, setAlertsGridCategory] = useState('ALL')
  const [alertsGridStatus, setAlertsGridStatus] = useState('ALL')
  const [alertsGridStartTime, setAlertsGridStartTime] = useState('')
  const [alertsGridEndTime, setAlertsGridEndTime] = useState('')
  const [alertsGridSearch, setAlertsGridSearch] = useState('')
  const [alertsGridPage, setAlertsGridPage] = useState(1)
  
  // State for global threat notification toasts
  const [toast, setToast] = useState({ visible: false, title: '', message: '', severity: '' })

  const triggerToast = (title, message, severity) => {
    setToast({ visible: true, title, message, severity })
    setTimeout(() => {
      setToast(prev => ({ ...prev, visible: false }))
    }, 4500)
  }

  // Load and refresh stats globally with chosen interval
  const loadStats = async (currInterval = statsIntervalRef.current) => {
    const data = await getDashboardStats(currInterval)
    if (data) {
      setStats(data)
      setAlertsCount(data.total_alerts)
    }
  }

  // Periodic polling for stats to keep dashboard updated
  useEffect(() => {
    if (!isAuthenticated) return
    if (!integrationsActive.simulator) {
      setAlertsCount(0)
      return
    }
    loadStats(statsInterval)
    
    const interval = setInterval(() => loadStats(statsInterval), 5000)
    return () => clearInterval(interval)
  }, [isAuthenticated, integrationsActive.simulator, statsInterval])

  // Global WebSocket listener for threat alert popups and real-time dashboard sync
  useEffect(() => {
    if (!isAuthenticated) return
    if (integrationsActive.correlation === false) return

    let wsHost = window.location.hostname || '127.0.0.1'
    if (wsHost === 'localhost') {
      wsHost = '127.0.0.1'
    }
    const wsUrl = `ws://${wsHost}:8000/ws/alerts`
    let socket
    let reconnectTimeout

    const connectWebSocket = () => {
      console.log('Global notification WebSocket establishing connection...')
      socket = new WebSocket(wsUrl)

      socket.onmessage = (event) => {
        try {
          const newAlert = JSON.parse(event.data)
          const srcIp = newAlert.trigger_log ? newAlert.trigger_log.source_ip : 'Unknown Source'
          const category = (newAlert.rule_id && typeof newAlert.rule_id === 'string' && newAlert.rule_id.includes('AUTH')) ? 'Authentication' : 
                            (newAlert.rule_id && typeof newAlert.rule_id === 'string' && newAlert.rule_id.includes('SQL')) ? 'Web Application' : 'System'
          
          triggerToast(
            newAlert.title,
            `Alert source IP: ${srcIp} | Category: ${category}`,
            newAlert.severity || 'MEDIUM'
          )
          
          // Trigger instant real-time stats update on WebSocket events
          loadStats(statsIntervalRef.current)
        } catch (err) {
          console.error('Global WebSocket payload parsing error:', err)
        }
      }

      socket.onclose = () => {
        reconnectTimeout = setTimeout(connectWebSocket, 5000)
      }

      socket.onerror = (err) => {
        console.error('Global WebSocket connection error:', err)
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
  }, [isAuthenticated, integrationsActive.correlation])

  const handleLogin = (username) => {
    localStorage.setItem('siem_session_user', username)
    setIsAuthenticated(true)
  }

  const handleLogout = () => {
    localStorage.removeItem('siem_session_user')
    setIsAuthenticated(false)
    setActiveTab('Dashboard')
    setTransferCaseData(null)
  }

  const handleAskAI = () => {
    if (!integrationsActive.gemini) {
      alert("⚠️ Access Blocked: The Gemini AI Analyst integration is currently disconnected. Please enable it in the Integrations Command Console.")
      return
    }
    setIsChatOpen(true)
  }

  const renderContent = () => {
    switch (activeTab) {
      case 'Dashboard':
        return (
          <>
            <div style={{ marginBottom: '20px' }}>
              <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>Dashboard</h1>
              <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>Overview of your security environment</span>
            </div>
            
            {/* Stat Counters Grid */}
            <KPICards integrationStates={integrationsActive} stats={stats} />

            {/* Timeline & Category Charts */}
            <SecurityCharts 
              setActiveTab={setActiveTab} 
              stats={stats} 
              statsInterval={statsInterval} 
              setStatsInterval={setStatsInterval} 
            />

            {/* Geographical Map & Top Sources */}
            <ThreatMap setActiveTab={setActiveTab} stats={stats} />
          </>
        )
      case 'Log Management':
        return <Simulator />
      case 'Alerts':
        return (
          <>
            <div style={{ marginBottom: '20px' }}>
              <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>Security Alerts</h1>
              <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>Triage and manage generated threat events</span>
            </div>
            <AlertsGrid 
              integrationStates={integrationsActive} 
              alerts={alertsGridData}
              setAlerts={setAlertsGridData}
              filterSeverity={alertsGridSeverity}
              setFilterSeverity={setAlertsGridSeverity}
              filterCategory={alertsGridCategory}
              setFilterCategory={setAlertsGridCategory}
              filterStatus={alertsGridStatus}
              setFilterStatus={setAlertsGridStatus}
              filterStartTime={alertsGridStartTime}
              setFilterStartTime={setAlertsGridStartTime}
              filterEndTime={alertsGridEndTime}
              setFilterEndTime={setAlertsGridEndTime}
              searchQuery={alertsGridSearch}
              setSearchQuery={setAlertsGridSearch}
              currentPage={alertsGridPage}
              setCurrentPage={setAlertsGridPage}
              setActiveTab={setActiveTab}
            />
          </>
        )
      case 'Incidents':
        return <IncidentsPanel setActiveTab={setActiveTab} />
      case 'Case Management':
        return <CaseManagement integrationStates={integrationsActive} onTransferToReports={(caseData) => {
          setTransferCaseData(caseData)
          setActiveTab('Reports')
        }} />
      case 'Threat Intelligence':
        return (
          <>
            <div style={{ marginBottom: '20px' }}>
              <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>Threat Intelligence</h1>
              <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>Visualizing global attack origins and threat actors</span>
            </div>
            <ThreatMap setActiveTab={setActiveTab} stats={stats} />
          </>
        )
      case 'UEBA':
        return <UEBA />
      case 'Reports':
      case 'Automation':
      case 'Integrations':
        return (
          <SecurityWorkspace 
            tabName={activeTab} 
            integrationStates={integrationsActive} 
            setIntegrationStates={setIntegrationsActive} 
            transferCaseData={transferCaseData}
            clearTransferCaseData={() => setTransferCaseData(null)}
          />
        )
      case 'Settings':
        return <SettingsPanel />
      default:
        return (
          <>
            <h1 className="ai-gradient-text" style={{ fontSize: '2rem', marginBottom: '10px' }}>
              {activeTab}
            </h1>
            <p style={{ color: 'hsl(var(--text-secondary))' }}>
              Displaying content workspace for {activeTab}.
            </p>
          </>
        )
    }
  }

  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} />
  }

  return (
    <div className="app-layout">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} alertsCount={alertsCount} onLogout={handleLogout} />
      
      {/* Main Dashboard Frame */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
        <Header 
          searchQuery={searchQuery} 
          setSearchQuery={setSearchQuery} 
          onAskAI={handleAskAI} 
          integrationStates={integrationsActive}
        />
        
        <main style={{ flex: 1, padding: '0 24px 24px 24px', overflowY: 'auto' }}>
          {renderContent()}
        </main>
      </div>
      {isChatOpen && (
        <AIChatDrawer isOpen={isChatOpen} onClose={() => setIsChatOpen(false)} />
      )}

      {/* Global Toast Alert Pop-Up */}
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
    </div>
  )
}

export default App

