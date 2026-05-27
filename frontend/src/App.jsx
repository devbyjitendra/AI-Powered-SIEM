import React, { useState } from 'react'
import Sidebar from './components/Sidebar.jsx'
import Header from './components/Header.jsx'
import KPICards from './components/KPICards.jsx'
import SecurityCharts from './components/SecurityCharts.jsx'
import ThreatMap from './components/ThreatMap.jsx'

function App() {
  const [activeTab, setActiveTab] = useState('Dashboard')
  const [searchQuery, setSearchQuery] = useState('')

  const handleAskAI = () => {
    alert("Gemini AI security assistant initialized. Prompt analysis features activate on Day 25!")
  }

  return (
    <div className="app-layout">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      {/* Main Dashboard Frame */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
        <Header 
          searchQuery={searchQuery} 
          setSearchQuery={setSearchQuery} 
          onAskAI={handleAskAI} 
        />
        
        <main style={{ flex: 1, padding: '0 24px 24px 24px', overflowY: 'auto' }}>
          {activeTab === 'Dashboard' ? (
            <>
              <div style={{ marginBottom: '20px' }}>
                <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>Dashboard</h1>
                <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>Overview of your security environment</span>
              </div>
              
              {/* Stat Counters Grid */}
              <KPICards />

              {/* Timeline & Category Charts */}
              <SecurityCharts />

              {/* Geographical Map & Top Sources */}
              <ThreatMap />
            </>
          ) : (
            <>
              <h1 className="ai-gradient-text" style={{ fontSize: '2rem', marginBottom: '10px' }}>
                {activeTab}
              </h1>
              <p style={{ color: 'hsl(var(--text-secondary))' }}>
                Displaying content workspace for {activeTab}.
              </p>
            </>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
