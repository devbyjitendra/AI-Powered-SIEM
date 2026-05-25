import React, { useState } from 'react'
import Sidebar from './components/Sidebar.jsx'

function App() {
  const [activeTab, setActiveTab] = useState('Dashboard')

  return (
    <div className="app-layout">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      {/* Main Dashboard Frame */}
      <main style={{ flex: 1, padding: '40px', overflowY: 'auto' }}>
        <h1 className="ai-gradient-text" style={{ fontSize: '2.5rem', marginBottom: '10px' }}>
          {activeTab}
        </h1>
        <p style={{ color: 'hsl(var(--text-secondary))' }}>
          Displaying content workspace for {activeTab}.
        </p>
      </main>
    </div>
  )
}

export default App
