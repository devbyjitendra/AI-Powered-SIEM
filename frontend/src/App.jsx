import React from 'react'

function App() {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      flexDirection: 'column',
      background: 'hsl(var(--bg-dark))',
      color: '#fff'
    }}>
      <h1 className="ai-gradient-text" style={{ fontSize: '2.5rem', marginBottom: '10px' }}>
        AI SIEM Command Center
      </h1>
      <p style={{ color: 'hsl(var(--text-secondary))' }}>
        Theme and scaffolding initialized. Sidebar and layout assets loading...
      </p>
    </div>
  )
}

export default App
