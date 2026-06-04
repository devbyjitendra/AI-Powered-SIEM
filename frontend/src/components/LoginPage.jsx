import React, { useState } from 'react'
import { ShieldAlert, Lock, User, Eye, EyeOff, Loader2 } from 'lucide-react'

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = (e) => {
    e.preventDefault()
    setError('')

    if (!username.trim() || !password.trim()) {
      setError('Please fill in all fields.')
      return
    }

    setLoading(true)

    // Simulate network authentication delay
    setTimeout(() => {
      if (username.toLowerCase() === 'admin' && password === 'password123') {
        onLogin(username)
      } else {
        setError('Invalid username or password.')
        setLoading(false)
      }
    }, 1200)
  }

  return (
    <div className="login-page-container">
      {/* Background ambient glowing blobs */}
      <div className="login-glow-blob login-blob-1"></div>
      <div className="login-glow-blob login-blob-2"></div>

      <div className="login-card glass-panel">
        <div className="login-header">
          <div className="login-logo-wrapper">
            <ShieldAlert className="login-shield-icon" size={32} />
          </div>
          <h1 className="login-title">AI SIEM GATEWAY</h1>
          <p className="login-subtitle">Secure intelligence analysis platform</p>
        </div>

        {error && (
          <div className="login-error-banner">
            <span>⚠️ {error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-input-group">
            <label className="login-label">Username</label>
            <div className="login-input-wrapper">
              <User className="login-field-icon" size={16} />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="login-input"
                disabled={loading}
                autoComplete="username"
              />
            </div>
          </div>

          <div className="login-input-group">
            <label className="login-label">Password</label>
            <div className="login-input-wrapper">
              <Lock className="login-field-icon" size={16} />
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="login-input"
                disabled={loading}
                autoComplete="current-password"
              />
              <button
                type="button"
                className="password-toggle-btn"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button type="submit" className="login-submit-btn ai-gradient-btn" disabled={loading}>
            {loading ? (
              <>
                <Loader2 size={18} className="animate-spin mr-2" />
                <span>Authenticating Gateway...</span>
              </>
            ) : (
              <span>Establish Secure Session</span>
            )}
          </button>
        </form>

      </div>
    </div>
  )
}

export default LoginPage
