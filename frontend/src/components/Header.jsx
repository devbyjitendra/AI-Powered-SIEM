import React from 'react'
import { 
  Search, 
  Menu, 
  Sparkles, 
  Bell, 
  HelpCircle, 
  Sun, 
  Moon 
} from 'lucide-react'

function Header({ searchQuery, setSearchQuery, onAskAI }) {
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
        <button className="ai-gradient-btn ask-ai-btn" onClick={onAskAI}>
          <Sparkles size={16} className="sparkle-icon" />
          <span>Ask AI</span>
        </button>

        {/* Notifications Alert Bell */}
        <div className="notification-bell-container">
          <button className="header-icon-btn">
            <Bell size={20} />
            <span className="bell-badge">12</span>
          </button>
        </div>

        {/* Support Link */}
        <button className="header-icon-btn">
          <HelpCircle size={20} />
        </button>

        {/* Theme Switching Button */}
        <button className="header-icon-btn theme-toggle-btn">
          <Sun size={20} />
        </button>
      </div>
    </header>
  )
}

export default Header
