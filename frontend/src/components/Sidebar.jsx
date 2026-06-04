import React, { useState } from 'react'
import {
  LayoutDashboard,
  Bell,
  ShieldAlert,
  Globe,
  UserCheck,
  FileSpreadsheet,
  FolderLock,
  LineChart,
  Cpu,
  Layers,
  Server,
  Settings,
  ChevronDown,
  LogOut
} from 'lucide-react'

// Navigation configuration matching reference mockup image exactly
const NAV_ITEMS = [
  { name: 'Dashboard', icon: LayoutDashboard },
  { name: 'Alerts', icon: Bell, badge: 0 },
  { name: 'Incidents', icon: ShieldAlert },
  { name: 'Threat Intelligence', icon: Globe },
  { name: 'UEBA', icon: UserCheck },
  { name: 'Log Management', icon: FileSpreadsheet },
  { name: 'Case Management', icon: FolderLock },
  { name: 'Reports', icon: LineChart },
  { name: 'Automation', icon: Cpu },
  { name: 'Integrations', icon: Layers },
  { name: 'Settings', icon: Settings },
]

function Sidebar({ activeTab, setActiveTab, alertsCount, onLogout }) {
  return (
    <aside className="sidebar-container">
      {/* Brand Header */}
      <div className="brand-header">
        <div className="logo-icon">
          <ShieldAlert size={22} className="logo-shield" />
        </div>
        <div className="brand-info">
          <h2>AI SIEM</h2>
          <span className="brand-slogan">Smart. Secure. Intelligent.</span>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="sidebar-nav">
        <ul>
          {NAV_ITEMS.map((item) => {
            const IconComponent = item.icon
            const isActive = activeTab === item.name
            
            return (
              <li key={item.name}>
                <button
                  className={`nav-button ${isActive ? 'active' : ''}`}
                  onClick={() => setActiveTab(item.name)}
                >
                  <span className="nav-btn-content">
                    <IconComponent size={18} className="nav-icon" />
                    <span className="nav-text">{item.name}</span>
                  </span>
                  {item.name === 'Alerts' ? (
                    (alertsCount !== undefined ? alertsCount : item.badge) > 0 && (
                      <span className="nav-badge">{alertsCount !== undefined ? alertsCount : item.badge}</span>
                    )
                  ) : (
                    item.badge && <span className="nav-badge">{item.badge}</span>
                  )}
                </button>
              </li>
            )
          })}
        </ul>
      </nav>

      {/* User profile and Log Out section at the bottom */}
      <div className="user-profile-wrapper" style={{ padding: '0 8px 16px 8px', borderTop: '1px solid rgba(255, 255, 255, 0.05)' }}>
        <div className="user-profile-section" style={{ border: 'none', background: 'transparent', padding: '12px 8px 4px 8px' }}>
          <div className="user-avatar-container">
            <div className="user-avatar">AD</div>
            <div className="user-info">
              <span className="user-name">Admin User</span>
              <span className="user-role">Super Administrator</span>
            </div>
          </div>
        </div>
        <button className="sidebar-logout-btn" onClick={onLogout} title="Terminate Security Session">
          <LogOut size={16} />
          <span>Log Out</span>
        </button>
      </div>
    </aside>
  )
}

export default Sidebar
