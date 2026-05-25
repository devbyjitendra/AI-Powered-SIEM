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
  ChevronDown
} from 'lucide-react'

// Navigation configuration matching reference mockup image exactly
const NAV_ITEMS = [
  { name: 'Dashboard', icon: LayoutDashboard },
  { name: 'Alerts', icon: Bell, badge: 12 },
  { name: 'Incidents', icon: ShieldAlert },
  { name: 'Threat Intelligence', icon: Globe },
  { name: 'UEBA', icon: UserCheck },
  { name: 'Log Management', icon: FileSpreadsheet },
  { name: 'Case Management', icon: FolderLock },
  { name: 'Reports', icon: LineChart },
  { name: 'Automation', icon: Cpu },
  { name: 'Integrations', icon: Layers },
  { name: 'Assets', icon: Server },
  { name: 'Settings', icon: Settings },
]

function Sidebar({ activeTab, setActiveTab }) {
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
                  {item.badge && <span className="nav-badge">{item.badge}</span>}
                </button>
              </li>
            )
          })}
        </ul>
      </nav>

      {/* User profile section at the bottom */}
      <div className="user-profile-section">
        <div className="user-avatar-container">
          <div className="user-avatar">AD</div>
          <div className="user-info">
            <span className="user-name">Admin User</span>
            <span className="user-role">Super Administrator</span>
          </div>
        </div>
        <ChevronDown size={14} className="profile-arrow" />
      </div>
    </aside>
  )
}

export default Sidebar
