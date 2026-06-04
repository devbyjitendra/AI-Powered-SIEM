import React, { useEffect, useState } from 'react'
import { Server, ShieldAlert, Cpu, HardDrive, ShieldCheck } from 'lucide-react'
import { getDashboardStats } from '../services/api'

function AssetsPanel() {
  const [assets, setAssets] = useState([])

  useEffect(() => {
    async function loadAssets() {
      const data = await getDashboardStats()
      if (data && data.assets) {
        setAssets(data.assets)
      }
    }
    loadAssets()
    
    const interval = setInterval(loadAssets, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleIsolateAsset = (assetId) => {
    alert(`Asset ${assetId} network isolation sequence initiated. Playbook auto-running.`)
    setAssets(prev => prev.map(a => a.id === assetId ? { ...a, status: 'Isolated', severity: 'low', vulnerabilityScore: 0 } : a))
  }

  return (
    <div className="assets-layout">
      {/* Header */}
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
          Protected Network Assets & Host Discovery
        </h1>
        <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
          Monitor internal subnets, active server nodes, and track operating system vulnerability status.
        </span>
      </div>

      <div className="simulator-grid" style={{ gridTemplateColumns: '1fr' }}>
        <div className="glass-panel simulator-card">
          <h3 className="card-title">
            <Server size={18} className="card-icon" /> Host Inventory Directory
          </h3>
          
          <div className="table-responsive">
            <table className="sources-table">
              <thead>
                <tr>
                  <th>Host Identity</th>
                  <th>IP Routing Address</th>
                  <th>Operating Environment</th>
                  <th>Vuln Risk Score</th>
                  <th>Active Status</th>
                  <th style={{ textAlign: 'right' }}>Incident Response</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => {
                  const statusColor = asset.status === 'Online' ? 'hsl(var(--sev-low))' : 
                                      asset.status === 'Offline' ? 'hsl(var(--text-muted))' : 'hsl(var(--sev-medium))'
                  
                  return (
                    <tr key={asset.id} className="alert-row">
                      <td className="ip-cell" style={{ color: '#fff' }}>{asset.id}</td>
                      <td className="source-cell" style={{ fontFamily: 'monospace' }}>{asset.ip}</td>
                      <td className="source-cell">{asset.os}</td>
                      <td>
                        <span className={`severity-tag label-${asset.severity}`} style={{ fontWeight: '700' }}>
                          Index: {asset.vulnerabilityScore}/100
                        </span>
                      </td>
                      <td>
                        <span style={{ fontSize: '0.8rem', fontWeight: '600', color: statusColor }}>
                          ● {asset.status}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {asset.status === 'Online' && asset.vulnerabilityScore > 40 ? (
                          <button 
                            className="grid-refresh-btn" 
                            onClick={() => handleIsolateAsset(asset.id)}
                            style={{ 
                              padding: '4px 10px', 
                              fontSize: '0.75rem', 
                              borderColor: 'rgba(239, 68, 68, 0.3)',
                              color: 'hsl(var(--sev-critical))',
                              backgroundColor: 'rgba(239, 68, 68, 0.05)'
                            }}
                          >
                            Isolate Host
                          </button>
                        ) : asset.status === 'Isolated' ? (
                          <span style={{ fontSize: '0.75rem', color: 'hsl(var(--sev-low))', fontWeight: '600' }}>
                            ✓ Secure Sandbox
                          </span>
                        ) : (
                          <span style={{ fontSize: '0.75rem', color: 'hsl(var(--text-muted))' }}>
                            No Actions Required
                          </span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AssetsPanel
