import React, { useState } from 'react'
import { Play, Terminal, Trash2, Cpu, ShieldAlert, Database, HelpCircle } from 'lucide-react'
import { ingestLogs } from '../services/api'

const ATTACK_TEMPLATES = [
  {
    id: 'ssh_brute_force',
    name: 'SSH Brute Force',
    description: 'Generates 5 rapid failed login attempts from a single external IP address to trigger the SSH Brute Force Detection rule.',
    eventType: 'auth',
    severity: 'WARNING',
    ruleTrigger: 'RULE-AUTH-BRUTEFORCE',
    generate: (ip = '198.51.100.45') => {
      const now = new Date();
      return Array.from({ length: 5 }).map((_, i) => {
        const time = new Date(now.getTime() - (5 - i) * 1000);
        return {
          event_type: 'auth',
          severity: 'WARNING',
          message: `sshd[28451]: Failed password for invalid user admin from ${ip} port 49152 ssh2`,
          raw_payload: `${time.toISOString()} server sshd[28451]: Failed password for invalid user admin from ${ip} port 49152 ssh2`,
          source_ip: ip,
          destination_ip: '10.0.0.15',
          source_port: 49152 + i,
          destination_port: 22,
          user_id: 'admin',
          timestamp: time.toISOString(),
          user_agent: 'SSH-2.0-OpenSSH_8.2p1'
        };
      });
    }
  },
  {
    id: 'sql_injection',
    name: 'SQL Injection (SQLi)',
    description: 'Generates a web application log containing a classic SQL injection payload attempting to bypass authentication.',
    eventType: 'web',
    severity: 'ERROR',
    ruleTrigger: 'RULE-WEB-SQLI',
    generate: (ip = '203.0.113.82') => {
      const time = new Date();
      return [{
        event_type: 'web',
        severity: 'ERROR',
        message: `WAF: SQL Injection detected on login page payload: ' OR '1'='1`,
        raw_payload: `GET /login.php?user=admin' OR '1'='1&pass=test HTTP/1.1\nHost: securebank.com\nUser-Agent: Mozilla/5.0\nIP: ${ip}`,
        source_ip: ip,
        destination_ip: '10.0.0.80',
        source_port: 52143,
        destination_port: 443,
        user_id: 'guest',
        timestamp: time.toISOString(),
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }];
    }
  },
  {
    id: 'distributed_brute_force',
    name: 'Distributed Brute Force',
    description: 'Simulates authentication failures targeting a single critical user (e.g. root) from 5 different geographical IPs.',
    eventType: 'auth',
    severity: 'WARNING',
    ruleTrigger: 'RULE-DIST-BRUTEFORCE',
    generate: () => {
      const now = new Date();
      const ips = ['198.51.100.10', '203.0.113.25', '185.190.140.40', '95.142.100.12', '82.102.23.9'];
      return ips.map((ip, i) => {
        const time = new Date(now.getTime() - (5 - i) * 1000);
        return {
          event_type: 'auth',
          severity: 'WARNING',
          message: `sshd[31200]: Failed password for root from ${ip} port 38290 ssh2`,
          raw_payload: `${time.toISOString()} server sshd[31200]: Failed password for root from ${ip} port 38290 ssh2`,
          source_ip: ip,
          destination_ip: '10.0.0.15',
          source_port: 38290,
          destination_port: 22,
          user_id: 'root',
          timestamp: time.toISOString(),
          user_agent: 'SSH-2.0-OpenSSH_8.0'
        };
      });
    }
  },
  {
    id: 'credential_stuffing',
    name: 'Credential Stuffing',
    description: 'Simulates a single threat actor IP attempting to log in to 5 different accounts in a very short duration.',
    eventType: 'auth',
    severity: 'WARNING',
    ruleTrigger: 'RULE-CRED-STUFFING',
    generate: (ip = '185.220.101.5') => {
      const now = new Date();
      const users = ['john', 'sarah', 'michael', 'jessica', 'david'];
      return users.map((user, i) => {
        const time = new Date(now.getTime() - (5 - i) * 1000);
        return {
          event_type: 'auth',
          severity: 'WARNING',
          message: `sshd[31405]: Failed password for ${user} from ${ip} port 51102 ssh2`,
          raw_payload: `${time.toISOString()} server sshd[31405]: Failed password for ${user} from ${ip} port 51102 ssh2`,
          source_ip: ip,
          destination_ip: '10.0.0.15',
          source_port: 51102,
          destination_port: 22,
          user_id: user,
          timestamp: time.toISOString(),
          user_agent: 'SSH-2.0-Go'
        };
      });
    }
  },
  {
    id: 'port_scan',
    name: 'Port Scan / Reconnaissance',
    description: 'Generates consecutive firewall block events across sequential target ports (e.g. 21, 22, 80, 443, 8080) from a single IP.',
    eventType: 'firewall',
    severity: 'INFO',
    ruleTrigger: 'RULE-FIREWALL-PORTSCAN',
    generate: (ip = '93.184.216.34') => {
      const now = new Date();
      const ports = [21, 22, 23, 25, 80, 110, 443, 8080];
      return ports.map((port, i) => {
        const time = new Date(now.getTime() - (ports.length - i) * 500);
        return {
          event_type: 'firewall',
          severity: 'INFO',
          message: `Firewall blocked connection attempt from ${ip} to port ${port}`,
          raw_payload: `rule=104 action=block src=${ip} dst=10.0.0.5 proto=tcp sport=54321 dport=${port}`,
          source_ip: ip,
          destination_ip: '10.0.0.5',
          source_port: 54321,
          destination_port: port,
          timestamp: time.toISOString(),
          user_agent: 'Nmap Scripting Engine'
        };
      });
    }
  }
]

function Simulator() {
  const [consoleLogs, setConsoleLogs] = useState([])
  const [asyncMode, setAsyncMode] = useState(false)
  const [isSimulating, setIsSimulating] = useState(null)
  const [customIp, setCustomIp] = useState('')

  const appendToConsole = (type, message, details = null) => {
    setConsoleLogs((prev) => [
      ...prev,
      {
        time: new Date().toLocaleTimeString(),
        type, // 'info', 'success', 'error', 'log'
        message,
        details
      }
    ])
  }

  const runSimulation = async (template) => {
    setIsSimulating(template.id)
    appendToConsole('info', `Initializing ${template.name} simulation...`)

    // Use custom IP if provided for templates that support it
    const ip = customIp.trim() || undefined
    const mockLogs = template.generate(ip)
    
    appendToConsole('log', `Generated ${mockLogs.length} structured security logs:`, mockLogs)

    try {
      appendToConsole('info', `Sending POST request to /api/v1/logs/ingest (async_mode=${asyncMode})...`)
      const response = await ingestLogs(mockLogs, asyncMode)
      
      if (response) {
        appendToConsole('success', `API Response Status: ${response.status.toUpperCase()}`)
        appendToConsole('success', `Message: ${response.message}`)
        appendToConsole('success', `Ingested count: ${response.count}`)
      } else {
        appendToConsole('error', 'API Response: Failed to communicate with ingest server.')
      }
    } catch (err) {
      appendToConsole('error', `Error sending logs: ${err.message}`)
    } finally {
      setIsSimulating(null)
    }
  }

  const clearConsole = () => {
    setConsoleLogs([])
  }

  return (
    <div className="simulator-layout">
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: '700', color: '#fff', fontFamily: "'Outfit', sans-serif" }}>
          Log Management & Attack Simulator
        </h1>
        <span style={{ fontSize: '0.85rem', color: 'hsl(var(--text-secondary))' }}>
          Simulate real-world security incident vectors and feed threat intelligence logs directly into the correlation engine.
        </span>
      </div>

      <div className="simulator-grid">
        {/* Left Side - Attack Controllers */}
        <div className="simulator-card-column">
          <div className="glass-panel simulator-card settings-card">
            <h3 className="card-title"><Cpu size={18} className="card-icon" /> Ingestion Settings</h3>
            <div className="settings-form">
              <div className="form-group">
                <label className="form-label">Simulation Mode</label>
                <div className="toggle-switch-wrapper" onClick={() => setAsyncMode(!asyncMode)}>
                  <div className={`toggle-track ${asyncMode ? 'active' : ''}`}>
                    <div className="toggle-thumb" />
                  </div>
                  <span className="toggle-label">
                    {asyncMode ? 'Asynchronous Queue (High Throughput)' : 'Synchronous direct injection (Immediate Processing)'}
                  </span>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="custom-ip">Override Source IP (Optional)</label>
                <input 
                  type="text" 
                  id="custom-ip"
                  className="search-input" 
                  placeholder="e.g. 8.8.8.8"
                  value={customIp}
                  onChange={(e) => setCustomIp(e.target.value)}
                  style={{ borderRadius: '8px', padding: '10px 14px' }}
                />
              </div>
            </div>
          </div>

          <div className="templates-list">
            {ATTACK_TEMPLATES.map((template) => (
              <div key={template.id} className="glass-panel attack-template-card">
                <div className="template-info">
                  <div className="template-header">
                    <h4 className="template-name">{template.name}</h4>
                    <span className="template-badge">{template.eventType}</span>
                  </div>
                  <p className="template-desc">{template.description}</p>
                  <div className="rule-association">
                    <ShieldAlert size={12} className="rule-icon" />
                    <span>Target rule: <strong>{template.ruleTrigger}</strong></span>
                  </div>
                </div>
                <button
                  className="ai-gradient-btn run-simulation-btn"
                  onClick={() => runSimulation(template)}
                  disabled={isSimulating !== null}
                >
                  <Play size={14} fill="currentColor" />
                  <span>{isSimulating === template.id ? 'Injecting...' : 'Simulate'}</span>
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Right Side - Terminal Output */}
        <div className="simulator-terminal-column">
          <div className="glass-panel terminal-card flex-column">
            <div className="terminal-header">
              <div className="terminal-title-container">
                <Terminal size={16} className="terminal-icon" />
                <span>Simulated Ingestion Stream Console</span>
              </div>
              <button className="grid-refresh-btn clear-btn" onClick={clearConsole} title="Clear Terminal">
                <Trash2 size={14} />
                <span>Clear</span>
              </button>
            </div>
            
            <div className="terminal-body">
              {consoleLogs.length === 0 ? (
                <div className="terminal-empty-state">
                  <Terminal size={40} className="terminal-placeholder-icon" />
                  <p>Console Idle. Run a simulation from the panel to view log execution output.</p>
                </div>
              ) : (
                <div className="terminal-feed">
                  {consoleLogs.map((log, index) => (
                    <div key={index} className={`terminal-line line-${log.type}`}>
                      <span className="line-time">[{log.time}]</span>
                      <span className="line-indicator">
                        {log.type === 'info' && '⚙️ [INFO]'}
                        {log.type === 'success' && '✅ [SUCCESS]'}
                        {log.type === 'error' && '❌ [ERROR]'}
                        {log.type === 'log' && '📦 [LOG GENERATED]'}
                      </span>
                      <span className="line-message">{log.message}</span>
                      {log.details && (
                        <pre className="line-json-details">
                          {JSON.stringify(log.details, null, 2)}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Simulator
