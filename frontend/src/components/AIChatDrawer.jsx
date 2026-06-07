import React, { useState, useEffect, useRef } from 'react'
import { X, Sparkles, Send, Trash2, ShieldAlert, ShieldCheck, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { askAIChat, API_BASE_URL } from '../services/api'

function AIChatDrawer({ isOpen, onClose }) {
  const [sessions, setSessions] = useState(() => {
    const saved = localStorage.getItem('siem_chat_sessions')
    if (saved) {
      try {
        const parsed = JSON.parse(saved)
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed
        }
      } catch (e) {
        console.error('Error parsing saved sessions:', e)
      }
    }
    return [
      {
        id: Date.now().toString(),
        title: 'New Chat',
        messages: [
          {
            role: 'assistant',
            content: 'Hello! I am your AI Security Analyst Assistant. Ask me anything about logs, intrusion mitigation, or firewall rules!'
          }
        ]
      }
    ]
  })

  const [activeSessionId, setActiveSessionId] = useState(() => {
    const savedActive = localStorage.getItem('siem_active_session_id')
    if (savedActive) {
      return savedActive
    }
    // Default to the first session
    const saved = localStorage.getItem('siem_chat_sessions')
    if (saved) {
      try {
        const parsed = JSON.parse(saved)
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed[0].id
        }
      } catch {}
    }
    return Date.now().toString()
  })

  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false)
  const messagesEndRef = useRef(null)

  const suggestions = [
    { label: 'Mitigate SQL Injection', query: 'How to mitigate SQL Injection attacks?' },
    { label: 'Mitigate Brute Force', query: 'How to protect against SSH Brute Force attacks?' },
    { label: 'Block Port Scan', query: 'How to defend against Network Port Scanning?' }
  ]

  const activeSession = sessions.find(s => s.id === activeSessionId) || sessions[0]
  const messages = activeSession ? activeSession.messages : []

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  // Load / save sessions and activeSessionId to localStorage
  useEffect(() => {
    localStorage.setItem('siem_chat_sessions', JSON.stringify(sessions))
  }, [sessions])

  useEffect(() => {
    localStorage.setItem('siem_active_session_id', activeSessionId)
  }, [activeSessionId])

  useEffect(() => {
    if (sessions.length > 0 && !sessions.some(s => s.id === activeSessionId)) {
      setActiveSessionId(sessions[0].id)
    }
  }, [sessions, activeSessionId])

  useEffect(() => {
    if (isOpen) {
      scrollToBottom()
    }
  }, [messages, isOpen])

  if (!isOpen) return null

  const setMessagesForActiveSession = (newMessagesOrUpdater) => {
    setSessions(prev => {
      return prev.map(s => {
        if (s.id === activeSessionId) {
          const updatedMsgs = typeof newMessagesOrUpdater === 'function' 
            ? newMessagesOrUpdater(s.messages) 
            : newMessagesOrUpdater
          
          let title = s.title
          if (s.title === 'New Chat' || s.messages.length <= 1) {
            const firstUserMsg = updatedMsgs.find(m => m.role === 'user')
            if (firstUserMsg) {
              const prompt = firstUserMsg.content
              title = prompt.length > 22 ? prompt.substring(0, 20) + '...' : prompt
            }
          }
          return { ...s, title, messages: updatedMsgs }
        }
        return s
      })
    })
  }

  const handleSend = async (textToSend) => {
    const prompt = textToSend.trim()
    if (!prompt) return

    // 1. Add user message
    setMessagesForActiveSession(prev => [...prev, { role: 'user', content: prompt }])
    setInput('')
    setLoading(true)

    try {
      const url = `${API_BASE_URL}/alerts/chat`
      
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ prompt })
      })

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let accumulatedResponse = ''

      setLoading(false) // Turn off loading spinner once streaming starts

      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        const chunk = decoder.decode(value, { stream: true })
        accumulatedResponse += chunk

        // Update the last message content with the accumulated text
        setSessions(prev => {
          return prev.map(s => {
            if (s.id === activeSessionId) {
              const updatedMessages = [...s.messages]
              if (updatedMessages.length > 0) {
                const lastMsg = updatedMessages[updatedMessages.length - 1]
                if (lastMsg.role === 'user') {
                  updatedMessages.push({
                    role: 'assistant',
                    content: accumulatedResponse
                  })
                } else {
                  updatedMessages[updatedMessages.length - 1] = {
                    role: 'assistant',
                    content: accumulatedResponse
                  }
                }
              }
              
              // Also update title if new chat
              let title = s.title
              if (s.title === 'New Chat' || s.messages.length <= 2) {
                const firstUserMsg = updatedMessages.find(m => m.role === 'user')
                if (firstUserMsg) {
                  const pText = firstUserMsg.content
                  title = pText.length > 22 ? pText.substring(0, 20) + '...' : pText
                }
              }

              return { ...s, title, messages: updatedMessages }
            }
            return s
          })
        })
      }
    } catch (err) {
      console.error(err)
      const errDetail = err.message || String(err)
      setSessions(prev => {
        return prev.map(s => {
          if (s.id === activeSessionId) {
            const updatedMessages = [...s.messages]
            if (updatedMessages.length > 0) {
              const lastMsg = updatedMessages[updatedMessages.length - 1]
              if (lastMsg.role === 'assistant') {
                updatedMessages[updatedMessages.length - 1] = {
                  role: 'assistant',
                  content: `An unexpected error occurred: ${errDetail}. Please verify your connection.`
                }
              } else {
                updatedMessages.push({
                  role: 'assistant',
                  content: `An unexpected error occurred: ${errDetail}. Please verify your connection.`
                })
              }
            }
            return { ...s, messages: updatedMessages }
          }
          return s
        })
      })
    } finally {
      setLoading(false)
    }
  }

  const handleNewChat = () => {
    const newId = Date.now().toString()
    const newSession = {
      id: newId,
      title: 'New Chat',
      messages: [
        {
          role: 'assistant',
          content: 'Hello! I am your AI Security Analyst Assistant. Ask me anything about logs, intrusion mitigation, or firewall rules!'
        }
      ]
    }
    setSessions(prev => [newSession, ...prev])
    setActiveSessionId(newId)
  }

  const handleDeleteSession = (idToDelete) => {
    if (window.confirm("Are you sure you want to delete this conversation session?")) {
      setSessions(prev => {
        const filtered = prev.filter(s => s.id !== idToDelete)
        if (filtered.length === 0) {
          return [
            {
              id: Date.now().toString(),
              title: 'New Chat',
              messages: [
                {
                  role: 'assistant',
                  content: 'Hello! I am your AI Security Analyst Assistant. Ask me anything about logs, intrusion mitigation, or firewall rules!'
                }
              ]
            }
          ]
        }
        return filtered
      })
    }
  }

  const handleClearActiveSession = () => {
    if (window.confirm("Are you sure you want to reset this chat session?")) {
      setMessagesForActiveSession([
        {
          role: 'assistant',
          content: 'Hello! I am your AI Security Analyst Assistant. Ask me anything about logs, intrusion mitigation, or firewall rules!'
        }
      ])
    }
  }

  const parseMarkdown = (text) => {
    if (!text) return null
    
    const lines = text.split('\n')
    const elements = []
    let currentKey = 0

    let inCodeBlock = false
    let codeLines = []
    let codeLang = ''

    let inTable = false
    let tableHeaders = null
    let tableRows = []

    let inList = false
    let listType = null // 'ul' or 'ol'
    let listItems = []

    const parseInline = (inlineText) => {
      if (!inlineText) return ''
      const regex = /(\*\*.*?\*\*|\*.*?\*|`.*?`|\[.*?\]\(.*?\))/g
      const segments = inlineText.split(regex)
      
      return segments.map((seg, i) => {
        if (seg.startsWith('**') && seg.endsWith('**')) {
          return <strong key={i} style={{ color: '#fff', fontWeight: '700' }}>{seg.slice(2, -2)}</strong>
        }
        if (seg.startsWith('*') && seg.endsWith('*')) {
          return <em key={i} style={{ fontStyle: 'italic', color: 'hsl(var(--text-secondary))' }}>{seg.slice(1, -1)}</em>
        }
        if (seg.startsWith('`') && seg.endsWith('`')) {
          return <code key={i} style={{ 
            background: 'rgba(255, 255, 255, 0.08)', 
            padding: '2px 6px', 
            borderRadius: '4px', 
            fontFamily: 'monospace',
            fontSize: '0.85em',
            color: 'hsl(var(--color-ai-cyan))'
          }}>{seg.slice(1, -1)}</code>
        }
        const linkMatch = seg.match(/^\[(.*?)\]\((.*?)\)$/)
        if (linkMatch) {
          return <a key={i} href={linkMatch[2]} target="_blank" rel="noopener noreferrer" style={{ color: 'hsl(var(--color-primary))', textDecoration: 'underline' }}>{linkMatch[1]}</a>
        }
        return seg
      })
    }

    const flushTable = () => {
      if (!inTable) return
      inTable = false
      const headers = tableHeaders
      const rows = [...tableRows]
      tableHeaders = null
      tableRows = []

      elements.push(
        <div key={`table-${currentKey++}`} style={{ margin: '12px 0', width: '100%', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.08)', background: 'rgba(7, 10, 19, 0.3)' }}>
          <table style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: '0.8rem',
            color: 'hsl(var(--text-secondary))',
            tableLayout: 'fixed'
          }}>
            {headers && (
              <thead>
                <tr style={{ background: 'rgba(255, 255, 255, 0.06)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  {headers.map((h, i) => (
                    <th key={i} style={{ padding: '8px 10px', textAlign: 'left', fontWeight: '600', color: '#fff', borderRight: '1px solid rgba(255, 255, 255, 0.05)', wordBreak: 'break-word', whiteSpace: 'normal' }}>{parseInline(h)}</th>
                  ))}
                </tr>
              </thead>
            )}
            <tbody>
              {rows.map((row, rIdx) => (
                <tr key={rIdx} style={{ 
                  borderBottom: rIdx === rows.length - 1 ? 'none' : '1px solid rgba(255, 255, 255, 0.04)',
                  background: rIdx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)'
                }}>
                  {row.map((cell, cIdx) => (
                    <td key={cIdx} style={{ padding: '8px 10px', borderRight: '1px solid rgba(255, 255, 255, 0.05)', wordBreak: 'break-word', whiteSpace: 'normal' }}>{parseInline(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
    }

    const flushCodeBlock = () => {
      if (!inCodeBlock) return
      inCodeBlock = false
      const content = codeLines.join('\n')
      codeLines = []
      elements.push(
        <pre key={`code-${currentKey++}`} style={{
          background: 'rgba(7, 10, 19, 0.8)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '6px',
          padding: '12px',
          margin: '12px 0',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          overflowX: 'hidden',
          fontFamily: 'monospace',
          fontSize: '0.8rem',
          color: '#e0e0e0'
        }}>
          <code>{content}</code>
        </pre>
      )
    }

    const flushList = () => {
      if (!inList) return
      inList = false
      const items = [...listItems]
      const type = listType
      listItems = []
      listType = null

      const Tag = type === 'ol' ? 'ol' : 'ul'
      elements.push(
        <Tag key={`list-${currentKey++}`} style={{
          paddingLeft: '20px',
          margin: '8px 0',
          listStyleType: type === 'ol' ? 'decimal' : 'disc'
        }}>
          {items.map((item, idx) => (
            <li key={idx} style={{ marginBottom: '4px', color: 'hsl(var(--text-secondary))' }}>{parseInline(item)}</li>
          ))}
        </Tag>
      )
    }

    const flushAll = () => {
      flushTable()
      flushCodeBlock()
      flushList()
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      const trimmed = line.trim()

      if (trimmed.startsWith('```')) {
        if (inCodeBlock) {
          flushCodeBlock()
        } else {
          flushAll()
          inCodeBlock = true
          codeLang = trimmed.slice(3).trim()
        }
        continue
      }

      if (inCodeBlock) {
        codeLines.push(line)
        continue
      }

      if (trimmed.startsWith('|')) {
        flushCodeBlock()
        flushList()
        
        const cells = line.split('|').map(c => c.trim())
        if (cells[0] === '') cells.shift()
        if (cells[cells.length - 1] === '') cells.pop()

        const isSeparator = cells.every(c => /^:?-+:?$/.test(c) || c === '')
        
        if (isSeparator) {
          inTable = true
          continue
        }

        if (!inTable) {
          inTable = true
          tableHeaders = cells
        } else {
          tableRows.push(cells)
        }
        continue
      } else {
        if (inTable) {
          flushTable()
        }
      }

      const olMatch = trimmed.match(/^(\d+)\.\s+(.*)/)
      const ulMatch = trimmed.match(/^([*\-+])\s+(.*)/)

      if (olMatch) {
        if (inList && listType !== 'ol') {
          flushList()
        }
        inList = true
        listType = 'ol'
        listItems.push(olMatch[2])
        continue
      } else if (ulMatch) {
        if (inList && listType !== 'ul') {
          flushList()
        }
        inList = true
        listType = 'ul'
        listItems.push(ulMatch[2])
        continue
      } else {
        if (inList) {
          flushList()
        }
      }

      if (trimmed === '---' || trimmed === '***' || trimmed === '___') {
        flushAll()
        elements.push(<hr key={`hr-${currentKey++}`} style={{ border: 'none', borderTop: '1px solid rgba(255, 255, 255, 0.1)', margin: '16px 0' }} />)
        continue
      }

      const headerMatch = trimmed.match(/^(#{1,6})\s+(.*)/)
      if (headerMatch) {
        flushAll()
        const level = headerMatch[1].length
        const content = headerMatch[2]
        const headerStyles = {
          color: '#fff',
          fontWeight: '600',
          marginTop: '14px',
          marginBottom: '8px',
        }
        
        let tag
        if (level === 1) tag = <h1 key={`h-${currentKey++}`} style={{ ...headerStyles, fontSize: '1.25rem', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', paddingBottom: '4px' }}>{parseInline(content)}</h1>
        else if (level === 2) tag = <h2 key={`h-${currentKey++}`} style={{ ...headerStyles, fontSize: '1.15rem' }}>{parseInline(content)}</h2>
        else if (level === 3) tag = <h3 key={`h-${currentKey++}`} style={{ ...headerStyles, fontSize: '1.05rem' }}>{parseInline(content)}</h3>
        else tag = <h4 key={`h-${currentKey++}`} style={{ ...headerStyles, fontSize: '0.95rem' }}>{parseInline(content)}</h4>
        
        elements.push(tag)
        continue
      }

      if (trimmed === '') {
        elements.push(<div key={`space-${currentKey++}`} style={{ height: '8px' }} />)
      } else {
        elements.push(
          <p key={`p-${currentKey++}`} style={{ margin: '6px 0', color: 'hsl(var(--text-secondary))', lineHeight: '1.6' }}>
            {parseInline(line)}
          </p>
        )
      }
    }

    flushAll()
    return elements
  }

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-container chat-drawer-container glass-panel" onClick={(e) => e.stopPropagation()} style={{ display: 'flex', flexDirection: 'row', overflow: 'hidden', padding: 0 }}>
        {/* Left Sessions Sidebar */}
        <div style={{
          width: isSidebarCollapsed ? '0px' : '200px',
          borderRight: isSidebarCollapsed ? 'none' : '1px solid rgba(255, 255, 255, 0.08)',
          display: isSidebarCollapsed ? 'none' : 'flex',
          flexDirection: 'column',
          background: 'rgba(7, 10, 19, 0.45)',
          overflow: 'hidden'
        }}>
          {/* New Chat Button */}
          <button 
            onClick={handleNewChat}
            style={{
              margin: '16px 12px 12px 12px',
              padding: '10px',
              borderRadius: '6px',
              border: '1px dashed rgba(160, 97, 255, 0.4)',
              background: 'rgba(160, 97, 255, 0.05)',
              color: '#fff',
              fontSize: '0.8rem',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              transition: 'all 0.2s',
              outline: 'none'
            }}
            onMouseOver={e => {
              e.currentTarget.style.background = 'rgba(160, 97, 255, 0.12)'
              e.currentTarget.style.borderColor = 'rgba(160, 97, 255, 0.7)'
            }}
            onMouseOut={e => {
              e.currentTarget.style.background = 'rgba(160, 97, 255, 0.05)'
              e.currentTarget.style.borderColor = 'rgba(160, 97, 255, 0.4)'
            }}
          >
            <Sparkles size={13} style={{ color: 'var(--color-ai-cyan)' }} />
            New Chat
          </button>
          
          {/* Sessions List */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '0 8px 12px 8px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {sessions.map(s => {
              const isActive = s.id === activeSessionId
              return (
                <div 
                  key={s.id}
                  onClick={() => setActiveSessionId(s.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '8px 10px',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    background: isActive ? 'rgba(255, 255, 255, 0.06)' : 'transparent',
                    border: isActive ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid transparent',
                    transition: 'all 0.15s'
                  }}
                  onMouseOver={e => {
                    if (!isActive) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)'
                  }}
                  onMouseOut={e => {
                    if (!isActive) e.currentTarget.style.background = 'transparent'
                  }}
                >
                  <span style={{
                    fontSize: '0.75rem',
                    color: isActive ? '#fff' : 'hsl(var(--text-secondary))',
                    fontWeight: isActive ? '600' : '400',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    flex: 1,
                    marginRight: '6px'
                  }}>
                    {s.title}
                  </span>
                  
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      handleDeleteSession(s.id)
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'rgba(255, 255, 255, 0.2)',
                      cursor: 'pointer',
                      padding: '2px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      borderRadius: '3px',
                      transition: 'all 0.15s'
                    }}
                    onMouseOver={(e) => {
                      e.currentTarget.style.color = 'hsl(var(--sev-critical))'
                      e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'
                    }}
                    onMouseOut={(e) => {
                      e.currentTarget.style.color = 'rgba(255, 255, 255, 0.2)'
                      e.currentTarget.style.background = 'none'
                    }}
                    title="Delete session"
                  >
                    <Trash2 size={11} />
                  </button>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Chat Panel */}
        <div 
          onClick={() => setIsSidebarCollapsed(true)}
          style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        >
          {/* Header */}
          <div className="drawer-header" style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div className="drawer-title-wrapper" style={{ display: 'flex', alignItems: 'center' }}>
              <button 
                onClick={(e) => {
                  e.stopPropagation()
                  setIsSidebarCollapsed(!isSidebarCollapsed)
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'hsl(var(--text-secondary))',
                  cursor: 'pointer',
                  padding: '6px',
                  marginRight: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: '4px',
                  backgroundColor: 'rgba(255,255,255,0.02)',
                  border: '1px solid rgba(255,255,255,0.05)'
                }}
                title={isSidebarCollapsed ? "Expand conversation list" : "Collapse conversation list"}
              >
                {isSidebarCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
              </button>
              <Sparkles size={20} className="ai-glow-icon" style={{ color: 'var(--color-ai-cyan)', marginRight: '8px' }} />
              <h2 className="ai-gradient-text" style={{ fontSize: '1.2rem', fontWeight: 700 }}>AI Security Assistant</h2>
            </div>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <button 
                onClick={handleClearActiveSession} 
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'hsl(var(--text-secondary))',
                  cursor: 'pointer',
                  padding: '4px'
                }}
                title="Reset current chat session"
              >
                <Trash2 size={16} />
              </button>
              <button className="drawer-close-btn" onClick={onClose} title="Close Assistant">
                <X size={18} />
              </button>
            </div>
          </div>

          {/* Chat Body */}
          <div style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            padding: '20px 20px 10px 20px'
          }}>
            {/* Scrollable messages area */}
            <div style={{
              flex: 1,
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
              paddingRight: '6px'
            }}>
               {messages.map((msg, idx) => {
                if (!msg.content || !msg.content.trim()) return null
                const isUser = msg.role === 'user'
                return (
                  <div 
                    key={idx} 
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: isUser ? 'flex-end' : 'flex-start',
                      maxWidth: '85%',
                      alignSelf: isUser ? 'flex-end' : 'flex-start'
                    }}
                  >
                    <div style={{
                      padding: '12px 16px',
                      borderRadius: '12px',
                      borderTopRightRadius: isUser ? '2px' : '12px',
                      borderTopLeftRadius: isUser ? '12px' : '2px',
                      fontSize: '0.85rem',
                      lineHeight: '1.5',
                      color: '#fff',
                      whiteSpace: isUser ? 'pre-wrap' : 'normal',
                      background: isUser 
                        ? 'linear-gradient(135deg, rgba(160, 97, 255, 0.2), rgba(120, 119, 253, 0.2))' 
                        : 'rgba(255, 255, 255, 0.04)',
                      border: isUser 
                        ? '1px solid rgba(160, 97, 255, 0.3)' 
                        : '1px solid rgba(255, 255, 255, 0.05)'
                    }}>
                      {isUser ? msg.content : parseMarkdown(msg.content)}
                    </div>
                    <span style={{
                      fontSize: '0.7rem',
                      color: 'hsl(var(--text-secondary))',
                      marginTop: '4px',
                      padding: '0 4px'
                    }}>
                      {isUser ? 'Analyst' : 'Gemini SIEM Advisor'}
                    </span>
                  </div>
                )
              })}

              {loading && (
                <div className="typing-dots">
                  <div className="typing-dot"></div>
                  <div className="typing-dot"></div>
                  <div className="typing-dot"></div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Quick Suggestion Chips */}
            <div style={{
              display: 'flex',
              gap: '8px',
              flexWrap: 'wrap',
              marginTop: '12px',
              borderTop: '1px solid rgba(255, 255, 255, 0.05)',
              paddingTop: '12px'
            }}>
              {suggestions.map((chip, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSend(chip.query)}
                  disabled={loading}
                  style={{
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                    borderRadius: '16px',
                    padding: '6px 12px',
                    color: 'hsl(var(--text-secondary))',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    outline: 'none'
                  }}
                  onMouseOver={(e) => {
                    e.currentTarget.style.background = 'rgba(160, 97, 255, 0.1)'
                    e.currentTarget.style.borderColor = 'rgba(160, 97, 255, 0.3)'
                    e.currentTarget.style.color = '#fff'
                  }}
                  onMouseOut={(e) => {
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)'
                    e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.05)'
                    e.currentTarget.style.color = 'hsl(var(--text-secondary))'
                  }}
                >
                  {chip.label}
                </button>
              ))}
            </div>

            {/* Input Panel */}
            <form 
              onSubmit={(e) => {
                e.preventDefault()
                handleSend(input)
              }}
              style={{
                display: 'flex',
                gap: '10px',
                padding: '12px 0 8px 0',
                alignItems: 'center'
              }}
            >
              <input
                type="text"
                placeholder="Ask a security question..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                disabled={loading}
                style={{
                  flex: 1,
                  backgroundColor: 'rgba(7, 10, 19, 0.6)',
                  border: '1px solid hsl(var(--border-color))',
                  borderRadius: '8px',
                  padding: '10px 14px',
                  color: '#fff',
                  fontSize: '0.85rem',
                  outline: 'none'
                }}
              />
              <button
                type="submit"
                disabled={loading || !input.trim()}
                style={{
                  background: 'linear-gradient(135deg, hsl(var(--color-ai-purple)), hsl(var(--color-ai-cyan)))',
                  border: 'none',
                  borderRadius: '8px',
                  width: '38px',
                  height: '38px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#fff',
                  cursor: 'pointer',
                  opacity: (loading || !input.trim()) ? 0.5 : 1,
                  transition: 'all 0.2s ease'
                }}
              >
                <Send size={16} />
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AIChatDrawer
