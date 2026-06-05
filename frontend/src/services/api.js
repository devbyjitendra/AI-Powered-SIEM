const getApiBaseUrl = () => {
  let url = import.meta.env.VITE_API_BASE_URL
  if (url) {
    url = url.trim()
    if (url.endsWith('/')) {
      url = url.slice(0, -1)
    }
    if (!url.endsWith('/api/v1')) {
      url = `${url}/api/v1`
    }
    return url
  }
  let host = typeof window !== 'undefined' ? (window.location.hostname || '127.0.0.1') : '127.0.0.1'
  if (host === 'localhost') {
    host = '127.0.0.1'
  }
  return `http://${host}:8000/api/v1`
}
export const API_BASE_URL = getApiBaseUrl()


/**
 * Fetches alerts from the backend, supporting status and severity filters.
 */
export async function getAlerts(status = '', severity = '', startTime = '', endTime = '') {
  const params = new URLSearchParams()
  if (status) params.append('status', status)
  if (severity) params.append('severity', severity)
  if (startTime) params.append('start_time', startTime)
  if (endTime) params.append('end_time', endTime)
  params.append('_t', Date.now())
  
  const url = `${API_BASE_URL}/alerts?${params.toString()}`
  
  try {
    const response = await fetch(url)
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to fetch alerts:', error)
    return []
  }
}

/**
 * Updates the investigation status of a specific alert.
 */
export async function updateAlertStatus(alertId, newStatus) {
  const url = `${API_BASE_URL}/alerts/${alertId}/status?alert_status=${newStatus}`
  
  try {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error(`Failed to update alert status for alert ID ${alertId}:`, error)
    return null
  }
}

/**
 * Submits logs to the ingestion pipeline.
 */
export async function ingestLogs(logsList, asyncMode = false) {
  const url = `${API_BASE_URL}/logs/ingest?async_mode=${asyncMode}`
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ logs: logsList })
    })
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to ingest logs:', error)
    return null
  }
}

/**
 * Fetches incident cases from the backend.
 */
export async function getCases(status = '', severity = '') {
  const params = new URLSearchParams()
  if (status) params.append('status', status)
  if (severity) params.append('severity', severity)
  params.append('_t', Date.now())
  
  const url = `${API_BASE_URL}/cases?${params.toString()}`
  
  try {
    const response = await fetch(url)
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to fetch cases:', error)
    return []
  }
}

/**
 * Creates a new incident case ticket.
 */
export async function createCase(caseData) {
  const url = `${API_BASE_URL}/cases`
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(caseData)
    })
    if (!response.ok) {
      const errText = await response.text()
      throw new Error(`HTTP ${response.status} - ${errText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to create case:', error)
    alert('Failed to escalate case. Error: ' + error.message)
    return null
  }
}

/**
 * Updates an existing incident case.
 */
export async function updateCase(caseId, updateData) {
  const url = `${API_BASE_URL}/cases/${caseId}`
  
  try {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(updateData)
    })
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error(`Failed to update case ${caseId}:`, error)
    return null
  }
}

/**
 * Deletes a security incident case.
 */
export async function deleteCase(caseId) {
  const url = `${API_BASE_URL}/cases/${caseId}`
  try {
    const response = await fetch(url, {
      method: 'DELETE'
    })
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return true
  } catch (error) {
    console.error(`Failed to delete case ${caseId}:`, error)
    return false
  }
}

/**
 * Associates a security alert to a case.
 */
export async function linkAlertToCase(caseId, alertId) {
  const url = `${API_BASE_URL}/cases/${caseId}/alerts?alert_id=${alertId}`
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({})
    })
    if (!response.ok) {
      const errText = await response.text()
      throw new Error(`HTTP ${response.status} - ${errText}`)
    }
    return await response.json()
  } catch (error) {
    console.error(`Failed to link alert ${alertId} to case ${caseId}:`, error)
    alert('Failed to link case. Error: ' + error.message)
    return null
  }
}

/**
 * Fetches all detection rules.
 */
export async function getRules() {
  const url = `${API_BASE_URL}/rules?_t=${Date.now()}`
  try {
    const response = await fetch(url)
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to fetch rules:', error)
    return []
  }
}

/**
 * Updates a detection rule's parameters (e.g. is_active).
 */
export async function updateRule(ruleId, ruleData) {
  const url = `${API_BASE_URL}/rules/${ruleId}`
  try {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(ruleData)
    })
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error(`Failed to update rule ${ruleId}:`, error)
    return null
  }
}

/**
 * Fetches real-time dashboard statistics and database counts.
 */
export async function getDashboardStats(interval = '5m') {
  const url = `${API_BASE_URL}/logs/stats?interval=${interval}&_t=${Date.now()}`
  try {
    const response = await fetch(url)
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to fetch dashboard stats:', error)
    return null
  }
}

/**
 * Sends a custom security message to the AI Assistant endpoint.
 */
export async function askAIChat(prompt) {
  const url = `${API_BASE_URL}/alerts/chat`
  try {
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
    return await response.json()
  } catch (error) {
    console.error('Failed to communicate with AI Assistant:', error)
    return { response: `Could not connect to the AI Assistant service. Details: ${error.message || String(error)}. Please verify your backend server is active.` }
  }
}


