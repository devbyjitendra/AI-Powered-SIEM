const API_BASE_URL = 'http://127.0.0.1:8000/api/v1'

/**
 * Fetches alerts from the backend, supporting status and severity filters.
 */
export async function getAlerts(status = '', severity = '') {
  const params = new URLSearchParams()
  if (status) params.append('status', status)
  if (severity) params.append('severity', severity)
  
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
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error('Failed to create case:', error)
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
 * Associates a security alert to a case.
 */
export async function linkAlertToCase(caseId, alertId) {
  const url = `${API_BASE_URL}/cases/${caseId}/alerts?alert_id=${alertId}`
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    })
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`)
    }
    return await response.json()
  } catch (error) {
    console.error(`Failed to link alert ${alertId} to case ${caseId}:`, error)
    return null
  }
}

/**
 * Fetches all detection rules.
 */
export async function getRules() {
  const url = `${API_BASE_URL}/rules`
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


