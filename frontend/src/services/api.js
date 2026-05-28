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
