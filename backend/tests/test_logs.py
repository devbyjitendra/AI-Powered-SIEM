def test_bulk_log_ingestion(client):
    """
    Tests that posting a batch of security logs to the ingest endpoint
    successfully saves them and returns the populated DB entities.
    """
    payload = {
        "logs": [
            {
                "event_type": "auth",
                "severity": "WARNING",
                "message": "SSH Login Failed",
                "raw_payload": "sshd: login failed for admin from 192.168.1.100",
                "source_ip": "192.168.1.100",
                "destination_port": 22
            },
            {
                "event_type": "web",
                "severity": "CRITICAL",
                "message": "SQL Injection attempt detected",
                "raw_payload": "GET /index.php?id=1' UNION SELECT NULL--",
                "source_ip": "203.0.113.45",
                "destination_port": 443
            }
        ]
    }
    
    response = client.post("/api/v1/logs/ingest", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert len(data) == 2
    assert data[0]["id"] is not None
    assert data[0]["event_type"] == "auth"
    assert data[0]["source_ip"] == "192.168.1.100"
    
    assert data[1]["id"] is not None
    assert data[1]["event_type"] == "web"
    assert data[1]["source_ip"] == "203.0.113.45"

def test_ingestion_sanitization(client):
    """
    Ensures that script tags injected in the ingestion payload are stripped
    by the validator before the logs are saved to the database.
    """
    payload = {
        "logs": [
            {
                "event_type": "web",
                "severity": "WARNING",
                "message": "<script>alert('XSS')</script>Malicious Payload",
                "raw_payload": "<img src=x onerror=alert(1)>"
            }
        ]
    }
    
    response = client.post("/api/v1/logs/ingest", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert data[0]["message"] == "alert('XSS')Malicious Payload"
    assert data[0]["raw_payload"] == ""
