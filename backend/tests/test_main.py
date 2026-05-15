def test_health_check(client):
    """
    Tests the health check endpoint returns 200 and healthy database status.
    """
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    
    payload = response.json()
    assert payload["status"] == "online"
    assert "app_name" in payload
    assert payload["database"] == "healthy"
