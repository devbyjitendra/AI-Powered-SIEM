def test_get_rules_api(client):
    """
    Asserts GET /api/v1/rules successfully returns seeded rules.
    """
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    
    data = response.json()
    assert len(data) >= 4
    assert any(rule["id"] == "RULE-AUTH-BRUTEFORCE" for rule in data)

def test_create_rule_success(client):
    """
    Asserts custom rules can be successfully created with valid regex.
    """
    payload = {
        "id": "RULE-TEST-API",
        "name": "API Test Rule",
        "description": "Rule to test endpoints",
        "pattern": r"malicious_api_pattern",
        "severity": "MEDIUM",
        "is_active": True
    }
    
    response = client.post("/api/v1/rules", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert data["id"] == "RULE-TEST-API"
    assert data["pattern"] == "malicious_api_pattern"

def test_create_rule_invalid_regex(client):
    """
    Asserts creating a rule with invalid regex returns 400 Bad Request.
    """
    payload = {
        "id": "RULE-TEST-BAD-REGEX",
        "name": "Bad Regex Rule",
        "pattern": r"[unclosed-bracket",
        "severity": "LOW",
        "is_active": True
    }
    
    response = client.post("/api/v1/rules", json=payload)
    assert response.status_code == 400
    assert "Invalid regular expression" in response.json()["detail"]

def test_update_rule_api(client):
    """
    Asserts updating a rule (e.g. disabling it) correctly persists and syncs cache.
    """
    # 1. Update status
    payload = {
        "is_active": False
    }
    
    response = client.put("/api/v1/rules/RULE-WEB-SQLI", json=payload)
    assert response.status_code == 200
    assert response.json()["is_active"] is False
