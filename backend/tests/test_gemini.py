import pytest
from app.services.gemini_service import generate_security_playbook, get_fallback_playbook

@pytest.mark.asyncio
async def test_fallback_brute_force():
    """
    Validates that the fallback playbook correctly identifies Brute Force attacks.
    """
    playbook = await generate_security_playbook(
        title="Failed Login Brute Force",
        description="Multiple failed logins from single IP",
        severity="HIGH",
        log_message="sshd[28451]: Failed password for admin",
        rule_pattern="Failed password",
        source_ip="198.51.100.45"
    )
    
    assert playbook["threat_level"] == "HIGH"
    assert "brute force" in playbook["analysis_summary"].lower()
    assert len(playbook["remediation_steps"]) > 0
    assert "198.51.100.45" in playbook["suggested_firewall_rule"]

@pytest.mark.asyncio
async def test_fallback_sql_injection():
    """
    Validates that the fallback playbook structures correct parameters for SQL injection attempts.
    """
    playbook = await generate_security_playbook(
        title="SQL Injection Attack Detected",
        description="SQL tokens in web request",
        severity="CRITICAL",
        log_message="GET /login.php?user=admin' OR '1'='1",
        rule_pattern="UNION SELECT",
        source_ip="203.0.113.82"
    )
    
    assert playbook["threat_level"] == "CRITICAL"
    assert "sql injection" in playbook["analysis_summary"].lower()
    assert "203.0.113.82" in playbook["suggested_firewall_rule"]

def test_fallback_generic():
    """
    Tests direct output of the fallback helper functions for other rule matches.
    """
    playbook = get_fallback_playbook(
        title="Suspicious Network Scanner Activity",
        severity="MEDIUM",
        log_message="Nmap ping scan detected"
    )
    
    assert playbook["threat_level"] == "MEDIUM"
    assert "scanner" in playbook["analysis_summary"].lower()
