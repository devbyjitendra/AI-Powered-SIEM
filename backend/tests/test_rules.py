from app.models.models import DetectionRule
from app.services.rule_loader import refresh_rules, get_active_rules

def test_seeded_rules_loading(db_session):
    """
    Verifies that the default seeded rules (brute force, sql injection, etc.)
    are successfully queried and loaded into the cache registry.
    """
    # Trigger refresh
    rules = refresh_rules(db_session)
    
    # We should have at least the 4 default rules seeded in Day 3
    assert len(rules) >= 4
    
    rule_ids = [rule.id for rule in rules]
    assert "RULE-AUTH-BRUTEFORCE" in rule_ids
    assert "RULE-WEB-SQLI" in rule_ids
    
    # Verify get_active_rules matches the returned cache
    assert get_active_rules() == rules

def test_add_rule_dynamics(db_session):
    """
    Verifies that adding a new rule to the database and refreshing 
    updates the cached registry instantly.
    """
    new_rule = DetectionRule(
        id="RULE-TEST-MALICIOUS-CMD",
        name="Suspicious command execution",
        description="Flags system administrative command calls",
        pattern=r"(sudo|chmod|rm -rf)",
        severity="HIGH",
        is_active=True
    )
    db_session.add(new_rule)
    db_session.commit()
    
    refresh_rules(db_session)
    rules = get_active_rules()
    
    assert any(rule.id == "RULE-TEST-MALICIOUS-CMD" for rule in rules)

def test_disabled_rule_exclusion(db_session):
    """
    Verifies that disabled rules (is_active=False) are excluded from the cache.
    """
    # Disable the test rule we added
    rule = db_session.query(DetectionRule).filter(DetectionRule.id == "RULE-AUTH-BRUTEFORCE").first()
    if rule:
        rule.is_active = False
        db_session.commit()
        
    refresh_rules(db_session)
    rules = get_active_rules()
    
    assert not any(rule.id == "RULE-AUTH-BRUTEFORCE" for rule in rules)
    
    # Re-enable for other tests
    rule.is_active = True
    db_session.commit()
