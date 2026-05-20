import re
from datetime import datetime, timedelta
from typing import Dict, List
from sqlalchemy.orm import Session

from app.models.models import SecurityLog, Alert, DetectionRule
from app.services.rule_loader import get_active_rules
from app.core.logging import logger

# In-memory database to track sliding-window failed logins by source IP
# Key: source_ip, Value: list of datetime timestamps of failed attempts
_brute_force_tracker: Dict[str, List[datetime]] = {}
WINDOW_SECONDS = 60
THRESHOLD_FAILED_ATTEMPTS = 5

def correlate_log(log: SecurityLog, db: Session) -> None:
    """
    Evaluates a single security log against active rules.
    Triggers database Alerts when rules are matched or thresholds are breached.
    """
    active_rules = get_active_rules()
    
    for rule in active_rules:
        # 1. Regex Pattern Matching
        if re.search(rule.pattern, log.message):
            
            # Special correlation logic for Brute Force (rate-based threshold checks)
            if rule.id == "RULE-AUTH-BRUTEFORCE":
                if not log.source_ip:
                    continue
                _process_brute_force(log, rule, db)
            
            # Simple signature rules trigger alerts immediately
            else:
                _trigger_alert(
                    db=db,
                    rule=rule,
                    log=log,
                    title=f"Signature Match: {rule.name}",
                    description=f"Log matched signature rule '{rule.name}'. Pattern found: '{rule.pattern}'"
                )

def _process_brute_force(log: SecurityLog, rule: DetectionRule, db: Session) -> None:
    """
    Tracks failed login attempts by IP in memory and triggers alert if rate threshold is crossed.
    """
    global _brute_force_tracker
    ip = log.source_ip
    now = datetime.utcnow()
    
    # Initialize list if first time
    if ip not in _brute_force_tracker:
        _brute_force_tracker[ip] = []
        
    # Append current failure
    _brute_force_tracker[ip].append(now)
    
    # Prune old timestamps outside the sliding window
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    _brute_force_tracker[ip] = [ts for ts in _brute_force_tracker[ip] if ts > cutoff]
    
    failed_count = len(_brute_force_tracker[ip])
    logger.debug(f"Failed logins from {ip} in last {WINDOW_SECONDS}s: {failed_count}/{THRESHOLD_FAILED_ATTEMPTS}")
    
    # Check threshold breach
    if failed_count >= THRESHOLD_FAILED_ATTEMPTS:
        # Clear tracker to prevent continuous alert spamming on subsequent failed attempts
        _brute_force_tracker[ip] = []
        
        _trigger_alert(
            db=db,
            rule=rule,
            log=log,
            title=f"Brute Force Alert: {rule.name}",
            description=f"Multiple failed login attempts ({failed_count} failures) detected from IP {ip} within {WINDOW_SECONDS} seconds."
        )

def _trigger_alert(db: Session, rule: DetectionRule, log: SecurityLog, title: str, description: str) -> None:
    """
    Creates and commits a new alert record to the database.
    """
    logger.warning(f"🚨 ALERT TRIGGERED: {title} - {description}")
    try:
        alert = Alert(
            rule_id=rule.id,
            trigger_log_id=log.id,
            title=title,
            description=description,
            severity=rule.severity,
            status="NEW"
        )
        db.add(alert)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to save alert: {e}", exc_info=True)
