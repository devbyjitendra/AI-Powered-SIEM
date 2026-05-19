from typing import List
from sqlalchemy.orm import Session
from app.models.models import DetectionRule
from app.core.logging import logger

# Global in-memory cache registry for active detection rules
_active_rules_cache: List[DetectionRule] = []

def refresh_rules(db: Session) -> List[DetectionRule]:
    """
    Queries the database for all active rules and updates the in-memory cache.
    """
    global _active_rules_cache
    logger.info("Refreshing active detection rules cache...")
    try:
        rules = db.query(DetectionRule).filter(DetectionRule.is_active == True).all()
        # Keep rules in memory
        _active_rules_cache = rules
        logger.info(f"Loaded {len(_active_rules_cache)} active rules into memory.")
        return _active_rules_cache
    except Exception as e:
        logger.error(f"Failed to load detection rules: {e}", exc_info=True)
        return _active_rules_cache


def get_active_rules() -> List[DetectionRule]:
    """
    Returns the currently cached active detection rules.
    """
    global _active_rules_cache
    return _active_rules_cache
