import re
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.core.logging import logger
from app.models.models import DetectionRule
from app.models.schemas import DetectionRuleResponse, DetectionRuleCreate, DetectionRuleUpdate
from app.services.rule_loader import refresh_rules

router = APIRouter()

@router.get("", response_model=List[DetectionRuleResponse])
def get_rules(db: Session = Depends(get_db)):
    """
    Retrieve all security detection rules from the database.
    """
    return db.query(DetectionRule).all()

@router.post("", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
def create_rule(payload: DetectionRuleCreate, db: Session = Depends(get_db)):
    """
    Creates a new custom threat detection rule.
    Validates regex pattern syntax before persisting.
    """
    # Verify regex compilation validity
    try:
        re.compile(payload.pattern)
    except re.error as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid regular expression pattern: {str(e)}"
        )
        
    # Check duplicate ID
    existing = db.query(DetectionRule).filter(DetectionRule.id == payload.id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Detection rule with ID '{payload.id}' already exists."
        )

    db_rule = DetectionRule(
        id=payload.id,
        name=payload.name,
        description=payload.description,
        pattern=payload.pattern,
        severity=payload.severity,
        is_active=payload.is_active
    )
    
    try:
        db.add(db_rule)
        db.commit()
        db.refresh(db_rule)
        
        # Sync in-memory rule cache
        refresh_rules(db)
        logger.info(f"Custom detection rule '{db_rule.id}' registered and loaded to cache.")
        return db_rule
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create rule: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while saving the rule."
        )

@router.put("/{rule_id}", response_model=DetectionRuleResponse)
def update_rule(rule_id: str, payload: DetectionRuleUpdate, db: Session = Depends(get_db)):
    """
    Updates an existing threat detection rule and syncs the rules cache.
    """
    db_rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with ID '{rule_id}' not found."
        )
        
    update_data = payload.dict(exclude_unset=True)
    
    # If pattern is updated, validate compilation
    if "pattern" in update_data:
        try:
            re.compile(update_data["pattern"])
        except re.error as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid regular expression pattern: {str(e)}"
            )

    try:
        for key, val in update_data.items():
            setattr(db_rule, key, val)
            
        db.commit()
        db.refresh(db_rule)
        
        # Sync in-memory rule cache
        refresh_rules(db)
        logger.info(f"Detection rule '{rule_id}' updated and rules cache refreshed.")
        return db_rule
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update rule: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the rule."
        )
