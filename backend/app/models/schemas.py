from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import re

# Helper function to strip HTML/Script tags to prevent stored XSS injection
def sanitize_log_text(text: str) -> str:
    if not text:
        return text
    # Strip HTML/script tags
    clean = re.sub(r'<[^>]*>', '', text)
    # Escape single/double quotes to prevent DB injection (SQLAlchemy handles this, but extra safety is good)
    return clean

# --- Security Log Schemas ---
class SecurityLogCreate(BaseModel):
    event_type: str = Field(..., example="auth", description="Type of event: auth, firewall, web, system")
    severity: str = Field(..., example="WARNING", description="Severity level: INFO, WARNING, ERROR, CRITICAL")
    message: str = Field(..., example="Failed password for invalid user admin", description="Log message text")
    raw_payload: str = Field(..., example="Jun 15 21:30:00 server sshd[1234]: Failed password...", description="Original raw log text")
    source_ip: Optional[str] = Field(None, example="192.168.1.100")
    destination_ip: Optional[str] = Field(None, example="10.0.0.5")
    source_port: Optional[int] = Field(None, example=54321)
    destination_port: Optional[int] = Field(None, example=22)
    geo_country: Optional[str] = Field(None, example="United States")
    user_agent: Optional[str] = Field(None, example="Mozilla/5.0...")
    user_id: Optional[str] = Field(None, example="admin")
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)

    @field_validator("message", "raw_payload")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return sanitize_log_text(v)

class SecurityLogResponse(SecurityLogCreate):
    id: int

    class Config:
        orm_mode = True
        from_attributes = True


class BulkLogIngestionRequest(BaseModel):
    logs: List[SecurityLogCreate] = Field(..., description="List of structured security logs to ingest in bulk")



# --- Detection Rule Schemas ---
class DetectionRuleCreate(BaseModel):
    id: str = Field(..., example="RULE-AUTH-BRUTEFORCE")
    name: str = Field(..., example="Brute Force Login Attempt")
    description: Optional[str] = Field(None)
    pattern: str = Field(..., example="Failed password")
    severity: str = Field(..., example="HIGH")
    is_active: bool = Field(True)

class DetectionRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    pattern: Optional[str] = None
    severity: Optional[str] = None
    is_active: Optional[bool] = None

class DetectionRuleResponse(DetectionRuleCreate):
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        from_attributes = True


# --- Alert Schemas ---
class AlertResponse(BaseModel):
    id: int
    timestamp: datetime
    rule_id: str
    trigger_log_id: int
    title: str
    description: str
    severity: str
    status: str
    ai_summary: Optional[str] = None
    ai_playbook: Optional[str] = None
    case_id: Optional[int] = None
    
    # Nested response objects if needed
    trigger_log: Optional[SecurityLogResponse] = None

    class Config:
        orm_mode = True
        from_attributes = True


# --- Incident Case Schemas ---
class IncidentCaseCreate(BaseModel):
    title: str = Field(..., example="Potential Brute Force from Dutch IP")
    severity: str = Field(..., example="HIGH")
    assigned_to: Optional[str] = Field("Unassigned")

class IncidentCaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = Field(None, example="IN_PROGRESS") # OPEN, IN_PROGRESS, CLOSED
    severity: Optional[str] = None
    assigned_to: Optional[str] = None

class IncidentCaseResponse(BaseModel):
    id: int
    title: str
    status: str
    severity: str
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime
    alerts: List[AlertResponse] = []

    class Config:
        orm_mode = True
        from_attributes = True


# --- AI Analyst Playbook Schema ---
class AIPlaybookRemediation(BaseModel):
    threat_level: str
    analysis_summary: str
    remediation_steps: List[str]
    suggested_firewall_rule: Optional[str] = None
