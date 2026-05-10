import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.models.models import Base, DetectionRule

# Local development SQLite connection string by default
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./siem_database.db")

# SQLite needs connect_args={"check_same_thread": False} to run with FastAPI multithreading safely
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """
    FastAPI dependency yielding a database session and closing it after request ends.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """
    Initializes database tables and seeds default detection rules if they do not exist.
    """
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Default security rules to seed
        default_rules = [
            DetectionRule(
                id="RULE-AUTH-BRUTEFORCE",
                name="Failed Login Brute Force",
                description="Detects multiple failed login attempts from a single source IP address within a short timeframe.",
                pattern=r"(Failed password|invalid user|authentication failure|Login failed)",
                severity="HIGH",
                is_active=True
            ),
            DetectionRule(
                id="RULE-WEB-SQLI",
                name="SQL Injection Attack",
                description="Identifies SQL injection syntax patterns (e.g., SELECT, UNION, or comment tokens) in HTTP queries or payloads.",
                pattern=r"(?i)(UNION\s+SELECT|SELECT\s+.*\s+FROM|OR\s+\d+=\d+|['\"#]|\/\*|\*\/)",
                severity="CRITICAL",
                is_active=True
            ),
            DetectionRule(
                id="RULE-WEB-XSS",
                name="Cross-Site Scripting (XSS)",
                description="Detects potential script tag injections or HTML entity manipulations in web request parameters.",
                pattern=r"(?i)(<script.*?>|javascript:|onload=|<img\s+src=.*onerror=)",
                severity="HIGH",
                is_active=True
            ),
            DetectionRule(
                id="RULE-NETWORK-SCAN",
                name="Nmap / Network Port Scanning",
                description="Flags connections matching signature characteristics of network scanning software like Nmap.",
                pattern=r"(?i)(nmap|masscan|zgrab|scan|ping)",
                severity="MEDIUM",
                is_active=True
            )
        ]
        
        for rule in default_rules:
            # Check if rule exists before seeding
            existing = db.query(DetectionRule).filter(DetectionRule.id == rule.id).first()
            if not existing:
                db.add(rule)
        
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()
