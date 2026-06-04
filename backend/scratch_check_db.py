from app.core.database import SessionLocal
from app.models.models import IncidentCase, Alert
import sys

db = SessionLocal()
try:
    print("Testing Case Creation...")
    # Fetch first alert
    alert = db.query(Alert).first()
    if not alert:
        print("No alert found to link!")
    else:
        print(f"Found Alert ID: {alert.id}")
        # Create Case
        case = IncidentCase(title="Test Case Escalation", severity="CRITICAL", assigned_to="Unassigned")
        db.add(case)
        db.commit()
        db.refresh(case)
        print(f"Created Case ID: {case.id}")
        
        # Link Alert
        alert.case_id = case.id
        db.commit()
        print("Successfully linked case!")
except Exception as e:
    import traceback
    traceback.print_exc()
finally:
    db.close()
