import sys
import traceback
from app.core.database import SessionLocal
from app.api.v1.endpoints.alerts import get_alerts

db = SessionLocal()
try:
    print("Executing get_alerts(status='NEW')...")
    res = get_alerts(status='NEW', db=db)
    print(f"Success! Retrieved {len(res)} alerts.")
    for idx, alert in enumerate(res):
        print(f"Alert {idx}: id={alert.id}, timestamp={alert.timestamp}, severity={alert.severity}")
except Exception as e:
    print("FAILED! Traceback:")
    traceback.print_exc()
finally:
    db.close()
