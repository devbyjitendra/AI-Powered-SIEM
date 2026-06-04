import sys
import traceback
from app.core.database import SessionLocal
from app.api.v1.endpoints.logs import get_dashboard_stats

db = SessionLocal()
try:
    print("Executing get_dashboard_stats()...")
    res = get_dashboard_stats(db)
    print("Success! Return data keys:")
    print(res.keys())
except Exception as e:
    print("FAILED! Traceback:")
    traceback.print_exc()
finally:
    db.close()
