import os
import sys

# Add backend app directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.database import SessionLocal, init_db
from app.api.v1.endpoints.logs import get_dashboard_stats

print("Initializing DB...")
init_db()

print("Querying stats...")
db = SessionLocal()
try:
    stats = get_dashboard_stats(db)
    print("Success! Stats keys:", stats.keys())
except Exception as e:
    import traceback
    traceback.print_exc()
finally:
    db.close()
