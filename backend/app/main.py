from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import init_db, get_db
from app.core.logging import logger
from app.api.v1.endpoints import logs

app = FastAPI(
    title=settings.APP_NAME,
    description="Google-Ready AI-Powered Security Information and Event Management (SIEM) API",
    version="1.0.0",
    debug=settings.DEBUG
)

# Set up CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    """
    FastAPI startup hook to initialize the database schema and seed default detection rules.
    """
    logger.info("Starting up AI-Powered SIEM Backend...")
    try:
        init_db()
        logger.info("Database initialized and default rules seeded successfully.")
    except Exception as e:
        logger.critical(f"Database initialization failed: {e}")

# Register routers
app.include_router(logs.router, prefix="/api/v1/logs", tags=["Logs"])

@app.get("/api/v1/health")
def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint to monitor the status of the API and database connectivity.
    """
    db_status = "healthy"
    try:
        # Perform a simple query to verify database response
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
        logger.error(f"Database health check failed: {e}")

    return {
        "status": "online",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database": db_status
    }
