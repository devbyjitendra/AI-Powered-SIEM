import os
from typing import List

class Settings:
    """
    Application settings loader that parses environment variables.
    Supports manual loading of the root-level .env file for development convenience.
    """
    def __init__(self):
        # Look for .env in the workspace root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        env_path = os.path.join(base_dir, ".env")
        
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip().strip('"').strip("'")
                        if key and key not in os.environ:
                            os.environ[key] = val

        self.APP_NAME: str = os.getenv("APP_NAME", "AI-Powered SIEM")
        self.APP_ENV: str = os.getenv("APP_ENV", "development")
        self.DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
        self.DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./siem_database.db")
        self.GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
        
        origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
        self.cors_origins: List[str] = [o.strip() for o in origins.split(",") if o.strip()]

settings = Settings()
