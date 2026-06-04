import sys
import os

# Add parent directory to path to allow importing app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.config import settings
from app.services.gemini_service import MISTRAL_AVAILABLE, MISTRAL_ACTIVE, OPENROUTER_ACTIVE

output = []
output.append(f"MISTRAL_AVAILABLE: {MISTRAL_AVAILABLE}")
output.append(f"MISTRAL_ACTIVE: {MISTRAL_ACTIVE}")
output.append(f"OPENROUTER_ACTIVE: {OPENROUTER_ACTIVE}")
output.append(f"MISTRAL_MODEL_NAME: {settings.MISTRAL_MODEL_NAME}")

# Print key lengths/existence safely without revealing credentials
mkey = settings.MISTRAL_API_KEY
output.append(f"MISTRAL_API_KEY exists: {bool(mkey)}")
if mkey:
    output.append(f"MISTRAL_API_KEY length: {len(mkey)}")
    output.append(f"MISTRAL_API_KEY starts with: {mkey[:4]}...")
    output.append(f"MISTRAL_API_KEY ends with: ...{mkey[-4:]}")
    output.append(f"Is dummy key check: {'your_mistral_api_key_here' in mkey}")

with open("mistral_diagnostics.txt", "w") as f:
    f.write("\n".join(output))
