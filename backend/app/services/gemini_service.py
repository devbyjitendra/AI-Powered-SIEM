import json
from typing import Dict, Any, List
from app.core.config import settings
from app.core.logging import logger

# Try to import Google Generative AI SDK. If missing, we gracefully fall back to mock.
GEMINI_AVAILABLE = False
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    logger.warning("google-generativeai SDK not installed. Fallback to mock security advisor is active.")

# Configure Gemini if key is provided and SDK is available
if GEMINI_AVAILABLE and settings.GEMINI_API_KEY:
    try:
        genai.configure(api_key=settings.GEMINI_API_KEY)
        logger.info("Google Gemini AI SDK successfully configured.")
    except Exception as e:
        logger.error(f"Failed to configure Gemini SDK: {e}")

def get_fallback_playbook(title: str, severity: str, log_message: str) -> Dict[str, Any]:
    """
    Generates a high-fidelity mock playbook for fallback when Gemini API is unavailable.
    """
    title_lower = title.lower()
    
    if "brute force" in title_lower or "login" in title_lower:
        return {
            "threat_level": severity.upper(),
            "analysis_summary": (
                f"The system detected a potential Authentication Brute Force attack. "
                f"Log message '{log_message}' indicates persistent authentication failures targeting critical entry points. "
                "The attacker is likely performing credentials cracking using automated dictionaries to gain unauthorized system access."
            ),
            "remediation_steps": [
                "Locate the originating source IP in your network perimeter router and temporarily drop all incoming traffic.",
                "Verify if any login attempts succeeded from the attacking IP around the time of the alert.",
                "Enforce multi-factor authentication (MFA) and implement account lockout policies after 3 failed attempts.",
                "Examine system logs (/var/log/auth.log or Event Viewer) to identify other targeted accounts."
            ],
            "suggested_firewall_rule": "iptables -A INPUT -s <SOURCE_IP> -p tcp --dport 22 -j DROP"
        }
    
    elif "sql" in title_lower or "web" in title_lower or "injection" in title_lower:
        return {
            "threat_level": severity.upper(),
            "analysis_summary": (
                f"Web Application firewall flagged a signature match for SQL Injection (SQLi) in log payload: '{log_message}'. "
                "An external actor is attempting to execute unescaped database commands via parameter manipulation, "
                "targeting information disclosure or authentication bypass."
            ),
            "remediation_steps": [
                "Immediately sanitize all HTTP parameter inputs using parameterized queries (Prepared Statements) or ORMs.",
                "Inspect web application controller files to locate where the unsanitized SQL queries are made.",
                "Verify WAF filters are set to block active attack strings, including 'OR 1=1' and 'UNION SELECT'.",
                "Review database access permissions to ensure web application connection strings run under least privilege."
            ],
            "suggested_firewall_rule": "nginx_block_ip.conf: deny <SOURCE_IP>;"
        }
        
    elif "port" in title_lower or "scan" in title_lower or "firewall" in title_lower:
        return {
            "threat_level": severity.upper(),
            "analysis_summary": (
                f"A firewall scan event '{log_message}' triggered a reconnaissance alert. "
                "An external IP is sequentially querying port ranges to discover active services, open ports, "
                "and system operating details (banner grabbing)."
            ),
            "remediation_steps": [
                "Configure edge firewall rules to block the attacking IP from traversing internal subnets.",
                "Validate that non-essential ports (e.g. Telnet, RDP, FTP) are completely closed to public routing.",
                "Enable rate-limiting and connection throttling thresholds on the public firewall profile.",
                "Ensure server operating systems are patched against known remote execution vulnerabilities."
            ],
            "suggested_firewall_rule": "ufw deny from <SOURCE_IP> to any"
        }
        
    else:
        return {
            "threat_level": severity.upper(),
            "analysis_summary": (
                f"Generic security rule violation: '{title}'. Trigger log details: '{log_message}'. "
                "Immediate analyst review is recommended to inspect traffic anomalous patterns."
            ),
            "remediation_steps": [
                "Review log payload details to determine if it is a false positive.",
                "Inspect target host resource usages for suspicious system processes.",
                "Isolate infected network nodes if compromise characteristics are observed."
            ],
            "suggested_firewall_rule": "iptables -I INPUT -s <SOURCE_IP> -j DROP"
        }

def clean_json_text(text: str) -> str:
    """
    Cleans up any markdown wrapper blocks (like ```json ... ```) 
    that might be returned by the LLM before JSON parsing.
    """
    text = text.strip()
    if text.startswith("```"):
        # Split lines and remove formatting wrappers
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text

async def generate_security_playbook(
    title: str,
    description: str,
    severity: str,
    log_message: str,
    rule_pattern: str,
    source_ip: str = "Unknown"
) -> Dict[str, Any]:
    """
    Leverages Gemini to perform security logs analysis and construct a structured mitigation playbook.
    Falls back to a high-fidelity local rules generator if the API is offline or key is missing.
    """
    # Use fallback if key is missing or SDK failed to load
    if not GEMINI_AVAILABLE or not settings.GEMINI_API_KEY:
        logger.info("Using mock security advisor fallback for playbook generation.")
        playbook = get_fallback_playbook(title, severity, log_message)
        # Inject the correct source IP if known
        if playbook.get("suggested_firewall_rule") and source_ip != "Unknown":
            playbook["suggested_firewall_rule"] = playbook["suggested_firewall_rule"].replace("<SOURCE_IP>", source_ip)
        return playbook

    logger.info(f"Querying Google Gemini API for security analysis on alert: '{title}'")
    try:
        # Prompt engineered to return a strict JSON payload matching the expected schema
        prompt = f"""
You are a senior security operations center (SOC) analyst and incident responder.
Analyze the following security SIEM alert:

ALERT TITLE: {title}
ALERT DESCRIPTION: {description}
RULE PATTERN: {rule_pattern}
SEVERITY LEVEL: {severity}
TRIGGERING LOG MESSAGE: {log_message}
SOURCE THREAT IP: {source_ip}

Generate a structured security investigation analysis and mitigation playbook.
Your response MUST be a valid JSON object matching this schema:
{{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "analysis_summary": "detailed explanation of the threat, attacker goals, and what the log signature indicates",
  "remediation_steps": [
    "step 1: identify or block...",
    "step 2: verify...",
    "step 3: recover or patch..."
  ],
  "suggested_firewall_rule": "exact command or WAF configuration snippet to block this specific source IP"
}}

Ensure that the firewall rule blocks the actual source IP '{source_ip}' if it is a valid IP.
Output ONLY the JSON object, with no markdown code blocks, backticks, or extra commentary.
"""
        model = genai.GenerativeModel("gemini-1.5-flash")
        
        # Call the model
        response = await asyncio.to_thread(
            model.generate_content,
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        
        # Clean and parse output JSON
        cleaned_text = clean_json_text(response.text)
        data = json.loads(cleaned_text)
        logger.info("Successfully received and parsed Gemini AI response.")
        return data

    except Exception as e:
        logger.error(f"Gemini API execution failed: {e}. Falling back to mock playbook.", exc_info=True)
        playbook = get_fallback_playbook(title, severity, log_message)
        if playbook.get("suggested_firewall_rule") and source_ip != "Unknown":
            playbook["suggested_firewall_rule"] = playbook["suggested_firewall_rule"].replace("<SOURCE_IP>", source_ip)
        return playbook

