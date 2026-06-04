import json
import httpx
from typing import Dict, Any, List
from app.core.config import settings
from app.core.logging import logger
from dotenv import load_dotenv

load_dotenv()

# Try to import Langchain Mistral AI SDK. If missing, we gracefully fall back to mock.
MISTRAL_AVAILABLE = False
try:
    from langchain_mistralai import ChatMistralAI
    from langchain_core.messages import SystemMessage, HumanMessage
    from pydantic import BaseModel, Field
    MISTRAL_AVAILABLE = True
except ImportError:
    logger.warning("langchain-mistralai or langchain-core is not installed. Fallback to mock security advisor is active.")

# Configure AI engine eligibility
MISTRAL_ACTIVE = MISTRAL_AVAILABLE and settings.MISTRAL_API_KEY and "your_mistral_api_key_here" not in settings.MISTRAL_API_KEY
OPENROUTER_ACTIVE = bool(settings.OPENROUTER_API_KEY and "your_openrouter_api_key_here" not in settings.OPENROUTER_API_KEY)

async def _call_openrouter(messages: List[Dict[str, str]], response_format: Any = None) -> str:
    headers = {
        "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "AI-Powered SIEM"
    }
    payload = {
        "model": settings.OPENROUTER_MODEL_NAME,
        "messages": messages
    }
    if response_format:
        payload["response_format"] = response_format
        
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post("https://openrouter.ai/api/v1/chat/completions", json=payload, headers=headers)
        if response.status_code != 200:
            raise Exception(f"OpenRouter API error {response.status_code}: {response.text}")
        data = response.json()
        return data["choices"][0]["message"]["content"]

async def _stream_openrouter(messages: List[Dict[str, str]]):
    headers = {
        "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "AI-Powered SIEM"
    }
    payload = {
        "model": settings.OPENROUTER_MODEL_NAME,
        "messages": messages,
        "stream": True
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        async with client.stream("POST", "https://openrouter.ai/api/v1/chat/completions", json=payload, headers=headers) as response:
            if response.status_code != 200:
                body = await response.aread()
                raise Exception(f"OpenRouter streaming error {response.status_code}: {body.decode()}")
            
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data_str = line[6:].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk_data = json.loads(data_str)
                        content = chunk_data["choices"][0]["delta"].get("content", "")
                        if content:
                            yield content
                    except Exception:
                        pass

# Define schema for structured playbooks if Langchain is available
if MISTRAL_AVAILABLE:
    class PlaybookSchema(BaseModel):
        threat_level: str = Field(description="LOW|MEDIUM|HIGH|CRITICAL")
        analysis_summary: str = Field(description="detailed explanation of the threat, attacker goals, and what the log signature indicates")
        remediation_steps: List[str] = Field(description="step-by-step remediation actions")
        suggested_firewall_rule: str = Field(description="exact command or WAF configuration snippet to block this specific source IP")

def get_fallback_playbook(title: str, severity: str, log_message: str) -> Dict[str, Any]:
    """
    Generates a high-fidelity mock playbook for fallback when Mistral API is unavailable.
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

def get_local_response(p: str) -> str:
    prompt_lower = p.lower()
    
    # Check if user asks about dashboard stats, recent alerts, logs, or metrics
    if any(k in prompt_lower for k in ["dashboard", "stat", "metric", "alert", "recent", "log"]):
        from app.core.database import SessionLocal
        from app.models.models import Alert, IncidentCase, SecurityLog
        db = SessionLocal()
        try:
            total_logs = db.query(SecurityLog).count()
            total_alerts = db.query(Alert).count()
            total_cases = db.query(IncidentCase).count()
            critical_alerts = db.query(Alert).filter(Alert.severity.in_(["HIGH", "CRITICAL"])).count()
            latest_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(5).all()
            
            alerts_summary = []
            for a in latest_alerts:
                alerts_summary.append(f"- **{a.title}** | Severity: `{a.severity}` | Source: `{a.source_ip}` | Status: `{a.status}`")
            alerts_text = "\n".join(alerts_summary) if alerts_summary else "No recent alerts."
            
            return (
                f"### 📊 Live SIEM Dashboard Status\n\n"
                f"* **Total Security Events Ingested**: `{total_logs}`\n"
                f"* **Correlated Security Alerts**: `{total_alerts}` (Critical/High: `{critical_alerts}`)\n"
                f"* **Active Incident Cases**: `{total_cases}`\n\n"
                f"### 🔔 Recent Security Alerts\n{alerts_text}\n\n"
                f"How can I assist you in mitigating any of these threats today?"
            )
        except Exception as e:
            logger.error(f"Error fetching stats in local responder: {e}")
        finally:
            db.close()

    if "sql" in prompt_lower or "sqli" in prompt_lower:
        return (
            "To mitigate SQL Injection (SQLi) attacks on your application:\n\n"
            "1. **Use Parameterized Queries**: Always use prepared statements or ORMs (like SQLAlchemy or Sequelize) instead of building raw SQL strings.\n"
            "2. **Input Sanitization**: Validate and sanitize all user input before processing.\n"
            "3. **Least Privilege**: Configure your database user accounts with only the permissions required to run the application (e.g. disable DROP, ALTER tables for normal users).\n"
            "4. **Web Application Firewall (WAF)**: Deploy a WAF (like Cloudflare or ModSecurity) to automatically block known injection payloads."
        )
    elif "brute force" in prompt_lower or "ssh" in prompt_lower or "auth" in prompt_lower:
        return (
            "To protect against Authentication Brute Force attacks:\n\n"
            "1. **Enforce Strong Lockout Policies**: Lock user accounts temporarily after 3 to 5 failed login attempts.\n"
            "2. **Use Multi-Factor Authentication (MFA)**: Require MFA for all users, especially administrative accounts.\n"
            "3. **Fail2Ban**: Install fail2ban or a similar daemon to automatically block IP addresses after repeated failed logins.\n"
            "4. **SSH Key Authentication**: Completely disable password logins on SSH and require cryptographic keys instead."
        )
    elif "port scan" in prompt_lower or "nmap" in prompt_lower:
        return (
            "To defend against Network Port Scanning and reconnaissance:\n\n"
            "1. **Close Unnecessary Ports**: Completely close all ports that do not serve public services (e.g. keep database ports private).\n"
            "2. **Enable State Inspection Firewall**: Use firewalls (like UFW or iptables) to drop invalid connection packets.\n"
            "3. **Implement Rate-Limiting**: Drop connections if an IP makes too many new socket requests per second.\n"
            "4. **Disable Banner Grabbing**: Configure services to hide their specific software version numbers in headers/banners."
        )
    else:
        return (
            "Hello! I am your AI Security Analyst Assistant. I can help you analyze security events, draft mitigation playbooks, "
            "or write firewall rules. Feel free to ask me about common security threats like Brute Force, SQL Injections, or Port Scans!"
        )

async def generate_security_playbook(
    title: str,
    description: str,
    severity: str,
    log_message: str,
    rule_pattern: str,
    source_ip: str = "Unknown"
) -> Dict[str, Any]:
    """
    Leverages Langchain & Mistral AI to perform security log analysis and construct a structured playbook.
    Falls back to a high-fidelity local generator if the API is offline or key is missing.
    """
    if not OPENROUTER_ACTIVE and not MISTRAL_ACTIVE:
        logger.info("Using mock security advisor fallback for playbook generation.")
        playbook = get_fallback_playbook(title, severity, log_message)
        if playbook.get("suggested_firewall_rule") and source_ip != "Unknown":
            playbook["suggested_firewall_rule"] = playbook["suggested_firewall_rule"].replace("<SOURCE_IP>", source_ip)
        return playbook

    if OPENROUTER_ACTIVE:
        logger.info(f"Querying OpenRouter API ({settings.OPENROUTER_MODEL_NAME}) for playbook generation...")
        try:
            prompt = f"""
Analyze the following security SIEM alert:

ALERT TITLE: {title}
ALERT DESCRIPTION: {description}
RULE PATTERN: {rule_pattern}
SEVERITY LEVEL: {severity}
TRIGGERING LOG MESSAGE: {log_message}
SOURCE THREAT IP: {source_ip}

You MUST return a JSON object representing the security playbook. The JSON object MUST strictly follow this JSON schema:
{{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "analysis_summary": "detailed explanation of the threat, attacker goals, and what the log signature indicates",
  "remediation_steps": ["step-by-step remediation actions"],
  "suggested_firewall_rule": "exact command or WAF configuration snippet to block this specific source IP"
}}
"""
            messages = [
                {"role": "system", "content": "You are a senior SOC analyst assisting a SIEM platform. Output structured JSON matching the requested schema. Return ONLY valid JSON, do not wrap in markdown codeblocks."},
                {"role": "user", "content": prompt}
            ]
            response_text = await _call_openrouter(messages, response_format={"type": "json_object"})
            data = json.loads(response_text)
            logger.info("Successfully received and parsed structured output from OpenRouter.")
            return data
        except Exception as e:
            logger.error(f"OpenRouter playbook generation failed: {e}. Falling back to mock playbook.", exc_info=True)
            return {
                "threat_level": "ERROR",
                "analysis_summary": f"⚠️ **OpenRouter API Playbook Error**: The API call failed with the following error:\n{str(e)}\n\nPlease verify your OPENROUTER_API_KEY settings.",
                "remediation_steps": [
                    "Verify that the OPENROUTER_API_KEY in your .env file is correct and active.",
                    "Check OpenRouter billing/credits."
                ],
                "suggested_firewall_rule": "N/A"
            }

    logger.info(f"Querying Mistral AI API (via Langchain) for security analysis on alert: '{title}'")
    try:
        model = ChatMistralAI(
            model=settings.MISTRAL_MODEL_NAME,
            api_key=settings.MISTRAL_API_KEY,
            temperature=0.1,
            max_retries=0,
            timeout=10
        )
        
        structured_model = model.with_structured_output(PlaybookSchema)
        
        prompt = f"""
Analyze the following security SIEM alert:

ALERT TITLE: {title}
ALERT DESCRIPTION: {description}
RULE PATTERN: {rule_pattern}
SEVERITY LEVEL: {severity}
TRIGGERING LOG MESSAGE: {log_message}
SOURCE THREAT IP: {source_ip}

Generate a structured security investigation analysis and mitigation playbook.
"""
        
        response = await structured_model.ainvoke([
            SystemMessage(content="You are a senior SOC analyst assisting a SIEM platform. Output structured data matching the playbook schema."),
            HumanMessage(content=prompt)
        ])
        
        if hasattr(response, "model_dump"):
            data = response.model_dump()
        else:
            data = dict(response)
            
        logger.info("Successfully received and parsed structured output from Mistral.")
        return data

    except Exception as e:
        logger.error(f"Mistral API playbook generation failed: {e}. Falling back to mock playbook.", exc_info=True)
        if MISTRAL_ACTIVE:
            return {
                "threat_level": "ERROR",
                "analysis_summary": f"⚠️ **Mistral API Playbook Error**: The API call failed with the following error:\n{str(e)}\n\nPlease verify your MISTRAL_API_KEY settings and billing/quota.",
                "remediation_steps": [
                    "Verify that the MISTRAL_API_KEY in your .env file is correct and active.",
                    "Check Mistral console status and network outbound routing."
                ],
                "suggested_firewall_rule": "N/A"
            }
        return playbook

def _get_live_db_stats():
    from app.core.database import _IN_MEMORY_DB, _DB_LOCK
    total_logs = 0
    total_alerts = 0
    total_cases = 0
    critical_alerts = 0
    alerts_text = "No recent alerts."
    
    try:
        with _DB_LOCK:
            logs_col = _IN_MEMORY_DB.get("security_logs", {})
            alerts_col = _IN_MEMORY_DB.get("alerts", {})
            cases_col = _IN_MEMORY_DB.get("incident_cases", {})
            
            total_logs = len(logs_col)
            total_alerts = len(alerts_col)
            total_cases = len(cases_col)
            
            critical_alerts = sum(
                1 for a in alerts_col.values()
                if str(a.get("severity", "")).upper() in ["HIGH", "CRITICAL"]
            )
            
            alerts_list = list(alerts_col.values())
            alerts_list.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
            latest_alerts = alerts_list[:5]
            
            if latest_alerts:
                alerts_summary = []
                for a in latest_alerts:
                    alerts_summary.append(
                        f"- Alert ID {a.get('id')}: '{a.get('title')}' | Severity: {a.get('severity')} | Source IP: {a.get('source_ip') or 'Unknown'} | Status: {a.get('status')}"
                    )
                alerts_text = "\n".join(alerts_summary)
    except Exception as db_err:
        logger.error(f"Error querying database stats for AI context: {db_err}", exc_info=True)
        
    return total_logs, total_alerts, total_cases, critical_alerts, alerts_text

async def ask_gemini_assistant(prompt: str) -> str:
    """
    Sends a general security question to Mistral AI / OpenRouter and returns the textual response.
    Keeps function name 'ask_gemini_assistant' to preserve compatibility with existing router bindings.
    """
    if not OPENROUTER_ACTIVE and not MISTRAL_ACTIVE:
        logger.info("Using mock assistant fallback for AI chat.")
        return get_local_response(prompt)

    logger.info(f"Querying AI engine for general security query: '{prompt}'")
    try:
        system_prompt = "You are a senior SOC Analyst and AI Security Assistant integrated directly within the SIEM platform. Answer in a professional, concise, and structured way."
        
        has_stats_keywords = any(k in prompt.lower() for k in ["dashboard", "stat", "metric", "alert", "recent", "log", "incident", "status", "count", "system"])
        if has_stats_keywords:
            total_logs, total_alerts, total_cases, critical_alerts, alerts_text = _get_live_db_stats()

            system_prompt = f"""You are a senior SOC Analyst and AI Security Assistant integrated directly within the SIEM platform.
You have direct read access to the live SIEM database and dashboard status. Here are the live metrics currently visible on the dashboard:
- Total Security Logs Ingested: {total_logs}
- Correlated Security Alerts: {total_alerts} (including {critical_alerts} HIGH or CRITICAL severity alerts)
- Active Incident Investigation Cases: {total_cases}

Most Recent Security Alerts correlated by the engine:
{alerts_text}

When the user asks about the dashboard, metrics, events, or alerts, answer them directly using these live statistics. Do NOT state that you cannot access external systems, view the dashboard, or retrieve SIEM data, because you are fully integrated and these are the live numbers. Answer in a professional, concise, and structured way."""

        if OPENROUTER_ACTIVE:
            logger.info("Using OpenRouter endpoint for chat.")
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            return await _call_openrouter(messages)

        model = ChatMistralAI(
            model=settings.MISTRAL_MODEL_NAME,
            api_key=settings.MISTRAL_API_KEY,
            max_retries=0,
            timeout=10
        )
        
        response = await model.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=prompt)
        ])
        
        return response.content
    except Exception as e:
        logger.error(f"AI Assistant execution failed: {e}. Falling back to local responder.", exc_info=True)
        if OPENROUTER_ACTIVE or MISTRAL_ACTIVE:
            return f"⚠️ **AI API Chat Error**: The API call failed with the following error:\n```\n{str(e)}\n```\n\nPlease check your key configurations and network status."
        return get_local_response(prompt)

async def stream_gemini_assistant(prompt: str):
    """
    Streams the general security response from Mistral AI / OpenRouter chunk-by-chunk using model.astream or custom SSE.
    Keeps naming convention for compatibility.
    """
    if not OPENROUTER_ACTIVE and not MISTRAL_ACTIVE:
        logger.info("Using mock assistant fallback for AI chat streaming.")
        response_text = get_local_response(prompt)
        # Yield in small chunks to simulate typing speed
        import asyncio
        for i in range(0, len(response_text), 15):
            yield response_text[i:i+15]
            await asyncio.sleep(0.02)
        return

    logger.info(f"Streaming AI API for security query: '{prompt}'")
    try:
        system_prompt = "You are a senior SOC Analyst and AI Security Assistant integrated directly within the SIEM platform. Answer in a professional, concise, and structured way."
        
        has_stats_keywords = any(k in prompt.lower() for k in ["dashboard", "stat", "metric", "alert", "recent", "log", "incident", "status", "count", "system"])
        if has_stats_keywords:
            total_logs, total_alerts, total_cases, critical_alerts, alerts_text = _get_live_db_stats()

            system_prompt = f"""You are a senior SOC Analyst and AI Security Assistant integrated directly within the SIEM platform.
You have direct read access to the live SIEM database and dashboard status. Here are the live metrics currently visible on the dashboard:
- Total Security Logs Ingested: {total_logs}
- Correlated Security Alerts: {total_alerts} (including {critical_alerts} HIGH or CRITICAL severity alerts)
- Active Incident Investigation Cases: {total_cases}

Most Recent Security Alerts correlated by the engine:
{alerts_text}

When the user asks about the dashboard, metrics, events, or alerts, answer them directly using these live statistics. Do NOT state that you cannot access external systems, view the dashboard, or retrieve SIEM data, because you are fully integrated and these are the live numbers. Answer in a professional, concise, and structured way."""

        if OPENROUTER_ACTIVE:
            logger.info("Using OpenRouter endpoint for chat streaming.")
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            async for chunk in _stream_openrouter(messages):
                yield chunk
            return

        model = ChatMistralAI(
            model=settings.MISTRAL_MODEL_NAME,
            api_key=settings.MISTRAL_API_KEY,
            max_retries=0,
            timeout=10
        )
        
        async for chunk in model.astream([
            SystemMessage(content=system_prompt),
            HumanMessage(content=prompt)
        ]):
            if chunk.content:
                yield chunk.content
            
    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        logger.error(f"AI Assistant streaming failed: {e}. Traceback:\n{tb_str}", exc_info=True)
        try:
            # Write to a file in the workspace backend directory
            with open("ai_error_log.txt", "w", encoding="utf-8") as f:
                f.write(tb_str)
        except Exception:
            pass
        err_msg = f"⚠️ **AI API Chat Error**: The API call failed with the following error:\n```\n{str(e) or type(e).__name__}\n```\n\nPlease check your key configurations."
        yield err_msg


