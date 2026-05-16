import re
from typing import Optional

# Static Geo-IP database mapping specific IPs from reference UI mockup to country names
GEO_IP_LOOKUP = {
    "185.199.108.153": "United States",
    "203.0.113.45": "Netherlands",
    "198.51.100.23": "Russia",
    "103.21.244.0": "Singapore",
    "45.77.32.11": "Brazil",
    "192.168.1.45": "Local Network",
    "127.0.0.1": "Localhost"
}

def resolve_geoip(ip: Optional[str]) -> str:
    """
    Simulates a Geo-IP database lookup. Maps public and private IPs to countries.
    Falls back to a default country indicator based on IP patterns.
    """
    if not ip:
        return "Unknown"
        
    # Standard static check
    if ip in GEO_IP_LOOKUP:
        return GEO_IP_LOOKUP[ip]
        
    # Fallback simulation logic for testing or extra simulated attacks
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return "Local Network"
        
    # Check IP hash or subnet ranges for simulation
    last_octet = ip.split(".")[-1]
    try:
        val = int(last_octet) % 5
        countries = ["United States", "United Kingdom", "Germany", "India", "Canada"]
        return countries[val]
    except ValueError:
        return "Unknown"


def parse_user_agent(ua_string: Optional[str]) -> str:
    """
    Parses a raw HTTP user-agent header string into a clean browser/system name.
    """
    if not ua_string:
        return "System Agent"
        
    ua_lower = ua_string.lower()
    
    if "firefox" in ua_lower:
        return "Firefox"
    elif "chrome" in ua_lower and "safari" in ua_lower and "edge" not in ua_lower:
        return "Chrome"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        return "Safari"
    elif "edge" in ua_lower or "edg/" in ua_lower:
        return "Edge"
    elif "curl" in ua_lower:
        return "cURL Client"
    elif "postman" in ua_lower:
        return "Postman Client"
    elif "nmap" in ua_lower:
        return "Security Scanner (Nmap)"
    
    return "Generic Client"
