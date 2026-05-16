from app.services.parser_service import resolve_geoip, parse_user_agent

def test_resolve_geoip_mock_ips():
    """
    Ensures that our mock Geo-IP lookup maps reference IPs correctly.
    """
    assert resolve_geoip("185.199.108.153") == "United States"
    assert resolve_geoip("203.0.113.45") == "Netherlands"
    assert resolve_geoip("198.51.100.23") == "Russia"
    assert resolve_geoip("103.21.244.0") == "Singapore"
    assert resolve_geoip("45.77.32.11") == "Brazil"
    assert resolve_geoip("192.168.1.1") == "Local Network"
    assert resolve_geoip("127.0.0.1") == "Localhost"
    assert resolve_geoip(None) == "Unknown"

def test_resolve_geoip_fallback():
    """
    Tests that unknown public IPs fall back to standard simulated geo-maps.
    """
    # IP ending in .0 -> 0 % 5 -> index 0 -> United States
    assert resolve_geoip("8.8.8.0") == "United States"
    # IP ending in .4 -> 4 % 5 -> index 4 -> Canada
    assert resolve_geoip("8.8.8.4") == "Canada"

def test_parse_user_agent():
    """
    Verifies browser classifications from HTTP user-agent header strings.
    """
    chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    firefox_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0"
    nmap_ua = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
    
    assert parse_user_agent(chrome_ua) == "Chrome"
    assert parse_user_agent(firefox_ua) == "Firefox"
    assert parse_user_agent(nmap_ua) == "Security Scanner (Nmap)"
    assert parse_user_agent(None) == "System Agent"
    assert parse_user_agent("some random bot") == "Generic Client"
