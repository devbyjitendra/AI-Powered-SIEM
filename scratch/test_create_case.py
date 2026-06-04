import requests

base_url = "http://127.0.0.1:8000/api/v1"

# 1. Create case
payload = {
    "title": "Test case from script",
    "severity": "HIGH",
    "assigned_to": "Unassigned"
}
try:
    r = requests.post(f"{base_url}/cases", json=payload)
    print("Create Case Response Code:", r.status_code)
    print("Create Case Response Content:", r.json())
    
    # 2. Get alerts to find a valid alert ID
    r_alerts = requests.get(f"{base_url}/alerts")
    alerts = r_alerts.json()
    if alerts:
        alert_id = alerts[0]["id"]
        case_id = r.json()["id"]
        # Link alert to case
        r_link = requests.post(f"{base_url}/cases/{case_id}/alerts?alert_id={alert_id}")
        print("Link Alert Response Code:", r_link.status_code)
        print("Link Alert Response Content:", r_link.json())
    else:
        print("No alerts found in system to link.")
except Exception as e:
    print("Error:", e)
