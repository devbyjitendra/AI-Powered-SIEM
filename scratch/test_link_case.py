import urllib.request
import urllib.error
import json

def test():
    # Let's first get alerts to find a valid alert ID
    try:
        req = urllib.request.Request("http://127.0.0.1:8000/api/v1/alerts")
        with urllib.request.urlopen(req) as res:
            alerts = json.loads(res.read().decode())
            print(f"Fetched {len(alerts)} alerts.")
            if not alerts:
                print("No alerts found in DB.")
                return
            alert_id = alerts[0]['id']
            print(f"Using alert ID {alert_id}")
    except Exception as e:
        print(f"Failed to fetch alerts: {e}")
        return

    # Let's create a case first
    try:
        case_data = json.dumps({
            "title": "Test Case Link",
            "severity": "HIGH",
            "assigned_to": "Unassigned"
        }).encode('utf-8')
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/v1/cases",
            data=case_data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            case = json.loads(res.read().decode())
            case_id = case['id']
            print(f"Created case with ID {case_id}")
    except Exception as e:
        print(f"Failed to create case: {e}")
        return

    # Let's link them
    url = f"http://127.0.0.1:8000/api/v1/cases/{case_id}/alerts?alert_id={alert_id}"
    print(f"Request URL: {url}")
    try:
        req = urllib.request.Request(url, data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            result = json.loads(res.read().decode())
            print("Successfully linked case:", result)
    except urllib.error.HTTPError as e:
        print(f"HTTPError: {e.code} - {e.read().decode()}")
    except Exception as e:
        print(f"General error: {e}")

if __name__ == '__main__':
    test()
