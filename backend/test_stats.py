import urllib.request
import json
import traceback

try:
    url = "http://127.0.0.1:8000/api/v1/logs/stats?interval=5m"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode('utf-8'))
        print("SUCCESS! Keys:", list(data.keys()))
except Exception as e:
    print("ERROR FETCHING STATS:")
    traceback.print_exc()
    if hasattr(e, "read"):
        try:
            print("Response body:", e.read().decode('utf-8'))
        except Exception:
            pass
