import urllib.request
import json
import time

def test():
    print("Testing stats api...")
    start = time.time()
    try:
        req = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/logs/stats?interval=5m", timeout=15)
        print("Status:", req.getcode())
        data = json.loads(req.read().decode())
        print("Success! Keys in response:", list(data.keys()))
        print("Timeline count:", len(data.get("timeline", [])))
    except Exception as e:
        print("Failed:", e)
    print("Elapsed time:", time.time() - start)

if __name__ == "__main__":
    test()
