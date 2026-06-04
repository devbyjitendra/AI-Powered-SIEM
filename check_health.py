import urllib.request
import json
import sys

def check():
    try:
        print("Checking health endpoint...")
        req = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/health", timeout=5)
        print("Health Status:", req.getcode())
        print(req.read().decode())
    except Exception as e:
        print("Health failed:", e)

    try:
        print("Checking stats endpoint...")
        req = urllib.request.urlopen("http://127.0.0.1:8000/api/v1/logs/stats?interval=5m", timeout=5)
        print("Stats Status:", req.getcode())
        print(req.read().decode()[:500])
    except Exception as e:
        print("Stats failed:", e)

if __name__ == "__main__":
    check()
