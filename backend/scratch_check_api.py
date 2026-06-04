import urllib.request
import json

def check_endpoint(url):
    print(f"Checking {url}...")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode('utf-8'))
            print(f"Status: {res.status}")
            print(f"Response: {data}\n")
    except Exception as e:
        print(f"Error checking {url}: {e}\n")

if __name__ == "__main__":
    check_endpoint("http://127.0.0.1:8000/api/v1/health")
    check_endpoint("http://127.0.0.1:8000/api/v1/rules")
    check_endpoint("http://127.0.0.1:8000/api/v1/alerts")
    check_endpoint("http://127.0.0.1:8000/api/v1/cases")
