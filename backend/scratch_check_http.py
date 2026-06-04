import urllib.request
import json

def check(url):
    print(f"GET {url}")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as res:
            print(f"Status: {res.status}")
            data = res.read().decode('utf-8')
            print(f"Response: {data[:200]}...\n")
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.read().decode('utf-8')}\n")
    except Exception as e:
        print(f"Error: {e}\n")

if __name__ == "__main__":
    check("http://127.0.0.1:8000/api/v1/logs/stats")
    check("http://127.0.0.1:8000/api/v1/alerts?status=NEW")
