import argparse
import json
import random
import time
import requests

SQLI = ["' OR '1'='1", "'; SELECT pg_sleep(1); --", "\" OR 1=1 --"]
XSS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
LFI = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--passw", default="pw")
    ap.add_argument("--seconds", type=int, default=30)
    args = ap.parse_args()

    s = requests.Session()

    # login
    r = s.post(f"{args.base}/login", json={"username": args.user, "password": args.passw}, timeout=5)
    r.raise_for_status()
    token = r.json()["token"]
    s.headers["Authorization"] = f"Bearer {token}"

    end = time.time() + args.seconds
    while time.time() < end:
        choice = random.choice(["search_sqli", "webhook_xss", "login_bruteforce", "admin", "lfi_like"])
        try:
            if choice == "search_sqli":
                q = random.choice(SQLI)
                s.get(f"{args.base}/search", params={"q": q, "owner": "admin"}, timeout=5)
            elif choice == "webhook_xss":
                payload = {"comment": random.choice(XSS), "meta": {"ua": "attack.py"}}
                s.post(f"{args.base}/webhook", json=payload, timeout=5)
            elif choice == "admin":
                s.get(f"{args.base}/admin", timeout=5)
            elif choice == "lfi_like":
                s.get(f"{args.base}/search", params={"q": random.choice(LFI)}, timeout=5)
            elif choice == "login_bruteforce":
                # brute force burst to trigger rate limiting / SIEM signals
                for i in range(5):
                    s.post(f"{args.base}/login", json={"username": "admin", "password": f"bad{i}"}, timeout=5)
        except Exception as e:
            print("err:", e)

        time.sleep(0.2)

    print(json.dumps({"done": True}))

if __name__ == "__main__":
    main()
