# dd-sec-lab (Security Lab App)

`dd-sec-lab` is a small, intentionally “noisy” demo application designed to generate **Datadog Security signals** (Cloud SIEM / Log Detection, and optionally runtime-style triggers) using predictable login events, HTTP endpoints, and an attack traffic generator.

It’s meant for:
- validating log ingestion
- testing / demoing out-of-the-box (OOTB) Cloud SIEM detections
- generating consistent security telemetry (auth failures, suspicious requests, injection-like patterns, etc.)
- experimenting with custom detection rules

> ⚠️ This app intentionally generates suspicious/attack-like activity.

---

## What the app does

The API exposes a few endpoints:
- `GET /health` — basic liveness check
- `POST /login` — returns a JWT token on success (`admin` / `pw`)
- `GET /admin` — a token-protected endpoint (for “auth required” behavior)
- Additional endpoints may exist depending on the repo version (search/webhook/etc.)

The repo also includes:
- `scripts/attack.py` — generates repeated “attack-ish” traffic for SIEM detections
- `scripts/runtime_triggers.sh` — runs commands inside the container to simulate runtime-like behaviors

---

## Prerequisites

- Docker Desktop (or Docker Engine) with `docker compose`
- Python 3 (for `scripts/attack.py`)
- Datadog org with:
  - Logs enabled / ingesting
  - Cloud SIEM enabled (Security Signals)

---

## Start App

From the repo root:

```bash
docker compose up --build
```

---

## After running the requests above, logs and traces appear immediately. Cloud SIEM signals may take 1–5 minutes depending on detection windows.

# Health check (basic traffic)
curl -s http://localhost:8080/health


# Login and capture token
TOKEN=$(curl -s -XPOST http://localhost:8080/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"pw"}' \
  | python -c "import sys, json; print(json.load(sys.stdin)['token'])")


# Access a protected endpoint (auth + trace)
curl -s http://localhost:8080/admin \
  -H "Authorization: Bearer $TOKEN"


# Failed login attempts (brute-force style behavior)
for i in {1..5}; do
  curl -s -XPOST http://localhost:8080/login \
    -H 'content-type: application/json' \
    -d '{"username":"admin","password":"wrong'$i'"}' >/dev/null
done


# SQL injection-style request (AppSec + SIEM patterns)
curl -s "http://localhost:8080/search?q=' OR 1=1 --" \
  -H "Authorization: Bearer $TOKEN"


# XSS-style payload in request body
curl -s -XPOST http://localhost:8080/webhook \
  -H "Authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{"comment":"<script>alert(1)</script>","source":"readme-example"}'
