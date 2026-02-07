import json
import os
import time
import uuid
from typing import Optional

from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import text

import redis as redis_lib

from db import SessionLocal, init_db
from settings import settings

app = FastAPI(title="DD Security Lab", version="0.1.0")

r = redis_lib.from_url(settings.redis_url, decode_responses=True)

def jlog(level: str, event: str, **fields):
    payload = {
        "ts": time.time(),
        "level": level,
        "event": event,
        "service": "dd-security-lab",
        "env": settings.app_env,
        **fields,
    }
    print(json.dumps(payload), flush=True)

@app.on_event("startup")
def startup():
    init_db()
    jlog("INFO", "startup", danger_mode=settings.danger_mode, weak_auth_mode=settings.weak_auth_mode)

@app.middleware("http")
async def add_request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    start = time.time()
    try:
        response = await call_next(request)
        duration_ms = int((time.time() - start) * 1000)
        jlog(
            "INFO", "http_request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=str(request.url.query),
            status=response.status_code,
            duration_ms=duration_ms,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        response.headers["x-request-id"] = request_id
        return response
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        jlog(
            "ERROR", "http_exception",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            err=str(e),
            duration_ms=duration_ms,
        )
        raise

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    # Brute force detector (simple)
    key = f"bf:{request.client.host if request.client else 'unknown'}:{username}"
    tries = r.incr(key)
    r.expire(key, 60)

    if tries > 10:
        jlog("WARN", "auth_bruteforce_suspected", username=username, tries=tries)
        raise HTTPException(status_code=429, detail="Too many attempts")

    if settings.weak_auth_mode:
        # intentionally weak: accepts any password length >= 1 for demo
        ok = bool(username) and bool(password)
    else:
        ok = (username == "admin" and password == "correcthorsebatterystaple")

    if ok:
        token = str(uuid.uuid4())
        r.setex(f"token:{token}", 3600, username)
        jlog("INFO", "auth_success", username=username)
        return {"token": token}
    else:
        jlog("WARN", "auth_failed", username=username)
        raise HTTPException(status_code=401, detail="Invalid credentials")

def require_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    username = r.get(f"token:{token}")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    return username

@app.post("/upload")
async def upload(request: Request, f: UploadFile = File(...)):
    user = require_token(request)
    content = await f.read()
    size = len(content)
    # store file under /tmp in container (lab)
    os.makedirs("/tmp/uploads", exist_ok=True)
    path = f"/tmp/uploads/{uuid.uuid4()}_{f.filename}"
    with open(path, "wb") as out:
        out.write(content)

    jlog("INFO", "file_uploaded", user=user, filename=f.filename, size=size, stored_path=path)
    return {"stored_path": path, "size": size}

@app.get("/search")
def search(request: Request, q: str, owner: Optional[str] = None):
    """
    Safe by default (parameterized).
    If DANGER_MODE=true, uses unsafe string formatting to simulate SQLi patterns.
    """
    user = require_token(request)
    owner = owner or user

    with SessionLocal() as db:
        if settings.danger_mode:
            # INTENTIONALLY UNSAFE: simulates SQL injection risk
            stmt = text(f"SELECT id, owner, body FROM notes WHERE owner = '{owner}' AND body ILIKE '%{q}%'")
        else:
            stmt = text("SELECT id, owner, body FROM notes WHERE owner = :owner AND body ILIKE :pat")
        if settings.danger_mode:
            rows = db.execute(stmt).fetchall()
        else:
            rows = db.execute(stmt, {"owner": owner, "pat": f"%{q}%"}).fetchall()

    jlog("INFO", "search", user=user, owner=owner, q=q, rows=len(rows), danger_mode=settings.danger_mode)
    return {"count": len(rows), "rows": [dict(r._mapping) for r in rows]}

@app.get("/admin")
def admin(request: Request):
    user = require_token(request)

    if settings.weak_auth_mode:
        # intentionally lax when weak_auth_mode=true
        allowed = (user in ["admin", "administrator"]) or user.startswith("a")
    else:
        allowed = (user == "admin")

    if not allowed:
        jlog("WARN", "admin_forbidden", user=user)
        raise HTTPException(status_code=403, detail="Forbidden")

    jlog("INFO", "admin_access", user=user)
    return {"message": "Welcome to admin area", "user": user}

@app.post("/webhook")
async def webhook(request: Request):
    """
    Parses JSON and logs it. In DANGER_MODE it also echoes back fields
    in a way that can be used to test XSS-ish reflections in clients.
    """
    user = "anonymous"
    try:
        user = require_token(request)
    except Exception:
        pass

    payload = await request.json()
    jlog("INFO", "webhook_received", user=user, keys=list(payload.keys())[:50])

    if settings.danger_mode:
        # reflect input (still JSON), useful for testing alerting + suspicious payload logging
        return JSONResponse({"received": payload, "reflected": True})
    return {"received": True}

@app.get("/debug/exec")
def debug_exec(request: Request, cmd: str):
    """
    Disabled unless DANGER_MODE=true.
    DO NOT expose publicly. Exists solely to generate detection signals in a lab.
    """
    if not settings.danger_mode:
        raise HTTPException(status_code=404, detail="Not found")

    user = require_token(request)
    # DO NOT actually exec arbitrary commands here (that’s too risky).
    # Instead, simulate an “exec attempt” signal.
    jlog("WARN", "exec_attempt", user=user, cmd=cmd)
    return {"ok": False, "message": "Simulated exec attempt logged", "cmd": cmd}
