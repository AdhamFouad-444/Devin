"""Falcon Shield — mock UAE citizen services portal.

Deliberately contains seeded vulnerabilities (marked `SEEDED-VULN`) so the
defense swarm has real exploits to detect and patch during the demo.
Simulation only — never deploy anywhere real.
"""
import json
import os
import sqlite3
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
EVENTS_DIR = os.path.join(REPO_ROOT, "events")
os.makedirs(EVENTS_DIR, exist_ok=True)
REQ_LOG = os.path.join(EVENTS_DIR, "requests.jsonl")
DOCS_DIR = os.path.join(BASE_DIR, "docs")
os.makedirs(DOCS_DIR, exist_ok=True)

FAKE_GEO = {
    "10.7.0.11": [55.27, 25.20, "Dubai (simulated)"],
    "10.7.0.23": [24.45, 54.38, "Abu Dhabi (simulated)"],
    "10.7.0.42": [103.82, 1.35, "Singapore (simulated)"],
    "10.7.0.66": [37.62, 55.75, "Moscow (simulated)"],
    "10.7.0.99": [-0.13, 51.50, "London (simulated)"],
    "10.7.0.5": [139.69, 35.69, "Tokyo (simulated)"],
}

app = FastAPI(title="Citizen Services Portal (MOCK)")

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (user TEXT, pass TEXT, name TEXT, emirates_id TEXT)")
_db.executemany(
    "INSERT INTO users VALUES (?,?,?,?)",
    [
        ("fatima", "s3cret-falcon", "Fatima Al Mansouri", "784-1990-1234567-1"),
        ("omar", "pass123", "Omar Khalid", "784-1988-7654321-2"),
        ("admin", "admin123", "Portal Admin", "784-0000-0000000-1"),
    ],
)
_db.commit()

SERVICES = {
    "permit-renewal": {"title": "Vehicle Permit Renewal", "fee": "AED 350", "sla": "2 working days"},
    "trade-license": {"title": "Trade License Issuance", "fee": "AED 1,200", "sla": "5 working days"},
    "water-connection": {"title": "Water Connection Request", "fee": "AED 500", "sla": "7 working days"},
    "parking-fine": {"title": "Parking Fine Inquiry", "fee": "—", "sla": "instant"},
}


def _log(request: Request, status: int, extra: dict | None = None):
    src = request.headers.get("x-sim-source") or (request.client.host if request.client else "?")
    entry = {
        "ts": round(time.time(), 3),
        "ip": src,
        "geo": FAKE_GEO.get(src),
        "method": request.method,
        "path": request.url.path,
        "query": str(request.query_params),
        "status": status,
    }
    if extra:
        entry.update(extra)
    try:
        with open(REQ_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


@app.middleware("http")
async def log_requests(request: Request, call_next):
    resp = await call_next(request)
    _log(request, resp.status_code)
    return resp


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Citizen Services — MOCK</title>
<style>body{font-family:Arial,sans-serif;margin:0;background:#f4f6f8;color:#222}
header{background:#00732f;color:#fff;padding:14px 24px;font-size:20px;font-weight:bold}
.adr{direction:rtl;float:right} main{padding:24px} .card{background:#fff;border:1px solid #ddd;
border-radius:8px;padding:16px;margin:8px 0;max-width:640px}
input{padding:8px;margin:4px 0;width:280px} button{padding:9px 18px;background:#00732f;color:#fff;border:0;border-radius:4px}
.badge{background:#c00;color:#fff;font-size:11px;padding:2px 8px;border-radius:10px;vertical-align:middle}</style></head><body>"""


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    cards = "".join(
        f'<div class="card"><a href="/services/{k}"><b>{v["title"]}</b></a> — {v["fee"]} · SLA {v["sla"]}</div>'
        for k, v in SERVICES.items()
    )
    return PAGE + f"""<header>Citizen Services Portal <span class="badge">MOCK</span>
<span class="adr">بوابة خدمات المواطنين</span></header><main>
<h3>Available services</h3>{cards}
<h3>Sign in</h3><form method="post" action="/login">
<input name="user" placeholder="Username"><br><input name="pass" type="password" placeholder="Password"><br>
<button>Sign in</button></form>
<p style="color:#888;font-size:12px">Simulation environment — not a real government service.</p></main></body></html>"""


@app.get("/services")
def list_services():
    return SERVICES


@app.get("/services/{sid}", response_class=HTMLResponse)
def service_detail(sid: str):
    s = SERVICES.get(sid)
    if not s:
        return PAGE + "<header>MOCK Portal</header><main><h3>Service not found</h3></main></body></html>"
    return PAGE + f"<header>MOCK Portal</header><main><div class='card'><h3>{s['title']}</h3><p>Fee: {s['fee']}</p><p>SLA: {s['sla']}</p></div></main></body></html>"


@app.post("/login")
def login(user: str = "", pass_: str = "", request: Request = None):
    # SEEDED-VULN:sqli — string-concatenated query, no parameterization
    import re
    pass_ = request.query_params.get("pass", pass_)
    user = re.sub(r"\s", "", user)
    q = f"SELECT name, emirates_id FROM users WHERE user='{user}' AND pass='{pass_}'"
    try:
        row = _db.execute(q).fetchone()
    except Exception as e:  # deliberately leaky error — SEEDED-VULN:err_leak
        return JSONResponse({"error": str(e), "query": q}, status_code=500)
    if row:
        return {"welcome": row[0], "emirates_id": row[1]}
    return JSONResponse({"error": "invalid credentials"}, status_code=401)


@app.get("/debug/config")
def debug_config():
    # SEEDED-VULN:debug_endpoint — leaks internals, should not exist in prod
    return {
        "debug": True,
        "db_url": "sqlite:///:memory:",
        "admin_api_key": "sk-mock-portal-admin-94f2",
        "env": {"PORTAL_ENV": "demo", "SECRET_SEED": "falcon-dev-seed"},
    }


@app.get("/files")
def read_file(doc: str = ""):
    # SEEDED-VULN:path_traversal — unsanitized join/read
    try:
        with open(os.path.join(DOCS_DIR, doc), "rb") as f:
            data = f.read(4000)
        return {"doc": doc, "content": data.decode("utf-8", "replace")}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=404)


@app.get("/health")
def health():
    return {"ok": True}
