import os
import sys
import json
import logging
import asyncio
import subprocess
import threading
import queue
from functools import wraps
from flask import Flask, Response, request, jsonify
import requests

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
CACHE_TTL      = int(os.environ.get("CACHE_TTL", 6 * 3600))
FETCH_TIMEOUT  = int(os.environ.get("FETCH_TIMEOUT", 30))
W3W_API_KEY    = os.environ.get("W3W_API_KEY", "")

# ── CORS helper ───────────────────────────────────────────────────────────────
def corsify(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            r = Response("", status=204)
            r.headers["Access-Control-Allow-Origin"]  = ALLOWED_ORIGIN
            r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
            r.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
            return r
        resp = f(*args, **kwargs)
        if hasattr(resp, "headers"):
            resp.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        return resp
    return wrapper

def sse_headers():
    return {
        "Content-Type":                "text/event-stream",
        "Cache-Control":               "no-cache",
        "X-Accel-Buffering":           "no",
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    }

def sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"

# ── Sanctions cache (kept from original) ─────────────────────────────────────
import time
_cache = {}

SOURCES = {
    "ofac": {"label":"OFAC SDN List (USA)","url":"https://www.treasury.gov/ofac/downloads/sdn.xml"},
    "un":   {"label":"UN Security Council Consolidated List","url":"https://scsanctions.un.org/resources/xml/en/consolidated.xml"},
    "eu":   {"label":"EU Consolidated Sanctions List","url":"https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw"},
    "uk":   {"label":"UK Sanctions List (FCDO)","url":"https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.xml"},
}

@app.route("/")
def index():
    return jsonify({"service":"The Intel Desk API","status":"ok"})

@app.route("/debug-env")
def debug_env():
    return jsonify({
        "W3W_API_KEY_set":    bool(os.environ.get("W3W_API_KEY","")),
        "W3W_API_KEY_length": len(os.environ.get("W3W_API_KEY","")),
        "W3W_module_var_set": bool(W3W_API_KEY),
        "W3W_module_var_len": len(W3W_API_KEY),
        "all_env_keys": [k for k in os.environ.keys() if not k.startswith("PATH") and not k.startswith("LD")],
    })

@app.route("/sanctions/<source>", methods=["GET","OPTIONS"])
@corsify
def fetch_sanctions(source):
    if source not in SOURCES:
        return Response(f'{{"error":"Unknown source: {source}"}}', status=404, mimetype="application/json")
    now = time.time()
    if source in _cache and (now - _cache[source]["ts"]) < CACHE_TTL:
        r = Response(_cache[source]["data"], status=200, mimetype="application/xml")
        r.headers["X-Cache"] = "HIT"
        return r
    try:
        resp = requests.get(SOURCES[source]["url"], timeout=FETCH_TIMEOUT,
            headers={"User-Agent":"IntelDesk/1.0"})
        resp.raise_for_status()
        _cache[source] = {"data": resp.content, "ts": now}
        r = Response(resp.content, status=200, mimetype="application/xml")
        r.headers["X-Cache"] = "MISS"
        return r
    except Exception as e:
        return Response(f'{{"error":"{str(e)}"}}', status=502, mimetype="application/json")

@app.route("/sanctions/<source>/status", methods=["GET","OPTIONS"])
@corsify
def sanctions_status(source):
    if source not in SOURCES:
        return jsonify({"error": f"Unknown source: {source}"}), 404
    cached = source in _cache
    age    = int(time.time() - _cache[source]["ts"]) if cached else None
    return jsonify({"source":source,"cached":cached,"age_seconds":age,"ttl":CACHE_TTL})

@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    secret = os.environ.get("CACHE_CLEAR_SECRET","")
    if secret and request.json.get("secret") != secret:
        return jsonify({"error":"Unauthorized"}), 403
    _cache.clear()
    return jsonify({"cleared": True})

# ── W3W routes ────────────────────────────────────────────────────────────────
@app.route("/w3w", methods=["GET","OPTIONS"])
@corsify
def what3words_forward():
    if not W3W_API_KEY:
        return Response('{"error":"W3W_API_KEY not set"}', status=503, mimetype="application/json")
    lat = request.args.get("lat","")
    lng = request.args.get("lng","")
    if not lat or not lng:
        return Response('{"error":"lat and lng required"}', status=400, mimetype="application/json")
    try:
        r = requests.get("https://api.what3words.com/v3/convert-to-3wa",
            params={"coordinates":f"{lat},{lng}","language":"en","format":"json","key":W3W_API_KEY},
            timeout=8, headers={"User-Agent":"IntelDesk/1.0"})
        d = r.json()
        if "words" in d:
            return jsonify({"words":d["words"],"nearestPlace":d.get("nearestPlace",""),"country":d.get("country","")})
        return Response(f'{{"error":"{d.get("error",{}).get("message","w3w error")}"}}', status=400, mimetype="application/json")
    except requests.exceptions.Timeout:
        return Response('{"error":"w3w API timed out"}', status=504, mimetype="application/json")

@app.route("/w3w-reverse", methods=["GET","OPTIONS"])
@corsify
def what3words_reverse():
    if not W3W_API_KEY:
        return Response('{"error":"W3W_API_KEY not set"}', status=503, mimetype="application/json")
    words = request.args.get("words","").strip().lstrip("/").lower()
    if not words or len(words.split(".")) != 3:
        return Response('{"error":"Provide three dot-separated words"}', status=400, mimetype="application/json")
    try:
        r = requests.get("https://api.what3words.com/v3/convert-to-coordinates",
            params={"words":words,"format":"json","key":W3W_API_KEY},
            timeout=8, headers={"User-Agent":"IntelDesk/1.0"})
        d = r.json()
        if "coordinates" in d:
            return jsonify({"lat":d["coordinates"]["lat"],"lng":d["coordinates"]["lng"],"words":d.get("words",""),"nearestPlace":d.get("nearestPlace",""),"country":d.get("country","")})
        return Response(f'{{"error":"{d.get("error",{}).get("message","w3w error")}"}}', status=400, mimetype="application/json")
    except requests.exceptions.Timeout:
        return Response('{"error":"w3w API timed out"}', status=504, mimetype="application/json")

# ── WHOIS route ───────────────────────────────────────────────────────────────
@app.route("/whois", methods=["GET","OPTIONS"])
@corsify
def whois_lookup():
    domain = request.args.get("domain","").strip().lower()
    if not domain:
        return Response('{"error":"domain parameter required"}', status=400, mimetype="application/json")
    domain = domain.replace("https://","").replace("http://","").split("/")[0]
    try:
        import whois as python_whois
        w = python_whois.whois(domain)
        def fmt_date(d):
            if d is None: return None
            if isinstance(d, list): d = d[0]
            try: return d.strftime("%Y-%m-%d")
            except: return str(d)
        def clean(v):
            if v is None: return None
            if isinstance(v, list):
                seen = set(); out = []
                for i in v:
                    s = str(i).strip()
                    if s and s.lower() not in seen:
                        seen.add(s.lower()); out.append(s)
                return out if len(out) > 1 else (out[0] if out else None)
            return str(v).strip() or None
        result = {
            "domain":      domain,
            "registrar":   clean(w.registrar),
            "created":     fmt_date(w.creation_date),
            "expires":     fmt_date(w.expiration_date),
            "updated":     fmt_date(w.updated_date),
            "status":      clean(w.status),
            "nameservers": clean(w.name_servers),
            "dnssec":      clean(w.dnssec),
            "org":         clean(w.org),
            "country":     clean(w.country),
        }
        return jsonify({k:v for k,v in result.items() if v is not None})
    except Exception as e:
        return jsonify({"error": str(e), "domain": domain}), 400

# ── SSE OSINT stream helper ───────────────────────────────────────────────────
def stream_subprocess(cmd, env=None):
    """Run a subprocess and yield SSE events for each output line."""
    def generate():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env={**os.environ, **(env or {})},
            )
            yield sse({"type":"start","cmd":cmd[0]})
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip()
                if line:
                    yield sse({"type":"line","text":line})
            proc.stdout.close()
            proc.wait()
            yield sse({"type":"done","returncode":proc.returncode})
        except FileNotFoundError:
            yield sse({"type":"error","text":f"Tool not found: {cmd[0]}. Is it installed?"})
        except Exception as e:
            yield sse({"type":"error","text":str(e)})
    return generate

# ── HOLEHE — email → platform check ──────────────────────────────────────────
@app.route("/holehe", methods=["GET","OPTIONS"])
@corsify
def holehe_stream():
    email = request.args.get("email","").strip()
    if not email or "@" not in email:
        return Response('{"error":"valid email required"}', status=400, mimetype="application/json")
    gen = stream_subprocess(["holehe", "--no-color", "--only-used", email])
    return Response(gen(), headers=sse_headers())

# ── SHERLOCK — username → social networks ─────────────────────────────────────
@app.route("/sherlock", methods=["GET","OPTIONS"])
@corsify
def sherlock_stream():
    username = request.args.get("username","").strip()
    if not username:
        return Response('{"error":"username required"}', status=400, mimetype="application/json")
    gen = stream_subprocess([
        "python3", "-m", "sherlock_project.sherlock",
        "--no-color", "--print-found",
        username
    ])
    return Response(gen(), headers=sse_headers())

# ── MAIGRET — username → deep profile ─────────────────────────────────────────
@app.route("/maigret", methods=["GET","OPTIONS"])
@corsify
def maigret_stream():
    username = request.args.get("username","").strip()
    if not username:
        return Response('{"error":"username required"}', status=400, mimetype="application/json")
    gen = stream_subprocess([
        "maigret", username,
        "--no-color",
        "--timeout", "10",
        "--retries", "1",
        "-n", "500",       # top 500 sites by popularity
    ])
    return Response(gen(), headers=sse_headers())

# ── IGNORANT — phone → platform check ────────────────────────────────────────
@app.route("/ignorant", methods=["GET","OPTIONS"])
@corsify
def ignorant_stream():
    phone = request.args.get("phone","").strip()
    if not phone:
        return Response('{"error":"phone required"}', status=400, mimetype="application/json")
    gen = stream_subprocess(["ignorant", "--no-color", phone])
    return Response(gen(), headers=sse_headers())

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
