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
from flask_cors import CORS
import requests

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins='*', supports_credentials=False)

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
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods":"GET, OPTIONS",
        "Access-Control-Allow-Headers":"Content-Type",
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

# ── IP Intelligence proxy route ──────────────────────────────────────────────
@app.route("/ip", methods=["GET","OPTIONS"])
@corsify
def ip_lookup():
    """
    IP geolocation proxy — avoids CORS issues with direct browser requests.
    Query: ?ip=8.8.8.8  (omit for caller's own IP)
    """
    ip = request.args.get("ip","").strip()
    
    # Use caller's IP if none provided
    if not ip:
        ip = request.headers.get("X-Forwarded-For","").split(",")[0].strip()
        if not ip:
            ip = request.remote_addr

    # Validate basic format
    if ip and ip not in ("127.0.0.1","::1","localhost"):
        target = ip
    else:
        target = ""

    try:
        url = f"https://ipwho.is/{target}" if target else "https://ipwho.is/"
        r = requests.get(url, timeout=10, headers={"User-Agent":"IntelDesk/1.0"})
        data = r.json()
        if data.get("success"):
            return jsonify(data)
        # Fallback to ip-api (server-side, no CORS issue)
        url2 = f"http://ip-api.com/json/{target}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        r2 = requests.get(url2, timeout=10, headers={"User-Agent":"IntelDesk/1.0"})
        data2 = r2.json()
        if data2.get("status") == "success":
            # Normalize to ipwho.is format
            return jsonify({
                "success": True,
                "ip": data2.get("query", target),
                "country": data2.get("country",""),
                "country_code": data2.get("countryCode",""),
                "region": data2.get("regionName",""),
                "city": data2.get("city",""),
                "zip": data2.get("zip",""),
                "latitude": data2.get("lat"),
                "longitude": data2.get("lon"),
                "timezone": {"id": data2.get("timezone","")},
                "connection": {
                    "isp": data2.get("isp",""),
                    "org": data2.get("org",""),
                    "asn": data2.get("as","").split()[0].replace("AS","") if data2.get("as") else "",
                    "domain": data2.get("asname",""),
                },
                "type": "mobile" if data2.get("mobile") else ("hosting" if data2.get("hosting") else ("proxy" if data2.get("proxy") else "business")),
                "is_mobile": data2.get("mobile", False),
                "is_proxy": data2.get("proxy", False),
                "is_hosting": data2.get("hosting", False),
                "continent": data2.get("continent",""),
            })
        return jsonify({"success": False, "error": "Lookup failed", "ip": target}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "ip": target}), 500

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
        import socket
        import concurrent.futures
        # Set a timeout so it doesn't hang
        socket.setdefaulttimeout(12)
        # Run with thread timeout to prevent hanging
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(python_whois.whois, domain)
            try:
                w = future.result(timeout=14)
            except concurrent.futures.TimeoutError:
                return jsonify({"error": "WHOIS lookup timed out for this domain", "domain": domain}), 504
        if w is None:
            return jsonify({"error": "No WHOIS data returned", "domain": domain}), 404

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
                    s = str(i).strip().lower()
                    if s and s not in seen:
                        seen.add(s); out.append(str(i).strip())
                return out if len(out) > 1 else (out[0] if out else None)
            s = str(v).strip()
            return s if s else None

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
        filtered = {k:v for k,v in result.items() if v is not None}
        if len(filtered) <= 1:
            return jsonify({"error": "No WHOIS data available for this domain", "domain": domain}), 404
        return jsonify(filtered)
    except Exception as e:
        log.error(f"WHOIS error for {domain}: {e}")
        return jsonify({"error": f"WHOIS lookup failed: {str(e)}", "domain": domain}), 400

# ── SSE OSINT stream helper ───────────────────────────────────────────────────
def stream_subprocess(cmd, env=None):
    """Run a subprocess and yield SSE events for each line.
    Sends keepalive comments every 15s to prevent proxy/Render timeout."""
    import select, time

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
            last_ping = time.time()
            proc.stdout.flush()

            while True:
                # Check if data is ready with 1s timeout
                ready = select.select([proc.stdout], [], [], 1.0)[0]
                if ready:
                    line = proc.stdout.readline()
                    if not line:  # EOF
                        break
                    line = line.rstrip()
                    if line:
                        yield sse({"type":"line","text":line})
                        last_ping = time.time()
                else:
                    # No data — check if process finished
                    if proc.poll() is not None:
                        # Drain any remaining output
                        for line in proc.stdout:
                            line = line.rstrip()
                            if line:
                                yield sse({"type":"line","text":line})
                        break
                    # Send keepalive ping every 15 seconds
                    if time.time() - last_ping > 15:
                        yield ": keepalive\n\n"
                        last_ping = time.time()

            proc.stdout.close()
            proc.wait()
            yield sse({"type":"done","returncode":proc.returncode})
        except FileNotFoundError:
            yield sse({"type":"error","text":f"Tool not found: {cmd[0]}. Is it installed on this server?"})
        except Exception as e:
            yield sse({"type":"error","text":str(e)})
    return generate

# ── HOLEHE — email → platform check ──────────────────────────────────────────
@app.route("/holehe", methods=["GET","OPTIONS"])
def holehe_stream():
    email = request.args.get("email","").strip()
    if not email or "@" not in email:
        return Response('{"error":"valid email required"}', status=400, mimetype="application/json")
    gen = stream_subprocess(["holehe", "--no-color", "--only-used", email])
    return Response(gen(), headers=sse_headers())

# ── SHERLOCK — username → social networks ─────────────────────────────────────
@app.route("/sherlock", methods=["GET","OPTIONS"])
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
def ignorant_stream():
    phone = request.args.get("phone","").strip()
    if not phone:
        return Response('{"error":"phone required"}', status=400, mimetype="application/json")
    gen = stream_subprocess(["ignorant", "--no-color", phone])
    return Response(gen(), headers=sse_headers())
@app.route("/ip", methods=["GET","OPTIONS"])
@corsify
def ip_lookup():
    ip = request.args.get("ip","").strip()
    if not ip:
        ip = request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.remote_addr
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=10, headers={"User-Agent":"IntelDesk/1.0"})
        d = r.json()
        if d.get("success"):
            return jsonify(d)
        r2 = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query", timeout=10)
        d2 = r2.json()
        if d2.get("status") == "success":
            return jsonify({"success":True,"ip":d2.get("query",ip),"country":d2.get("country",""),"country_code":d2.get("countryCode",""),"region":d2.get("regionName",""),"city":d2.get("city",""),"latitude":d2.get("lat"),"longitude":d2.get("lon"),"timezone":{"id":d2.get("timezone","")},"connection":{"isp":d2.get("isp",""),"org":d2.get("org",""),"asn":d2.get("as","").split()[0].replace("AS","") if d2.get("as") else "","domain":d2.get("asname","")},"is_mobile":d2.get("mobile",False),"is_proxy":d2.get("proxy",False),"is_hosting":d2.get("hosting",False),"continent":d2.get("continent","")})
        return jsonify({"success":False,"error":"Lookup failed"}), 400
    except Exception as e:
        return jsonify({"success":False,"error":str(e)}), 500
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
