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
from network_analyzer import network_bp

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── ENVIRONMENT VARIABLES REQUIRED ───────────────────────────────────────────
# Set these in Render Dashboard → Environment (never hardcode in this file):
#
#   AISSTREAM_KEY   — aisstream.io WebSocket API key
#   HIVE_KEY_ID     — Hive AI Access Key ID (thehive.ai)
#   HIVE_SECRET     — Hive AI Secret Key
#   HF_TOKEN        — HuggingFace API token (huggingface.co/settings/tokens)
#   W3W_API_KEY     — what3words API key
#
# Optional (used by specific tools):
#   IPINFO_KEY      — IPInfo token (ipinfo.io)
#   ABUSEIPDB_KEY   — AbuseIPDB API key
#
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.register_blueprint(network_bp)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB upload limit
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

# ── WHATSMYNAME — username → 500+ sites via live JSON database ──────────────
WMN_DB_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_wmn_cache = {"data": None, "ts": 0}

def get_wmn_db():
    import time
    now = time.time()
    if _wmn_cache["data"] and (now - _wmn_cache["ts"]) < 3600:
        return _wmn_cache["data"]
    try:
        r = requests.get(WMN_DB_URL, timeout=15, headers={"User-Agent":"IntelDesk/1.0"})
        r.raise_for_status()
        _wmn_cache["data"] = r.json()
        _wmn_cache["ts"] = now
        return _wmn_cache["data"]
    except Exception as e:
        log.error(f"WMN DB fetch: {e}")
        return None

@app.route("/maigret", methods=["GET","OPTIONS"])
@corsify
def maigret_stream():
    """WhatsMyName check — replaces maigret endpoint."""
    username = request.args.get("username","").strip()
    if not username:
        return Response('{"error":"username required"}', status=400, mimetype="application/json")

    def generate():
        try:
            import asyncio, httpx
            yield sse({"type":"start","cmd":"whatsmyname"})
            yield sse({"type":"line","text":"[*] Loading WhatsMyName database..."})

            db = get_wmn_db()
            if not db:
                yield sse({"type":"error","text":"Could not load WhatsMyName database."})
                return

            sites = db.get("sites",[])
            yield sse({"type":"line","text":f"[*] Checking {username} across {len(sites)} sites..."})
            yield sse({"type":"line","text":""})

            found_count = 0

            async def run():
                nonlocal found_count
                results = []
                BATCH = 25
                for i in range(0, len(sites), BATCH):
                    batch = sites[i:i+BATCH]
                    async with httpx.AsyncClient(
                        timeout=7, follow_redirects=True,
                        headers={"User-Agent":"Mozilla/5.0 (compatible; IntelDesk/1.0)"},
                        limits=httpx.Limits(max_connections=25),
                    ) as client:
                        urls = [s.get("uri_check","").replace("{account}", username) for s in batch]
                        resps = await asyncio.gather(*[client.get(u) for u in urls], return_exceptions=True)
                        for site, url, resp in zip(batch, urls, resps):
                            name = site.get("name","")
                            if isinstance(resp, Exception):
                                continue
                            e_code   = site.get("e_code", 200)
                            e_string = site.get("e_string","")
                            m_string = site.get("m_string","")
                            try:
                                hit = (
                                    resp.status_code == e_code and
                                    (not e_string or e_string in resp.text) and
                                    (not m_string or m_string not in resp.text)
                                )
                            except Exception:
                                hit = False
                            profile = site.get("uri_pretty","").replace("{account}", username) or url
                            results.append((hit, name, profile))
                return results

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                all_results = loop.run_until_complete(run())
            finally:
                loop.close()

            for hit, name, url in all_results:
                if hit:
                    found_count += 1
                    yield sse({"type":"line","text":f"[+] {name}: {url}"})
                else:
                    yield sse({"type":"line","text":f"[-] {name}"})

            yield sse({"type":"line","text":""})
            yield sse({"type":"line","text":f"[*] Complete — {found_count} profiles found across {len(sites)} sites"})
            yield sse({"type":"done","returncode":0})

        except Exception as e:
            yield sse({"type":"error","text":f"Error: {str(e)}"})

    return Response(generate(), headers=sse_headers())


# ── WHATSMYNAME via Naminter ─────────────────────────────────────────────────
@app.route("/whatsmyname", methods=["GET","OPTIONS"])
@corsify
def whatsmyname_stream():
    username = request.args.get("username","").strip()
    if not username:
        return Response('{"error":"username required"}', status=400, mimetype="application/json")
    gen = stream_subprocess([
        "naminter",
        "--username", username,
        "--found-only",
        "--no-color",
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


# ── URL INTELLIGENCE routes ───────────────────────────────────────────────────
import ssl
import socket
import urllib.parse
from datetime import datetime

@app.route("/url-inspect", methods=["GET","OPTIONS"])
@corsify
def url_inspect():
    """
    Follow redirect chain, get final URL, SSL cert, response info.
    Query: ?url=https://example.com
    """
    raw = request.args.get("url","").strip()
    if not raw:
        return jsonify({"error": "url parameter required"}), 400

    # Ensure scheme
    if not raw.startswith(('http://','https://')):
        raw = 'https://' + raw

    try:
        import requests as req
        result = {
            "original_url": raw,
            "redirect_chain": [],
            "final_url": None,
            "final_domain": None,
            "status_code": None,
            "content_type": None,
            "server": None,
            "response_time_ms": None,
            "ssl": None,
        }

        # Follow redirects manually to capture chain
        session = req.Session()
        session.max_redirects = 10
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; IntelDesk/1.0; +https://inteldesk.io)",
            "Accept": "text/html,application/xhtml+xml,*/*",
        }

        # Manual redirect chain
        chain = []
        current_url = raw
        import time

        for _ in range(10):
            t0 = time.time()
            try:
                r = req.get(
                    current_url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=10,
                    verify=False,  # We check SSL separately
                )
                elapsed = int((time.time() - t0) * 1000)
                chain.append({
                    "url": current_url,
                    "status_code": r.status_code,
                    "elapsed_ms": elapsed,
                })
                if r.status_code in (301,302,303,307,308) and 'Location' in r.headers:
                    loc = r.headers['Location']
                    # Handle relative redirects
                    if loc.startswith('/'):
                        parsed = urllib.parse.urlparse(current_url)
                        loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                    current_url = loc
                else:
                    # Final destination
                    result['status_code']   = r.status_code
                    result['content_type']  = r.headers.get('Content-Type','').split(';')[0]
                    result['server']        = r.headers.get('Server','')
                    result['response_time_ms'] = elapsed
                    result['x_powered_by']  = r.headers.get('X-Powered-By','')
                    result['content_length']= r.headers.get('Content-Length','')
                    break
            except req.exceptions.SSLError:
                chain.append({"url": current_url, "status_code": "SSL_ERROR", "elapsed_ms": 0})
                break
            except Exception as e:
                chain.append({"url": current_url, "status_code": f"ERROR: {str(e)[:60]}", "elapsed_ms": 0})
                break

        result['redirect_chain'] = chain
        result['final_url']      = current_url
        parsed_final = urllib.parse.urlparse(current_url)
        result['final_domain']   = parsed_final.netloc

        # SSL certificate info
        try:
            hostname = parsed_final.netloc.split(':')[0]
            port     = int(parsed_final.port or 443)
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['ssl'] = {
                        "valid": True,
                        "subject": dict(x[0] for x in cert.get('subject',[])),
                        "issuer":  dict(x[0] for x in cert.get('issuer',[])),
                        "not_before": cert.get('notBefore',''),
                        "not_after":  cert.get('notAfter',''),
                        "san": [v for t,v in cert.get('subjectAltName',[]) if t=='DNS'],
                        "version": cert.get('version',''),
                    }
        except ssl.SSLCertVerificationError as e:
            result['ssl'] = {"valid": False, "error": str(e)[:100]}
        except Exception as e:
            result['ssl'] = {"valid": None, "error": str(e)[:80]}

        # ── Extract links, emails, phones from page HTML
        try:
            page_resp = req.get(current_url, headers=headers, timeout=10, verify=False)
            html = page_resp.text
            import re as _re

            emails = list(set(_re.findall(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html
            )))
            bad = ["example.","sentry","wixpress","@2x","schema.org",
                   "w3.org","xmlns","openid",".png",".jpg",".gif",".svg"]
            emails = [e for e in emails if not any(x in e.lower() for x in bad)][:30]

            phones = list(set(_re.findall(
                r"(?:(?:\+|00)[1-9]\d{0,2}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}",
                html
            )))
            phones = [p.strip() for p in phones if len(p.strip()) >= 10][:20]

            raw_links = _re.findall(r"""href=["']([^"']+)["']""", html)
            links = []
            seen = set()
            for lnk in raw_links:
                if lnk.startswith("http") and lnk not in seen:
                    seen.add(lnk); links.append(lnk)
                elif lnk.startswith("/") and lnk not in seen:
                    seen.add(lnk)
                    pb = urllib.parse.urlparse(current_url)
                    links.append(f"{pb.scheme}://{pb.netloc}{lnk}")
            links = links[:50]

            socials = {}
            skip = {"share","sharer","intent","login","signup","home","explore",
                    "about","privacy","terms","settings","help","www","web","ads"}
            sp = {
                "twitter":   r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})",
                "instagram": r"instagram\.com/([A-Za-z0-9_.]{1,30})",
                "linkedin":  r"linkedin\.com/(?:in|company)/([A-Za-z0-9\-_]{1,60})",
                "facebook":  r"facebook\.com/([A-Za-z0-9.\-]{1,50})",
                "github":    r"github\.com/([A-Za-z0-9\-]{1,39})",
                "youtube":   r"youtube\.com/(?:@|channel/|user/)([A-Za-z0-9_\-]{1,60})",
                "tiktok":    r"tiktok\.com/@([A-Za-z0-9_.]{1,24})",
            }
            for platform, pattern in sp.items():
                found = [h for h in set(_re.findall(pattern, html))
                         if h.lower() not in skip][:5]
                if found:
                    socials[platform] = found

            result["extracted"] = {
                "emails": emails, "phones": phones,
                "links": links, "socials": socials,
                "link_count": len(links),
            }
        except Exception as ex:
            result["extracted"] = {"error": str(ex)[:100]}


        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── FLIGHT DATA PROXY ────────────────────────────────────────────────────────
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

_flight_cache = {"data": None, "ts": 0}
FLIGHT_CACHE_TTL = 12

def _get(url, timeout=10):
    hdrs = {"User-Agent": "IntelDesk/1.0", "Accept": "application/json"}
    r = requests.get(url, timeout=timeout, headers=hdrs)
    r.raise_for_status()
    return r.json()

def _norm(a, src):
    icao = (a.get("hex") or "").lower().strip()
    if not icao: return None
    try:
        lat = float(a.get("lat") or 0)
        lon = float(a.get("lon") or 0)
    except: return None
    if lat == 0 and lon == 0: return None
    alt_raw = a.get("alt_baro") or a.get("alt_geom")
    alt_ft  = 0 if alt_raw == "ground" else (round(float(alt_raw)) if alt_raw else None)
    spd = a.get("gs")
    return {
        "icao": icao,
        "cs":   (a.get("flight") or "").strip(),
        "reg":  a.get("r") or "",
        "type": a.get("t") or "",
        "country": a.get("country") or "",
        "lat":  round(lat, 4), "lon": round(lon, 4),
        "alt":  alt_ft,
        "gnd":  alt_raw == "ground",
        "spd":  round(float(spd)) if spd else None,
        "hdg":  round(float(a.get("track") or 0)),
        "vrt":  round(float(a.get("baro_rate") or 0)),
        "sq":   str(a.get("squawk") or ""),
        "src":  src,
    }

@app.route("/flights", methods=["GET","OPTIONS"])
@corsify
def flights_proxy():
    """Fetch live ADS-B from adsb.lol (global) + adsb.fi (regional grids)."""
    global _flight_cache
    now = _time.time()
    if _flight_cache["data"] and (now - _flight_cache["ts"]) < FLIGHT_CACHE_TTL:
        return jsonify(_flight_cache["data"])

    merged = {}
    source_counts = {}

    # ── adsb.lol global endpoint ─────────────────────────────────────────────
    # Uses ADSBExchange-compatible API — no AWS block, true global
    lol_urls = [
        "https://api.adsb.lol/v2/lat/0/lon/0/dist/99999",
        "https://api.adsb.lol/v2/all",
    ]
    for url in lol_urls:
        try:
            d = _get(url, timeout=10)
            aircraft = d.get("ac") or d.get("aircraft") or []
            if aircraft:
                for a in aircraft:
                    ac = _norm(a, "adsblo")
                    if ac and ac["icao"] not in merged:
                        merged[ac["icao"]] = ac
                source_counts["adsblo"] = len([v for v in merged.values() if v["src"]=="adsblo"])
                log.info(f"adsb.lol ({url}): {source_counts.get('adsblo',0)} aircraft")
                break
        except Exception as e:
            log.warning(f"adsb.lol {url}: {e}")

    # ── adsb.fi regional grid — 8 regions covering the globe ────────────────
    # Each query covers 250nm radius; 8 points cover most populated airspace
    regions = [
        (51, 10),   # Europe
        (40, -95),  # North America
        (-15, -50), # South America
        (20, 80),   # South Asia
        (35, 115),  # East Asia
        (-25, 135), # Australia
        (20, 40),   # Middle East / Africa
        (60, 30),   # Russia / North
    ]

    def fetch_adsbfi(lat, lon):
        url = f"https://opendata.adsb.fi/api/v2/lat/{lat}/lon/{lon}/dist/250"
        try:
            d = _get(url, timeout=8)
            return d.get("ac") or []
        except Exception as e:
            log.warning(f"adsb.fi ({lat},{lon}): {e}")
            return []

    fi_count = 0
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(fetch_adsbfi, lat, lon): (lat,lon) for lat,lon in regions}
        for future in _as_completed(futures, timeout=12):
            try:
                aircraft = future.result()
                for a in aircraft:
                    ac = _norm(a, "adsbfi")
                    if ac and ac["icao"] not in merged:
                        merged[ac["icao"]] = ac
                        fi_count += 1
            except: pass

    if fi_count:
        source_counts["adsbfi"] = fi_count
        log.info(f"adsb.fi regions: {fi_count} additional aircraft")

    aircraft_list = list(merged.values())
    result = {
        "count":    len(aircraft_list),
        "sources":  source_counts,
        "ts":       int(now),
        "aircraft": aircraft_list,
    }
    _flight_cache["data"] = result
    _flight_cache["ts"]   = now
    log.info(f"/flights total: {len(aircraft_list)} from {source_counts}")
    return jsonify(result)




# ── CLIENT-SIDE API PROXIES ────────────────────────────────────────────────────
# These keep API keys server-side so the CTI dashboard works for all users
# without them needing their own keys.

OTX_KEY       = os.environ.get("OTX_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
IPINFO_KEY    = os.environ.get("IPINFO_KEY", "")

@app.route("/proxy/otx/pulses", methods=["GET","OPTIONS"])
@corsify
def proxy_otx_pulses():
    """Proxy AlienVault OTX subscribed pulses — keeps API key server-side."""
    if not OTX_KEY:
        return jsonify({"error": "OTX_KEY not configured on server"}), 503
    try:
        since = request.args.get("since", "")
        limit = request.args.get("limit", "30")
        url   = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={limit}"
        if since:
            url += f"&modified_since={since}"
        r = requests.get(url, headers={"X-OTX-API-KEY": OTX_KEY}, timeout=15)
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/proxy/otx/indicators/<pulse_id>", methods=["GET","OPTIONS"])
@corsify
def proxy_otx_indicators(pulse_id):
    """Proxy OTX pulse indicators."""
    if not OTX_KEY:
        return jsonify({"error": "OTX_KEY not configured"}), 503
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators?limit=50",
            headers={"X-OTX-API-KEY": OTX_KEY}, timeout=15
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/proxy/abuseipdb", methods=["GET","OPTIONS"])
@corsify
def proxy_abuseipdb():
    """Proxy AbuseIPDB IP reputation check — keeps API key server-side."""
    if not ABUSEIPDB_KEY:
        return jsonify({"error": "ABUSEIPDB_KEY not configured on server"}), 503
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "ip parameter required"}), 400
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/proxy/ipinfo/<ip>", methods=["GET","OPTIONS"])
@corsify
def proxy_ipinfo(ip):
    """Proxy IPInfo geolocation — keeps API key server-side."""
    if not IPINFO_KEY:
        return jsonify({"error": "IPINFO_KEY not configured on server"}), 503
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json?token={IPINFO_KEY}",
            timeout=10
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/proxy/urlhaus", methods=["POST","OPTIONS"])
@corsify
def proxy_urlhaus():
    """Proxy URLhaus malware feed — handles CORS for browser clients."""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/30/",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data="limit=30",
            timeout=15
        )
        return jsonify(r.json()), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/debug-deepfake", methods=["GET","OPTIONS"])
@corsify
def debug_deepfake():
    """Test Hive and HuggingFace connectivity without needing an image."""
    out = {
        "hive_key_id":    HIVE_KEY_ID[:6] + "..." if HIVE_KEY_ID else "NOT SET",
        "hive_secret":    HIVE_SECRET[:6] + "..." if HIVE_SECRET else "NOT SET",
        "hf_token":       HF_TOKEN[:8]    + "..." if HF_TOKEN    else "NOT SET",
        "hive_test":      None,
        "hf_test":        None,
    }

    # Use a real small JPEG from a public URL for testing
    try:
        _test_resp = requests.get(
            "https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PNG_transparency_demonstration_1.png/120px-PNG_transparency_demonstration_1.png",
            timeout=5
        )
        tiny_jpg = _test_resp.content
    except Exception:
        import base64 as _b64debug
        # Fallback: minimal 8x8 JPEG
        tiny_jpg = _b64debug.b64decode(
            "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDB"
            "kSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAAR"
            "CAAIAAgDASIAAhEBAxEB/8QAFgABAQEAAAAAAAAAAAAAAAAABgUE/8QAIRAAAQME"
            "AgMAAAAAAAAAAAAAAQIDBAAFERIhMUH/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QA"
            "FBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8Amk2Ta7TmMpIkSmS2z0sQ"
            "60A5E5KznGefvQvSdOt59MiPusJU84kqUokk5Jz3oopJHSP/2Q=="
        )

    try:
        # Test V3 endpoint with Bearer secret key
        endpoints = [
            ("V3_bearer_secret_image",
             "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection",
             "Bearer " + HIVE_SECRET, "image"),
            ("V3_bearer_secret_media",
             "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection",
             "Bearer " + HIVE_SECRET, "media"),
            ("V2_token_secret_media",
             "https://api.thehive.ai/api/v2/task/sync",
             "Token " + HIVE_SECRET, "media"),
        ]
        hive_results = {}
        for item in endpoints:
            name, url, auth, field = item[0], item[1], item[2], item[3]
            r = requests.post(
                url,
                headers={"Authorization": auth},
                files={field: ("test.jpg", tiny_jpg, "image/jpeg")},
                timeout=10,
            )
            hive_results[name] = {"status": r.status_code, "body": r.text[:200]}
            if r.status_code == 200:
                break
        out["hive_test"] = hive_results
    except Exception as e:
        out["hive_test"] = {"error": str(e)}

    # Test HuggingFace
    try:
        r2 = requests.post(
            "https://api-inference.huggingface.co/models/umm-maybe/AI-image-detector",
            headers={"Authorization": f"Bearer {HF_TOKEN}"},
            data=tiny_jpg,
            timeout=15,
        )
        out["hf_test"] = {
            "status": r2.status_code,
            "body_preview": r2.text[:200],
        }
    except Exception as e:
        out["hf_test"] = {"error": str(e)}

    return jsonify(out)



@app.route("/debug-hive", methods=["GET","OPTIONS"])
@corsify
def debug_hive():
    """Test Hive with a real image URL to see exact response structure."""
    import base64 as _b64dh

    # Fetch a known real image
    try:
        test_img = requests.get(
            "https://upload.wikimedia.org/wikipedia/commons/thumb/3/3a/Cat03.jpg/320px-Cat03.jpg",
            timeout=10
        )
        img_bytes = test_img.content
        mime_type = "image/jpeg"
    except Exception as e:
        return jsonify({"error": f"Could not fetch test image: {e}"})

    results = {}

    # Try all approaches and return raw responses
    # Try every possible approach
    import base64 as _b64dh2

    # Approach 1: V3 with URL (avoids file encoding issues entirely)
    try:
        r = requests.post(
            "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection",
            headers={"Authorization": f"Bearer {HIVE_SECRET}", "Content-Type": "application/json"},
            json={"url": "https://upload.wikimedia.org/wikipedia/commons/thumb/3/3a/Cat03.jpg/320px-Cat03.jpg"},
            timeout=20,
        )
        try: body = r.json()
        except: body = r.text[:300]
        results["V3_url_json"] = {"status": r.status_code, "body": body}
    except Exception as e:
        results["V3_url_json"] = {"error": str(e)}

    # Approach 2: V3 multipart with io.BytesIO
    try:
        import io
        r = requests.post(
            "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection",
            headers={"Authorization": f"Bearer {HIVE_SECRET}"},
            files={"media": ("cat.jpg", io.BytesIO(img_bytes), "image/jpeg")},
            timeout=20,
        )
        try: body = r.json()
        except: body = r.text[:300]
        results["V3_bytesio"] = {"status": r.status_code, "body": body}
    except Exception as e:
        results["V3_bytesio"] = {"error": str(e)}

    # Approach 3: V3 with base64 data URI
    try:
        b64 = _b64dh2.b64encode(img_bytes).decode()
        r = requests.post(
            "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection",
            headers={"Authorization": f"Bearer {HIVE_SECRET}", "Content-Type": "application/json"},
            json={"image": f"data:image/jpeg;base64,{b64}"},
            timeout=20,
        )
        try: body = r.json()
        except: body = r.text[:300]
        results["V3_base64_uri"] = {"status": r.status_code, "body": body}
    except Exception as e:
        results["V3_base64_uri"] = {"error": str(e)}

    # Approach 4: V3 raw bytes POST
    try:
        r = requests.post(
            "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection",
            headers={"Authorization": f"Bearer {HIVE_SECRET}", "Content-Type": "image/jpeg"},
            data=img_bytes,
            timeout=20,
        )
        try: body = r.json()
        except: body = r.text[:300]
        results["V3_raw_bytes"] = {"status": r.status_code, "body": body}
    except Exception as e:
        results["V3_raw_bytes"] = {"error": str(e)}

    # Approach 5: V3 with form field named "file"
    try:
        r = requests.post(
            "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection",
            headers={"Authorization": f"Bearer {HIVE_SECRET}"},
            files={"file": ("cat.jpg", img_bytes, "image/jpeg")},
            timeout=20,
        )
        try: body = r.json()
        except: body = r.text[:300]
        results["V3_file_field"] = {"status": r.status_code, "body": body}
    except Exception as e:
        results["V3_file_field"] = {"error": str(e)}

    return jsonify({
        "hive_key_id": HIVE_KEY_ID[:8] + "..." if HIVE_KEY_ID else "NOT SET",
        "hive_secret": HIVE_SECRET[:8] + "..." if HIVE_SECRET else "NOT SET",
        "results": results,
    })



@app.route("/hibp/account/<path:email>", methods=["GET","OPTIONS"])
@corsify
def hibp_account(email):
    """Proxy HIBP breachedaccount endpoint. Requires HIBP_API_KEY env var."""
    if not HIBP_KEY:
        return jsonify({"error": "HIBP_API_KEY not configured — email lookup requires a paid HIBP subscription ($3.50/mo at haveibeenpwned.com/API/Key)"}), 503
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": HIBP_KEY,
                "User-Agent": "IntelDesk/1.0 (https://inteldesk.io)",
            },
            params={"truncateResponse": "false"},
            timeout=15,
        )
        log.info(f"HIBP account {email}: {r.status_code}")
        if r.status_code == 200:
            return Response(r.content, status=200, mimetype="application/json")
        elif r.status_code == 404:
            return jsonify([]), 200  # not found = not pwned = empty array
        elif r.status_code == 401:
            return jsonify({"error": "Invalid HIBP API key"}), 401
        return Response(r.content, status=r.status_code, mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── CLOUDFLARE RADAR PROXY ─────────────────────────────────────────────────────
# Proxies requests to Cloudflare Radar API so the token stays server-side

CF_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"

@app.route("/cf-radar/<path:endpoint>", methods=["GET","OPTIONS"])
@corsify
def cf_radar_proxy(endpoint):
    if not CF_RADAR_TOKEN:
        return jsonify({"error": "CLOUDFLARE_RADAR_TOKEN not configured"}), 503

    # Forward query params
    params = {k: v for k, v in request.args.items()}
    url = f"{CF_RADAR_BASE}/{endpoint}"

    try:
        r = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {CF_RADAR_TOKEN}",
                "Content-Type":  "application/json",
            },
            params=params,
            timeout=20,
        )
        log.info(f"CF Radar {endpoint}: {r.status_code}")
        return Response(r.content, status=r.status_code, mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── HIBP PROXY — HaveIBeenPwned breach list ────────────────────────────────────
@app.route("/hibp/breaches", methods=["GET","OPTIONS"])
@corsify
def hibp_breaches():
    """Proxy HIBP /breaches endpoint to avoid CORS + user-agent restrictions."""
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={
                "User-Agent": "IntelDesk/1.0 (https://inteldesk.io; investigative tools)",
                "Accept": "application/json",
            },
            timeout=20,
        )
        log.info(f"HIBP breaches: {r.status_code}, {len(r.content)} bytes")
        if r.status_code == 200:
            return Response(r.content, status=200, mimetype="application/json",
                headers={"X-Total-Breaches": str(len(r.json()))})
        return Response(r.content, status=r.status_code, mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── REVERSE IMAGE SEARCH PROXIES ──────────────────────────────────────────────

@app.route("/image-search/saucenao", methods=["POST","OPTIONS"])
@corsify
def saucenao_search():
    """
    Reverse image search via SauceNAO.
    Accepts file upload (multipart) or JSON {"url": "..."}.
    Requires SAUCENAO_API_KEY env var (free at saucenao.com).
    If Render's IP is blocked by SauceNAO's WAF, set IMGUR_CLIENT_ID
    as a fallback relay — image is uploaded to Imgur first to get a CDN URL.
    """
    if not SAUCENAO_KEY:
        return jsonify({"error": "SAUCENAO_API_KEY not configured", "no_key": True}), 503

    if "image" not in request.files and not request.json:
        return jsonify({"error": "No image provided"}), 400

    try:
        img_url   = None
        img_bytes = None
        img_type  = "image/jpeg"

        if "image" in request.files:
            img_file  = request.files["image"]
            img_bytes = img_file.read()
            img_type  = img_file.content_type or "image/jpeg"

            # If IMGUR_CLIENT_ID is set, use Imgur as relay to get a CDN URL
            # (bypasses SauceNAO WAF that blocks cloud server IPs)
            if IMGUR_CLIENT_ID:
                imgur_r = requests.post(
                    "https://api.imgur.com/3/image",
                    headers={
                        "Authorization": f"Client-ID {IMGUR_CLIENT_ID}",
                        "User-Agent": "IntelDesk/1.0 (https://inteldesk.io)",
                    },
                    files={"image": ("image.jpg", img_bytes, img_type)},
                    timeout=20,
                )
                log.info(f"Imgur relay: {imgur_r.status_code}")
                if imgur_r.ok:
                    img_url = imgur_r.json()["data"]["link"]
                    log.info(f"Imgur URL: {img_url}")
                # If Imgur fails, fall through to direct file upload
        else:
            img_url = request.json.get("url", "").strip()
            if not img_url:
                return jsonify({"error": "No URL provided"}), 400

        # Build SauceNAO request — prefer URL, fall back to file upload
        sn_data = {
            "output_type": 2,
            "numres": 8,
            "db": 999,
            "api_key": SAUCENAO_KEY,
        }
        sn_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        if img_url:
            sn_data["url"] = img_url
            sn_r = requests.post(
                "https://saucenao.com/search.php",
                data=sn_data,
                headers=sn_headers,
                timeout=25,
            )
        else:
            # Direct file upload — works unless Render IP is blocked
            sn_r = requests.post(
                "https://saucenao.com/search.php",
                data=sn_data,
                files={"file": ("image.jpg", img_bytes, img_type)},
                headers=sn_headers,
                timeout=25,
            )

        log.info(f"SauceNAO: {sn_r.status_code}, {len(sn_r.content)} bytes")

        if sn_r.status_code == 200:
            result = sn_r.json()
            if img_url:
                result["_relay_url"] = img_url
            return jsonify(result)
        if sn_r.status_code == 403:
            # IP blocked — tell client to retry with Imgur relay hint
            return jsonify({
                "error": "SauceNAO blocked request (403) — add IMGUR_CLIENT_ID to Render env to enable relay",
                "blocked": True
            }), 403
        if sn_r.status_code == 429:
            return jsonify({"error": "SauceNAO rate limit reached (200/day). Try again later."}), 429
        return jsonify({"error": f"SauceNAO HTTP {sn_r.status_code}"}), sn_r.status_code

    except Exception as e:
        log.error(f"SauceNAO error: {e}")
        return jsonify({"error": str(e)}), 502


@app.route("/image-search/iqdb", methods=["POST","OPTIONS"])
@corsify
def iqdb_search():
    """Proxy IQDB reverse image search — best for anime/illustration."""
    if "image" not in request.files:
        return jsonify({"error": "No image provided"}), 400
    try:
        img_file  = request.files["image"]
        img_bytes = img_file.read()
        r = requests.post(
            "https://iqdb.org/",
            files={"file": ("image.jpg", img_bytes, img_file.content_type or "image/jpeg")},
            data={"service[]": ["1","2","3","4","5","6","11","13"]},
            timeout=20,
        )
        log.info(f"IQDB: {r.status_code}")
        # IQDB returns HTML — parse it server-side
        if r.status_code == 200:
            from html.parser import HTMLParser
            class IQDBParser(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.results = []
                    self.current = {}
                    self.in_pages = False
                    self.in_result = False
                def handle_starttag(self, tag, attrs):
                    attrs = dict(attrs)
                    if tag == "div" and "pages" in attrs.get("id",""):
                        self.in_pages = True
                    if self.in_pages and tag == "div" and "result" in attrs.get("class",""):
                        self.in_result = True
                        self.current = {}
                    if self.in_result and tag == "img":
                        src = attrs.get("src","")
                        if src and not src.startswith("//iqdb"):
                            self.current["thumbnail"] = "https:" + src if src.startswith("//") else src
                        alt = attrs.get("alt","")
                        if alt: self.current["title"] = alt
                    if self.in_result and tag == "a":
                        href = attrs.get("href","")
                        if href and href.startswith("//"):
                            self.current["url"] = "https:" + href
                def handle_endtag(self, tag):
                    if tag == "div" and self.in_result:
                        if self.current.get("url"):
                            self.results.append(self.current)
                        self.current = {}
                        self.in_result = False

            parser = IQDBParser()
            parser.feed(r.text)
            return jsonify({"results": parser.results[:8]})
        return jsonify({"error": f"IQDB HTTP {r.status_code}"}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── COMPANIES HOUSE PROXY ──────────────────────────────────────────────────────
CH_KEY = os.environ.get("COMPANIES_HOUSE_KEY", "")

@app.route("/companies-house/search", methods=["GET","OPTIONS"])
@corsify
def companies_house_search():
    """Search UK Companies House.
    Strategy 1: Use API key if COMPANIES_HOUSE_KEY is set (structured JSON).
    Strategy 2: Scrape the public website search (no key needed, always works).
    """
    q = request.args.get("q","").strip()
    if not q:
        return jsonify({"error": "q parameter required"}), 400

    # ── Strategy 1: API key (if configured) ──────────────────────────────────
    if CH_KEY:
        try:
            import base64
            auth = base64.b64encode(f"{CH_KEY}:".encode()).decode()
            r = requests.get(
                "https://api.company-information.service.gov.uk/search/companies",
                params={"q": q, "items_per_page": 10},
                headers={"Accept": "application/json", "Authorization": f"Basic {auth}"},
                timeout=10,
            )
            if r.status_code == 200:
                return Response(r.content, status=200, mimetype="application/json")
            log.warning(f"CH API key failed ({r.status_code}), falling back to scrape")
        except Exception as e:
            log.warning(f"CH API exception: {e}, falling back to scrape")

    # ── Strategy 2: Scrape public website (no key needed) ────────────────────
    try:
        from html.parser import HTMLParser

        r = requests.get(
            "https://find-and-update.company-information.service.gov.uk/search",
            params={"q": q},
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; IntelDesk/1.0; +https://inteldesk.io)",
                "Accept": "text/html,application/xhtml+xml",
            },
            timeout=15,
        )
        log.info(f"CH scrape: {r.status_code}")
        if r.status_code != 200:
            return jsonify({"error": f"Companies House HTTP {r.status_code}"}), r.status_code

        # Parse search results from HTML
        import re as _re
        items = []

        # Find all company result blocks
        # Each result has a link like /company/XXXXXXXX
        company_blocks = _re.findall(
            r'<li[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)</li>',
            r.text, _re.DOTALL
        )

        # Fallback: find all company links directly
        if not company_blocks:
            # Match company links and names from the search results page
            matches = _re.findall(
                r'href="/company/([A-Z0-9]+)"[^>]*>\s*<span[^>]*>([^<]+)</span>',
                r.text
            )
            for number, name in matches[:10]:
                items.append({
                    "company_number": number,
                    "title": name.strip(),
                    "company_status": "",
                    "company_type": "",
                    "date_of_creation": "",
                    "registered_office_address": {},
                    "links": {"self": f"/company/{number}"}
                })
        else:
            for block in company_blocks[:10]:
                number_m = _re.search(r'/company/([A-Z0-9]+)', block)
                name_m   = _re.search(r'<span[^>]*class="[^"]*name[^"]*"[^>]*>([^<]+)</span>', block)
                status_m = _re.search(r'<strong[^>]*>([^<]*(?:Active|Dissolved|Liquidation|Struck off)[^<]*)</strong>', block, _re.I)
                type_m   = _re.search(r'Company type[^<]*</[^>]+>\s*([^<]+)', block)
                date_m   = _re.search(r'Incorporated on[^<]*</[^>]+>\s*([^<]+)', block)
                addr_m   = _re.search(r'Registered office address[^<]*</[^>]+>\s*<[^>]+>\s*([^<]+)', block)

                if not number_m:
                    continue
                items.append({
                    "company_number": number_m.group(1),
                    "title": (name_m.group(1) if name_m else "Unknown").strip(),
                    "company_status": (status_m.group(1) if status_m else "").strip(),
                    "company_type": (type_m.group(1) if type_m else "").strip(),
                    "date_of_creation": (date_m.group(1) if date_m else "").strip(),
                    "registered_office_address": {
                        "address_line_1": (addr_m.group(1) if addr_m else "").strip()
                    },
                    "links": {"self": f"/company/{number_m.group(1)}"}
                })

        # If scraping got nothing, return a useful fallback with the search URL
        if not items:
            return jsonify({
                "items": [],
                "scrape_url": f"https://find-and-update.company-information.service.gov.uk/search?q={q}",
                "message": "Could not parse results — open Companies House directly"
            })

        return jsonify({"items": items, "total_results": len(items)})

    except Exception as e:
        log.error(f"CH scrape error: {e}")
        return jsonify({"error": str(e)}), 502


@app.route("/icij/search", methods=["GET","OPTIONS"])
@corsify
def icij_search():
    """Proxy ICIJ Offshore Leaks reconciliation API — free, no key."""
    q = request.args.get("q","").strip()
    if not q:
        return jsonify({"error": "q parameter required"}), 400
    try:
        r = requests.post(
            "https://offshoreleaks.icij.org/api/v1/reconcile",
            json={"query": q, "limit": 15},
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=10,
        )
        log.info(f"ICIJ: {r.status_code}")
        if r.status_code == 200:
            return Response(r.content, status=200, mimetype="application/json")
        return jsonify({"error": f"ICIJ HTTP {r.status_code}"}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ── SUBDOMAIN DISCOVERY — crt.sh Certificate Transparency ─────────────────────
@app.route("/crtsh", methods=["GET","OPTIONS"])
@corsify
def crtsh_search():
    """Query crt.sh CT logs to enumerate subdomains. Free, no key."""
    domain = request.args.get("domain","").strip().lower()
    if not domain:
        return jsonify({"error": "domain parameter required"}), 400
    # Strip protocol and path
    domain = domain.replace("https://","").replace("http://","").split("/")[0]
    try:
        r = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": "Mozilla/5.0 (compatible; IntelDesk/1.0; +https://inteldesk.io)"},
            timeout=20,
        )
        log.info(f"crt.sh {domain}: {r.status_code}, {len(r.content)} bytes")
        if r.status_code != 200:
            return jsonify({"error": f"crt.sh HTTP {r.status_code}"}), r.status_code

        # Parse — deduplicate and clean
        entries = r.json()
        seen = set()
        subdomains = []
        for entry in entries:
            # name_value can contain multiple names separated by newlines
            names = entry.get("name_value","").split("\n")
            for name in names:
                name = name.strip().lower()
                if not name or name in seen:
                    continue
                # Only include subdomains of the target domain
                if name == domain or name.endswith("." + domain):
                    seen.add(name)
                    subdomains.append(name)

        # Sort: exact match first, then alphabetically
        subdomains.sort(key=lambda s: (s == domain, s))

        return jsonify({
            "domain": domain,
            "count": len(subdomains),
            "subdomains": subdomains,
        })
    except Exception as e:
        log.error(f"crt.sh error: {e}")
        return jsonify({"error": str(e)}), 502


# ── SEC EDGAR — US Company Search (no key needed) ─────────────────────────────
@app.route("/sec/search", methods=["GET","OPTIONS"])
@corsify
def sec_search():
    """Search SEC EDGAR for US public companies. No API key required."""
    q = request.args.get("q","").strip()
    if not q:
        return jsonify({"error": "q parameter required"}), 400
    try:
        # EDGAR full-text search API — free, no key, covers 800k+ filers
        r = requests.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={
                "q": f'"{q}"',
                "dateRange": "custom",
                "startdt": "2020-01-01",
                "forms": "10-K,10-Q,8-K",
                "hits.hits.total.value": 10,
                "_source": "period_of_report,entity_name,file_num,period_of_report,biz_location,inc_states",
            },
            headers={"User-Agent": "IntelDesk/1.0 (https://inteldesk.io; contact@inteldesk.io)"},
            timeout=10,
        )
        # Also search company names via EDGAR company search
        r2 = requests.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={
                "q": q,
                "entity": q,
                "hits.hits._source": "period_of_report,entity_name,file_num",
                "hits.hits.total.value": 10,
            },
            headers={"User-Agent": "IntelDesk/1.0 (https://inteldesk.io; contact@inteldesk.io)"},
            timeout=10,
        )

        # Better: use the EDGAR company concept API to search by name
        r3 = requests.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": q, "dateRange": "custom", "startdt": "2023-01-01"},
            headers={"User-Agent": "IntelDesk/1.0 (https://inteldesk.io; contact@inteldesk.io)"},
            timeout=10,
        )

        # Use the company search endpoint specifically
        r4 = requests.get(
            "https://www.sec.gov/cgi-bin/browse-edgar",
            params={
                "company": q,
                "CIK": "",
                "type": "10-K",
                "dateb": "",
                "owner": "include",
                "count": "10",
                "search_text": "",
                "action": "getcompany",
                "output": "atom",
            },
            headers={"User-Agent": "IntelDesk/1.0 (https://inteldesk.io; contact@inteldesk.io)"},
            timeout=10,
        )

        log.info(f"SEC EDGAR company search '{q}': {r4.status_code}")

        # Parse Atom feed
        import xml.etree.ElementTree as ET
        companies = []
        if r4.status_code == 200:
            try:
                ns = {"atom": "http://www.w3.org/2005/Atom"}
                root = ET.fromstring(r4.text)
                for entry in root.findall("atom:entry", ns)[:10]:
                    name_el    = entry.find("atom:company-info/atom:conformed-name", ns) or entry.find(".//conformed-name")
                    cik_el     = entry.find("atom:company-info/atom:cik", ns) or entry.find(".//CIK")
                    state_el   = entry.find("atom:company-info/atom:state-of-incorporation", ns) or entry.find(".//state-of-incorporation")
                    sic_el     = entry.find("atom:company-info/atom:assigned-sic-desc", ns) or entry.find(".//assigned-sic-desc")
                    loc_el     = entry.find("atom:company-info/atom:business-address/atom:state", ns) or entry.find(".//business-address/state")

                    # Fallback: parse from entry content directly
                    content_el = entry.find("atom:content", ns)
                    content    = content_el.text if content_el is not None else ""

                    # Try to get name from title
                    title_el = entry.find("atom:title", ns)
                    name = (name_el.text if name_el is not None else
                            title_el.text if title_el is not None else "Unknown")

                    cik = cik_el.text.strip().lstrip("0") if cik_el is not None else ""
                    companies.append({
                        "name":           name.strip(),
                        "cik":            cik,
                        "state":          state_el.text.strip() if state_el is not None else "",
                        "sic_description":sic_el.text.strip() if sic_el is not None else "",
                        "location":       loc_el.text.strip() if loc_el is not None else "",
                        "edgar_url":      f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&type=10-K&dateb=&owner=include&count=10" if cik else "",
                    })
            except Exception as parse_err:
                log.warning(f"EDGAR XML parse error: {parse_err}")

        # If XML parsing got nothing, try the JSON-based EDGAR company search
        if not companies:
            r5 = requests.get(
                "https://efts.sec.gov/LATEST/search-index",
                params={"q": q, "dateRange": "custom", "startdt": "2020-01-01",
                        "hits.hits.total.value": 10},
                headers={"User-Agent": "IntelDesk/1.0 (https://inteldesk.io)"},
                timeout=10,
            )
            if r5.status_code == 200:
                data = r5.json()
                seen_ciks = set()
                for hit in (data.get("hits",{}).get("hits",[]) or [])[:10]:
                    src = hit.get("_source", {})
                    cik = str(src.get("entity_id","")).lstrip("0")
                    if cik in seen_ciks: continue
                    seen_ciks.add(cik)
                    companies.append({
                        "name":            src.get("display_names", [src.get("entity_name","")])[0] if src.get("display_names") else src.get("entity_name",""),
                        "cik":             cik,
                        "state":           src.get("inc_states",""),
                        "sic_description": src.get("category",""),
                        "location":        src.get("biz_location",""),
                        "edgar_url":       f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&type=10-K" if cik else "",
                        "form_type":       src.get("form_type",""),
                        "filed_at":        src.get("period_of_report",""),
                    })

        return jsonify({"companies": companies, "total": len(companies)})

    except Exception as e:
        log.error(f"SEC search error: {e}")
        return jsonify({"error": str(e)}), 502


# ── CRYPTO ADDRESS LOOKUP ──────────────────────────────────────────────────────
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")

@app.route("/crypto/btc/<address>", methods=["GET","OPTIONS"])
@corsify
def btc_lookup(address):
    """Bitcoin address lookup via blockchain.info — free, no key."""
    address = address.strip()
    if not address:
        return jsonify({"error": "address required"}), 400
    try:
        r = requests.get(
            f"https://blockchain.info/rawaddr/{address}",
            params={"limit": 20},
            headers={"User-Agent": "IntelDesk/1.0 (https://inteldesk.io)"},
            timeout=15,
        )
        log.info(f"BTC lookup {address}: {r.status_code}")
        if r.status_code == 200:
            return Response(r.content, status=200, mimetype="application/json")
        if r.status_code == 404:
            return jsonify({"error": "Address not found or has no transactions"}), 404
        return jsonify({"error": f"blockchain.info HTTP {r.status_code}"}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/crypto/eth/<address>", methods=["GET","OPTIONS"])
@corsify
def eth_lookup(address):
    """Ethereum address lookup via Etherscan — requires ETHERSCAN_API_KEY."""
    address = address.strip()
    if not address:
        return jsonify({"error": "address required"}), 400

    if not ETHERSCAN_KEY:
        return jsonify({"error": "ETHERSCAN_API_KEY not configured", "no_key": True}), 503

    try:
        base = "https://api.etherscan.io/api"
        headers = {"User-Agent": "IntelDesk/1.0 (https://inteldesk.io)"}

        # Get balance
        bal_r = requests.get(base, params={
            "module": "account", "action": "balance",
            "address": address, "tag": "latest", "apikey": ETHERSCAN_KEY,
        }, headers=headers, timeout=10)
        bal_data = bal_r.json() if bal_r.ok else {}

        # Get tx count
        cnt_r = requests.get(base, params={
            "module": "proxy", "action": "eth_getTransactionCount",
            "address": address, "tag": "latest", "apikey": ETHERSCAN_KEY,
        }, headers=headers, timeout=10)
        cnt_data = cnt_r.json() if cnt_r.ok else {}

        # Get recent txs
        tx_r = requests.get(base, params={
            "module": "account", "action": "txlist",
            "address": address, "startblock": 0, "endblock": 99999999,
            "page": 1, "offset": 15, "sort": "desc", "apikey": ETHERSCAN_KEY,
        }, headers=headers, timeout=10)
        tx_data = tx_r.json() if tx_r.ok else {}

        # Check if contract
        code_r = requests.get(base, params={
            "module": "proxy", "action": "eth_getCode",
            "address": address, "tag": "latest", "apikey": ETHERSCAN_KEY,
        }, headers=headers, timeout=10)
        code_data = code_r.json() if code_r.ok else {}
        is_contract = code_data.get("result","0x") not in ("0x","0x0","")

        # Token count
        tok_r = requests.get(base, params={
            "module": "account", "action": "tokentx",
            "address": address, "page": 1, "offset": 1, "apikey": ETHERSCAN_KEY,
        }, headers=headers, timeout=10)
        tok_data = tok_r.json() if tok_r.ok else {}

        tx_count_hex = cnt_data.get("result","0x0")
        tx_count = int(tx_count_hex, 16) if tx_count_hex.startswith("0x") else 0

        log.info(f"ETH lookup {address}: bal={bal_data.get('result')}")
        return jsonify({
            "address":     address,
            "balance":     bal_data.get("result","0"),
            "tx_count":    tx_count,
            "is_contract": is_contract,
            "token_count": len(tok_data.get("result") or []),
            "txs":         tx_data.get("result") or [],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502



# ── PERSONA FACE PROXY ────────────────────────────────────────────────────────
@app.route("/persona/face", methods=["GET","OPTIONS"])
@corsify
def persona_face():
    """
    Proxy for this-person-does-not-exist.com face generation.
    Accepts: ?gender=male|female&age=25-35&ethnicity=white|black|asian|indian|middle-eastern|latino
    Returns: JSON with image_url pointing to the face image
    Falls back gracefully if the service is unavailable.
    """
    gender    = request.args.get("gender", "").strip().lower()
    age       = request.args.get("age", "").strip()
    ethnicity = request.args.get("ethnicity", "").strip().lower()

    # Map our params to this-person-does-not-exist.com query format
    # Their API: /new?gender=male&age=19-25&etnic=white
    gender_map = {
        "male": "male", "female": "female",
        "nonbinary": "",  # no nonbinary option — omit for random
    }
    age_map = {
        "18-25":  "19-25",
        "26-35":  "26-35",
        "36-45":  "35-50",
        "46-60":  "35-50",
        "60+":    "50+",
    }
    # Note: their param is "etnic" (sic)
    ethnicity_map = {
        "white":          "white",
        "black":          "black",
        "asian":          "asian",
        "indian":         "indian",
        "middle-eastern": "middle-eastern",
        "latino":         "latino",
    }

    params = {}
    if gender and gender in gender_map and gender_map[gender]:
        params["gender"] = gender_map[gender]
    if age and age in age_map:
        params["age"] = age_map[age]
    if ethnicity and ethnicity in ethnicity_map:
        params["etnic"] = ethnicity_map[ethnicity]

    try:
        r = requests.get(
            "https://this-person-does-not-exist.com/new",
            params=params,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Referer": "https://this-person-does-not-exist.com/en",
                "Accept": "application/json, text/plain, */*",
            },
            timeout=12,
        )
        log.info(f"TPDNE face: {r.status_code} params={params}")

        if r.status_code == 200:
            data = r.json()
            # Response is typically: {"src": "/img/avatar-genXXX.jpg", "name": "..."}
            src = data.get("src", "")
            if src:
                full_url = f"https://this-person-does-not-exist.com{src}"
                return jsonify({
                    "image_url": full_url,
                    "src": src,
                    "source": "this-person-does-not-exist.com",
                })
        return jsonify({"error": f"Face service HTTP {r.status_code}"}), r.status_code

    except Exception as e:
        log.error(f"Face proxy error: {e}")
        return jsonify({"error": str(e)}), 502

# ── AIS STREAM — vessel positions cache ───────────────────────────────────────
import threading
import json
import time

AIS_KEY = os.environ.get("AISSTREAM_KEY", "")
_ais_vessels = {}   # mmsi -> vessel dict
_ais_lock    = threading.Lock()
_ais_running = False

def _ais_worker():
    """Background thread: connect to AISstream WebSocket, fill vessel cache."""
    global _ais_running
    try:
        import websocket as ws_lib
    except ImportError:
        log.warning("websocket-client not installed — AIS worker disabled")
        _ais_running = False
        return

    _ais_running = True
    log.info("AIS worker starting...")

    def on_message(ws, raw):
        try:
            msg  = json.loads(raw)
            mtype = msg.get("MessageType","")
            meta  = msg.get("Metadata", {})
            lat   = meta.get("latitude") or meta.get("Latitude")
            lon   = meta.get("longitude") or meta.get("Longitude")
            mmsi  = str(meta.get("MMSI") or meta.get("mmsi") or "")
            if not mmsi or lat is None or lon is None:
                return
            vessel = _ais_vessels.get(mmsi, {"mmsi": mmsi})
            vessel["lat"]     = lat
            vessel["lon"]     = lon
            vessel["ts"]      = int(time.time())
            vessel["name"]    = meta.get("ShipName") or vessel.get("name","")
            if mtype == "PositionReport":
                pr = msg.get("Message",{}).get("PositionReport",{})
                vessel["heading"] = pr.get("TrueHeading") or pr.get("Cog", 0)
                vessel["speed"]   = pr.get("Sog", 0)
                vessel["status"]  = pr.get("NavigationalStatus", 0)
            elif mtype == "ShipStaticData":
                sd = msg.get("Message",{}).get("ShipStaticData",{})
                vessel["name"]      = sd.get("Name","").strip() or vessel.get("name","")
                vessel["callsign"]  = sd.get("CallSign","").strip()
                vessel["ship_type"] = sd.get("Type", 0)
                vessel["imo"]       = sd.get("ImoNumber", "")
                vessel["dest"]      = sd.get("Destination","").strip()
                vessel["draught"]   = sd.get("Draught", 0)
                vessel["dim_a"]     = sd.get("DimensionA", 0)
                vessel["dim_b"]     = sd.get("DimensionB", 0)
                vessel["flag"]      = meta.get("flag", "")
            with _ais_lock:
                _ais_vessels[mmsi] = vessel
        except Exception as e:
            pass

    def on_error(ws, err):
        log.error(f"AIS WS error: {err}")

    def on_close(ws, *args):
        log.info("AIS WS closed — reconnecting in 10s")
        _ais_running = False

    def on_open(ws):
        log.info("AIS WS connected — subscribing world")
        sub = {
            "APIKey": AIS_KEY,
            "BoundingBoxes": [[[-90, -180], [90, 180]]],
            "FilterMessageTypes": ["PositionReport","ShipStaticData"],
        }
        ws.send(json.dumps(sub))

    while True:
        try:
            wsapp = ws_lib.WebSocketApp(
                "wss://stream.aisstream.io/v0/stream",
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )
            wsapp.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as e:
            log.error(f"AIS worker crash: {e}")
        time.sleep(10)

# Start AIS worker thread on import
def _start_ais():
    t = threading.Thread(target=_ais_worker, daemon=True)
    t.start()

try:
    _start_ais()
except Exception as e:
    log.warning(f"Could not start AIS worker: {e}")

@app.route("/ais/vessels", methods=["GET","OPTIONS"])
@corsify
def ais_vessels():
    """Return current vessel snapshot from AIS cache."""
    with _ais_lock:
        vessels = list(_ais_vessels.values())
    # Return only vessels updated in last 10 minutes
    cutoff = time.time() - 600
    fresh  = [v for v in vessels if v.get("ts",0) > cutoff]
    return jsonify({
        "count": len(fresh),
        "ts":    int(time.time()),
        "vessels": fresh,
    })

@app.route("/ais/status", methods=["GET","OPTIONS"])
@corsify
def ais_status():
    return jsonify({
        "running": _ais_running,
        "vessel_count": len(_ais_vessels),
        "ts": int(time.time()),
    })



# ── DEEPFAKE / AI IMAGE DETECTION ────────────────────────────────────────────
import base64 as _b64
import hashlib as _hashlib

HIVE_KEY_ID  = os.environ.get("HIVE_KEY_ID", "")
HIVE_SECRET  = os.environ.get("HIVE_SECRET", "")
HF_TOKEN     = os.environ.get("HF_TOKEN", "")
CF_RADAR_TOKEN = os.environ.get("CLOUDFLARE_RADAR_TOKEN", "")
SAUCENAO_KEY   = os.environ.get("SAUCENAO_API_KEY", "")
IMGUR_CLIENT_ID = os.environ.get("IMGUR_CLIENT_ID", "")
HIBP_KEY       = os.environ.get("HIBP_API_KEY", "")

@app.route("/deepfake/analyze", methods=["POST","OPTIONS"])
@corsify
def deepfake_analyze():
    """
    Multi-signal AI/deepfake image analysis.
    Accepts: multipart/form-data with 'image' file field
    Returns: JSON with hive, huggingface, and metadata signals
    """
    if "image" not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    img_file  = request.files["image"]
    img_bytes = img_file.read()
    mime_type = img_file.content_type or "image/jpeg"
    file_size = len(img_bytes)

    result = {
        "file_size":   file_size,
        "mime_type":   mime_type,
        "hive":        None,
        "huggingface": None,
    }

    # ── Signal 1: AI or Not — free AI image detection ───────────────────────
    # aiornot.com — free tier, no enterprise required, purpose-built for this
    AIORNOT_KEY = os.environ.get("AIORNOT_KEY", "")
    try:
        if AIORNOT_KEY:
            # AI or Not v2 API — multipart file upload
            aon_resp = requests.post(
                "https://api.aiornot.com/v2/image/sync",
                headers={"Authorization": f"Bearer {AIORNOT_KEY}"},
                files={"image": (img_file.filename or "image.jpg", img_bytes, mime_type)},
                timeout=30,
            )
            log.info(f"AI or Not v2: {aon_resp.status_code} — {aon_resp.text[:300]}")
            if aon_resp.status_code == 200:
                aon_data = aon_resp.json()
                log.info(f"AI or Not full: {str(aon_data)[:400]}")
                # v2 response: {report: {ai_generated: {verdict, ai: {confidence}, human: {confidence}}}}
                report   = aon_data.get("report", {})
                ai_gen   = report.get("ai_generated", report)
                verdict  = ai_gen.get("verdict", "")
                ai_info  = ai_gen.get("ai", {})
                ai_conf  = ai_info.get("confidence", 0) if isinstance(ai_info, dict) else float(ai_info or 0)
                deepfake = report.get("deepfake", {})
                df_conf  = deepfake.get("confidence", None) if isinstance(deepfake, dict) else None
                result["hive"] = {
                    "classes": [
                        {"class": "ai_generated",     "score": float(ai_conf)},
                        {"class": "not_ai_generated", "score": 1 - float(ai_conf)},
                    ],
                    "ai_score":       float(ai_conf),
                    "deepfake_score": float(df_conf) if df_conf is not None else None,
                    "verdict":        verdict,
                    "source":         "aiornot.com",
                }
            else:
                result["hive"] = {"error": f"AI or Not HTTP {aon_resp.status_code}", "detail": aon_resp.text[:200]}
        else:
            # No key — fall back to Hive with all format attempts
            import base64 as _b64h
            img_b64  = _b64h.b64encode(img_bytes).decode()
            HIVE_URL = "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection"
            auth_hdr = {"Authorization": f"Bearer {HIVE_SECRET}"}

            for attempt_name, req_kwargs in [
                ("json_url",        {"json": {"url": f"data:{mime_type};base64,{img_b64}"}, "headers": auth_hdr | {"Content-Type": "application/json"}}),
                ("multipart_file",  {"files": {"file":  ("img.jpg", img_bytes, "image/jpeg")}, "headers": auth_hdr}),
                ("multipart_media", {"files": {"media": ("img.jpg", img_bytes, "image/jpeg")}, "headers": auth_hdr}),
            ]:
                r = requests.post(HIVE_URL, timeout=25, **req_kwargs)
                log.info(f"Hive {attempt_name}: {r.status_code} — {r.text[:150]}")
                if r.status_code == 200:
                    hive_json = r.json()
                    def find_cls(obj, d=0):
                        if d > 8: return []
                        if isinstance(obj, list):
                            for i in obj:
                                r2 = find_cls(i, d+1)
                                if r2: return r2
                        elif isinstance(obj, dict):
                            if "classes" in obj and isinstance(obj["classes"], list) and obj["classes"]:
                                return obj["classes"]
                            for v in obj.values():
                                r2 = find_cls(v, d+1)
                                if r2: return r2
                        return []
                    classes    = find_cls(hive_json)
                    ai_cls     = next((x for x in classes if x.get("class","").lower() in ("ai_generated","yes")), None)
                    not_ai_cls = next((x for x in classes if x.get("class","").lower() in ("not_ai_generated","no")), None)
                    df_cls     = next((x for x in classes if "deepfake" in x.get("class","").lower()), None)
                    result["hive"] = {
                        "classes":        classes,
                        "ai_score":       ai_cls["score"] if ai_cls else (1 - not_ai_cls["score"] if not_ai_cls else None),
                        "deepfake_score": df_cls["score"] if df_cls else None,
                        "source":         "hive",
                    }
                    break
            else:
                result["hive"] = {"error": "All Hive approaches returned non-200"}

    except Exception as e:
        result["hive"] = {"error": str(e)[:100]}
        log.error(f"Signal 1 exception: {e}")

    # ── Signal 2: Deepfake score from Signal 1 ────────────────────────────────
    try:
        hive_norm = result.get("hive") or {}
        classes   = hive_norm.get("classes", [])
        df_score  = hive_norm.get("deepfake_score")
        if df_score is not None:
            result["huggingface"] = {"model": "deepfake-detection", "deepfake_score": df_score, "output": classes}
        elif classes:
            result["huggingface"] = {"model": "deepfake-detection", "deepfake_score": 0.0, "note": "No face detected", "output": classes}
        else:
            result["huggingface"] = {"error": "No signal 1 data"}
    except Exception as e:
        result["huggingface"] = {"error": str(e)[:100]}
    return jsonify(result)






# ══════════════════════════════════════════════════════════════════════════════
# URL PREVIEW — Burner Link Previewer endpoint
# Fetches a URL safely server-side and returns parsed page content for preview
# without the user ever visiting the link.
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/url-preview", methods=["GET", "OPTIONS"])
def url_preview():
    """
    Burner Link Previewer endpoint.
    Fetches a URL safely server-side and returns:
      - title, meta description, OG/Twitter tags
      - headings (h1-h3), body text excerpt
      - embedded forms (with password input flagging)
      - outbound external links
      - favicon, screenshot URL (thum.io tall crop)
    User never visits the link directly.
    """
    if request.method == "OPTIONS":
        resp = jsonify({"ok": True})
        resp.headers["Access-Control-Allow-Origin"]  = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    raw_url = (request.args.get("url") or "").strip()
    if not raw_url:
        resp = jsonify({"error": "No URL provided"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(raw_url)
        if not parsed_url.netloc:
            raise ValueError("invalid URL")
    except Exception:
        resp = jsonify({"error": "Invalid URL"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400

    result = {
        "url":           raw_url,
        "final_url":     None,
        "final_domain":  None,
        "status_code":   None,
        "title":         None,
        "description":   None,
        "og":            {},
        "twitter":       {},
        "headings":      [],
        "body_excerpt":  None,
        "forms":         [],
        "outbound_links":[],
        "internal_links_count": 0,
        "external_links_count": 0,
        "language":      None,
        "favicon":       None,
        "screenshot_url": None,
    }

    try:
        import re as _re
        from bs4 import BeautifulSoup
        HEADERS = {
            "User-Agent": "Mozilla/5.0 (compatible; IntelDeskBot/1.0; +https://inteldesk.io)"
        }
        r = requests.get(
            raw_url,
            headers=HEADERS,
            timeout=15,
            allow_redirects=True,
            verify=True,
        )
        result["final_url"]   = r.url
        result["status_code"] = r.status_code
        try:
            result["final_domain"] = urlparse(r.url).netloc
        except Exception:
            result["final_domain"] = parsed_url.netloc

        ct = (r.headers.get("Content-Type") or "").lower()
        if "html" in ct or r.text.strip().startswith("<"):
            soup = BeautifulSoup(r.text, "html.parser")

            # Title
            if soup.title and soup.title.string:
                result["title"] = soup.title.string.strip()[:300]

            # Lang
            html_tag = soup.find("html")
            if html_tag and html_tag.get("lang"):
                result["language"] = html_tag.get("lang")[:20]

            # Meta description
            md = soup.find("meta", attrs={"name": "description"})
            if md and md.get("content"):
                result["description"] = md.get("content").strip()[:500]

            # Open Graph
            for prop in ["og:title", "og:description", "og:image",
                         "og:site_name", "og:type", "og:url"]:
                tag = soup.find("meta", attrs={"property": prop})
                if tag and tag.get("content"):
                    key = prop.split(":", 1)[1]
                    result["og"][key] = tag.get("content").strip()[:500]

            # Twitter card
            for prop in ["twitter:card", "twitter:title",
                         "twitter:description", "twitter:image", "twitter:site"]:
                tag = soup.find("meta", attrs={"name": prop})
                if tag and tag.get("content"):
                    key = prop.split(":", 1)[1]
                    result["twitter"][key] = tag.get("content").strip()[:500]

            # Favicon
            for sel in ["icon", "shortcut icon", "apple-touch-icon"]:
                f_tag = soup.find("link", rel=sel)
                if f_tag and f_tag.get("href"):
                    href = f_tag.get("href").strip()
                    if href.startswith("//"):
                        href = "https:" + href
                    elif href.startswith("/"):
                        href = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                    elif not href.startswith("http"):
                        href = f"{parsed_url.scheme}://{parsed_url.netloc}/{href}"
                    result["favicon"] = href[:400]
                    break

            # Headings (h1-h3)
            for level in [1, 2, 3]:
                for h in soup.find_all(f"h{level}", limit=15):
                    text = h.get_text(" ", strip=True)
                    if text:
                        result["headings"].append({
                            "level": level,
                            "text":  text[:200]
                        })
            result["headings"] = result["headings"][:30]

            # Body text excerpt
            for tag in soup(["script", "style", "noscript", "svg", "nav", "footer"]):
                tag.decompose()
            body_text = soup.get_text(" ", strip=True)
            body_text = _re.sub(r"\s+", " ", body_text)
            result["body_excerpt"] = body_text[:1500] if body_text else None

            # Forms
            for form in soup.find_all("form", limit=10):
                fields = []
                has_pw = False
                for inp in form.find_all(["input", "textarea", "select"], limit=20):
                    ftype = (inp.get("type") or inp.name or "").lower()
                    if ftype == "password":
                        has_pw = True
                    name = inp.get("name") or inp.get("id") or ""
                    placeholder = inp.get("placeholder") or ""
                    fields.append({
                        "name":        str(name)[:80],
                        "type":        ftype[:30],
                        "placeholder": str(placeholder)[:120],
                    })
                action = form.get("action") or "(same page)"
                method = (form.get("method") or "GET").upper()
                if action and action != "(same page)" and not action.startswith("http"):
                    if action.startswith("//"):
                        action = "https:" + action
                    elif action.startswith("/"):
                        action = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
                result["forms"].append({
                    "action":       str(action)[:400],
                    "method":       method,
                    "has_password": has_pw,
                    "fields":       fields,
                })

            # Outbound links
            seen_links = set()
            base_host = (urlparse(r.url).netloc or "").lower().lstrip("www.")
            ext_links = []
            int_count = 0
            for a in soup.find_all("a", href=True, limit=300):
                href = (a.get("href") or "").strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                if href.startswith("//"):
                    href = "https:" + href
                elif href.startswith("/"):
                    href = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                elif not href.startswith("http"):
                    continue
                if href in seen_links:
                    continue
                seen_links.add(href)
                try:
                    link_host = (urlparse(href).netloc or "").lower().lstrip("www.")
                except Exception:
                    continue
                is_external = bool(link_host) and link_host != base_host and not link_host.endswith("." + base_host)
                text = a.get_text(" ", strip=True) or "(no text)"
                text = text[:80]
                if is_external:
                    if len(ext_links) < 50:
                        ext_links.append({
                            "href":        href[:400],
                            "text":        text,
                            "host":        link_host,
                            "is_external": True,
                        })
                else:
                    int_count += 1
            result["outbound_links"]       = ext_links
            result["external_links_count"] = len(ext_links)
            result["internal_links_count"] = int_count
        else:
            result["body_excerpt"] = f"Non-HTML content ({ct or 'unknown'})"

        # Tall thum.io screenshot
        result["screenshot_url"] = (
            f"https://image.thum.io/get/width/1024/crop/2400/noanimate/"
            f"{requests.utils.quote(r.url, safe='')}"
        )

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {str(e)[:200]}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out (15s)"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {str(e)[:200]}"
    except Exception as e:
        result["error"] = f"Fetch error: {str(e)[:200]}"

    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp




# ══════════════════════════════════════════════════════════════════════════════
# HASH LOOKUP TOOL — paste-in routes for app.py
# 
# Layers:
#   1. /hash-lookup       — query abuse.ch sources (MalwareBazaar, URLhaus, ThreatFox)
#   2. /file-analyze      — upload file, hash + static analysis + YARA scan
#   3. /eml-analyze       — upload .eml, extract attachments, analyze each
#   4. /archive-analyze   — upload zip/rar/7z, extract, analyze each member
#
# Dependencies (add to requirements.txt):
#   python-magic==0.4.27
#   oletools==0.60.2
#   pypdf==4.3.1
#   yara-python==4.5.1
#   rarfile==4.2
#   py7zr==0.22.0
#
# System deps (add via Render build script):
#   apt-get install -y libmagic1 libyara9 unrar p7zip-full
#
# YARA rules: clone https://github.com/Yara-Rules/rules to ./yara_rules at build
# ══════════════════════════════════════════════════════════════════════════════

import os as _os
import io as _io
import re as _re
import hashlib as _hashlib
import tempfile as _tempfile
import zipfile as _zipfile
import email as _email
import threading as _threading
import logging as _logging
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor

_log = _logging.getLogger("hash-lookup")

# ── Hash type detection ─────────────────────────────────────────────────
def _detect_hash_type(h):
    h = (h or "").strip().lower()
    if _re.fullmatch(r"[a-f0-9]{32}", h): return "md5"
    if _re.fullmatch(r"[a-f0-9]{40}", h): return "sha1"
    if _re.fullmatch(r"[a-f0-9]{64}", h): return "sha256"
    return None

# ── Threat intel sources (all free, no keys) ────────────────────────────
def _query_malwarebazaar(hash_value):
    """abuse.ch MalwareBazaar — POST API, returns full malware metadata."""
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_value},
            timeout=10,
            headers={"User-Agent": "IntelDesk/1.0"},
        )
        if r.status_code != 200:
            return {"source": "malwarebazaar", "found": False, "status": "http_error"}
        data = r.json()
        if data.get("query_status") != "ok":
            return {"source": "malwarebazaar", "found": False, "status": data.get("query_status","unknown")}
        sample = (data.get("data") or [{}])[0]
        return {
            "source":         "malwarebazaar",
            "found":          True,
            "sha256":         sample.get("sha256_hash"),
            "md5":            sample.get("md5_hash"),
            "sha1":           sample.get("sha1_hash"),
            "file_name":      sample.get("file_name"),
            "file_type":      sample.get("file_type"),
            "file_size":      sample.get("file_size"),
            "signature":      sample.get("signature"),
            "tags":           sample.get("tags") or [],
            "first_seen":     sample.get("first_seen"),
            "last_seen":      sample.get("last_seen"),
            "delivery":       sample.get("delivery_method"),
            "intel":          sample.get("intelligence", {}),
            "vendor_threat":  sample.get("vendor_intel", {}),
            "yara_rules":     [r.get("rule_name") for r in (sample.get("yara_rules") or [])],
            "permalink":      f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash','')}/",
        }
    except Exception as e:
        _log.debug(f"malwarebazaar error: {e}")
        return {"source": "malwarebazaar", "found": False, "status": "error", "error": str(e)[:120]}

def _query_threatfox(hash_value):
    """abuse.ch ThreatFox — IOC database with hash lookups."""
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_hash", "hash": hash_value},
            timeout=10,
            headers={"User-Agent": "IntelDesk/1.0"},
        )
        if r.status_code != 200:
            return {"source": "threatfox", "found": False, "status": "http_error"}
        data = r.json()
        if data.get("query_status") != "ok":
            return {"source": "threatfox", "found": False, "status": data.get("query_status","unknown")}
        iocs = data.get("data") or []
        if not iocs:
            return {"source": "threatfox", "found": False, "status": "no_results"}
        return {
            "source":     "threatfox",
            "found":      True,
            "ioc_count":  len(iocs),
            "malware":    list({i.get("malware_printable") for i in iocs if i.get("malware_printable")}),
            "threat_types": list({i.get("threat_type") for i in iocs if i.get("threat_type")}),
            "confidence": max((i.get("confidence_level", 0) or 0) for i in iocs),
            "first_seen": min((i.get("first_seen", "") or "z") for i in iocs),
            "tags":       list({t for i in iocs for t in (i.get("tags") or []) if t}),
            "permalink":  f"https://threatfox.abuse.ch/browse.php?search=hash%3A{hash_value}",
        }
    except Exception as e:
        _log.debug(f"threatfox error: {e}")
        return {"source": "threatfox", "found": False, "status": "error", "error": str(e)[:120]}

def _query_urlhaus(hash_value):
    """abuse.ch URLhaus — distribution URLs for known payload hashes (sha256/md5)."""
    try:
        # URLhaus accepts either md5 or sha256
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/payload/",
            data={"sha256_hash": hash_value} if len(hash_value)==64 else {"md5_hash": hash_value},
            timeout=10,
            headers={"User-Agent": "IntelDesk/1.0"},
        )
        if r.status_code != 200:
            return {"source": "urlhaus", "found": False, "status": "http_error"}
        data = r.json()
        if data.get("query_status") != "ok":
            return {"source": "urlhaus", "found": False, "status": data.get("query_status","unknown")}
        urls = data.get("urls") or []
        return {
            "source":     "urlhaus",
            "found":      True,
            "url_count":  data.get("url_count", len(urls)),
            "file_size":  data.get("file_size"),
            "file_type":  data.get("file_type"),
            "signature":  data.get("signature"),
            "first_seen": data.get("firstseen"),
            "last_seen":  data.get("lastseen"),
            "urls":       [{
                "url":       u.get("url"),
                "status":    u.get("url_status"),
                "first":     u.get("firstseen"),
                "last":      u.get("lastseen"),
                "tags":      u.get("tags") or [],
            } for u in urls[:25]],
            "permalink":  f"https://urlhaus.abuse.ch/browse.php?search={hash_value}",
        }
    except Exception as e:
        _log.debug(f"urlhaus error: {e}")
        return {"source": "urlhaus", "found": False, "status": "error", "error": str(e)[:120]}

def _query_all_intel(hash_value):
    """Query all three abuse.ch sources in parallel."""
    sources = []
    with _ThreadPoolExecutor(max_workers=3) as ex:
        futures = [
            ex.submit(_query_malwarebazaar, hash_value),
            ex.submit(_query_threatfox,     hash_value),
            ex.submit(_query_urlhaus,       hash_value),
        ]
        for f in futures:
            try:
                sources.append(f.result(timeout=12))
            except Exception as e:
                _log.debug(f"intel future error: {e}")
    return sources

# ── Verdict synthesis ────────────────────────────────────────────────────
def _synthesize_verdict(intel_results):
    """Merge intel sources into a single verdict."""
    found_sources = [r for r in intel_results if r.get("found")]
    if not found_sources:
        return {
            "level":      "clean",
            "label":      "No matches",
            "summary":    "No threat intelligence sources have records of this hash. This does not guarantee the file is safe — only that it has not been observed and reported by these sources.",
            "confidence": "low",
            "sources_hit": 0,
        }
    # Collect malware family names from all sources
    families = set()
    tags = set()
    for r in found_sources:
        if r.get("signature"):
            families.add(r["signature"])
        for m in r.get("malware", []) or []:
            families.add(m)
        for t in r.get("tags", []) or []:
            tags.add(t)
    family_str = ", ".join(sorted(families)) if families else "Unknown family"
    return {
        "level":       "malicious",
        "label":       "Known malware",
        "summary":     f"This hash matches known malware: {family_str}. Found in {len(found_sources)} of {len(intel_results)} threat intelligence sources.",
        "confidence":  "high" if len(found_sources) >= 2 else "medium",
        "sources_hit": len(found_sources),
        "families":    sorted(families),
        "tags":        sorted(tags),
    }

# ── Static file analysis ────────────────────────────────────────────────
def _hash_file_bytes(data):
    return {
        "md5":    _hashlib.md5(data).hexdigest(),
        "sha1":   _hashlib.sha1(data).hexdigest(),
        "sha256": _hashlib.sha256(data).hexdigest(),
        "size":   len(data),
    }

def _detect_file_type(data, claimed_name=""):
    """Detect file type by magic bytes."""
    try:
        import magic as _magic
        mime = _magic.from_buffer(data, mime=True)
        desc = _magic.from_buffer(data, mime=False)
    except Exception:
        # Fallback: header sniff
        mime, desc = "application/octet-stream", "unknown"
        if data.startswith(b"MZ"):                      mime, desc = "application/x-dosexec", "PE executable"
        elif data.startswith(b"\x7fELF"):               mime, desc = "application/x-executable", "ELF binary"
        elif data.startswith(b"%PDF"):                  mime, desc = "application/pdf", "PDF document"
        elif data.startswith(b"PK\x03\x04"):            mime, desc = "application/zip", "ZIP archive"
        elif data.startswith(b"Rar!"):                  mime, desc = "application/x-rar", "RAR archive"
        elif data.startswith(b"7z\xbc\xaf\x27\x1c"):    mime, desc = "application/x-7z-compressed", "7-Zip archive"
        elif data.startswith(b"\xd0\xcf\x11\xe0"):      mime, desc = "application/x-ole-storage", "OLE / Office97 doc"
    # Check claimed extension mismatch
    mismatch = False
    if claimed_name and "." in claimed_name:
        ext = claimed_name.rsplit(".", 1)[-1].lower()
        ext_to_mime = {
            "pdf":  "application/pdf",
            "exe":  "application/x-dosexec",
            "doc":  "application/x-ole-storage",
            "docx": "application/zip",
            "xlsx": "application/zip",
            "zip":  "application/zip",
        }
        expected = ext_to_mime.get(ext)
        if expected and expected not in mime:
            mismatch = True
    return {"mime": mime, "description": desc, "extension_mismatch": mismatch}

def _calculate_entropy(data, sample_size=65536):
    """Shannon entropy. High entropy (>7.0) suggests packed/encrypted/compressed."""
    if not data: return 0.0
    sample = data[:sample_size]
    counts = [0] * 256
    for b in sample: counts[b] += 1
    n = len(sample)
    import math
    entropy = -sum((c/n) * math.log2(c/n) for c in counts if c > 0)
    return round(entropy, 3)

_SUSPICIOUS_STRINGS = [
    # Persistence / execution
    rb"cmd\.exe", rb"powershell\.exe", rb"wscript\.exe", rb"cscript\.exe",
    rb"regsvr32", rb"rundll32", rb"mshta\.exe",
    # Networking
    rb"WSAStartup", rb"InternetOpenUrl", rb"URLDownloadToFile", rb"WinHttpOpen",
    # Process injection
    rb"VirtualAllocEx", rb"WriteProcessMemory", rb"CreateRemoteThread",
    rb"NtUnmapViewOfSection", rb"SetWindowsHookEx",
    # Registry persistence
    rb"\\Run\\", rb"CurrentVersion\\Run", rb"RegSetValue",
    # Anti-analysis
    rb"IsDebuggerPresent", rb"CheckRemoteDebuggerPresent", rb"GetTickCount",
    rb"vmware", rb"virtualbox", rb"sandbox",
    # Crypto / ransomware indicators
    rb"CryptEncrypt", rb"BCryptEncrypt", rb"\.locked", rb"\.encrypted",
    rb"README.*\.txt", rb"DECRYPT",
]

def _extract_strings(data, min_len=6, max_strings=200):
    """Extract printable ASCII and UTF-16 strings."""
    out = set()
    # ASCII
    pattern = b"[\\x20-\\x7e]{%d,}" % min_len
    for m in _re.finditer(pattern, data):
        s = m.group().decode("ascii", errors="ignore")
        out.add(s[:200])
        if len(out) >= max_strings: break
    # UTF-16-LE (very common in Windows binaries)
    if len(out) < max_strings:
        try:
            decoded = data.decode("utf-16-le", errors="ignore")
            for m in _re.finditer(r"[\x20-\x7e]{%d,}" % min_len, decoded):
                out.add(m.group()[:200])
                if len(out) >= max_strings: break
        except Exception: pass
    return list(out)[:max_strings]

def _find_iocs(data):
    """Pull URLs, IPs, emails out of file content."""
    text = data.decode("utf-8", errors="ignore") + "\n" + data.decode("utf-16-le", errors="ignore")
    urls = list({m.group(0) for m in _re.finditer(r"https?://[a-zA-Z0-9\.\-_/?&=%]+", text)})[:50]
    ips  = list({m.group(0) for m in _re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)})[:50]
    # filter obvious non-routable IPs to reduce noise
    ips = [i for i in ips if not (i.startswith(("0.","127.","10.","192.168.","255.")) or i.startswith("169.254."))][:25]
    emails = list({m.group(0) for m in _re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)})[:25]
    return {"urls": urls, "ips": ips, "emails": emails}

def _scan_suspicious_strings(data):
    """Check for known suspicious string patterns."""
    hits = []
    for pattern in _SUSPICIOUS_STRINGS:
        if _re.search(pattern, data, _re.IGNORECASE):
            hits.append(pattern.decode("ascii", errors="replace"))
    return hits

def _analyze_pdf(data):
    """PDF-specific analysis: embedded JS, forms, encryption."""
    info = {"has_javascript": False, "has_forms": False, "is_encrypted": False, "page_count": None, "warnings": []}
    try:
        import pypdf as _pypdf
        reader = _pypdf.PdfReader(_io.BytesIO(data))
        info["is_encrypted"] = reader.is_encrypted
        info["page_count"] = len(reader.pages)
        # JavaScript indicator
        if b"/JS" in data or b"/JavaScript" in data:
            info["has_javascript"] = True
            info["warnings"].append("PDF contains embedded JavaScript")
        # Forms
        if b"/AcroForm" in data:
            info["has_forms"] = True
        # Auto-action triggers
        if b"/OpenAction" in data or b"/AA" in data:
            info["warnings"].append("PDF contains auto-execute action")
        if b"/Launch" in data:
            info["warnings"].append("PDF can launch external programs")
        if b"/EmbeddedFile" in data:
            info["warnings"].append("PDF contains embedded files")
    except Exception as e:
        info["error"] = str(e)[:120]
    return info

def _analyze_office(data):
    """Office doc analysis: VBA macros, embedded objects."""
    info = {"has_macros": False, "macro_count": 0, "warnings": []}
    try:
        from oletools.olevba import VBA_Parser
        vbaparser = VBA_Parser("uploaded", data=data)
        if vbaparser.detect_vba_macros():
            info["has_macros"] = True
            info["warnings"].append("Document contains VBA macros — potential phishing payload")
            macros = list(vbaparser.extract_all_macros())
            info["macro_count"] = len(macros)
            # Pull keywords from macros — autostart triggers, suspicious calls
            try:
                results = vbaparser.analyze_macros()
                kws = set()
                for kw_type, keyword, description in results or []:
                    if kw_type in ("AutoExec", "Suspicious"):
                        kws.add(f"{kw_type}: {keyword}")
                info["macro_keywords"] = sorted(kws)[:20]
            except Exception:
                pass
        vbaparser.close()
    except Exception as e:
        info["error"] = str(e)[:120]
    return info

# ── YARA scanning ────────────────────────────────────────────────────────
_YARA_RULES_CACHE = None
_YARA_LOAD_LOCK = _threading.Lock()

def _load_yara_rules():
    """Load and compile YARA rules at first use. Cached after."""
    global _YARA_RULES_CACHE
    if _YARA_RULES_CACHE is not None:
        return _YARA_RULES_CACHE
    with _YARA_LOAD_LOCK:
        if _YARA_RULES_CACHE is not None:
            return _YARA_RULES_CACHE
        try:
            import yara as _yara
            rules_dir = _os.environ.get("YARA_RULES_DIR", "./yara_rules")
            if not _os.path.isdir(rules_dir):
                _log.warning(f"YARA rules dir not found: {rules_dir}")
                _YARA_RULES_CACHE = False
                return False
            rule_files = {}
            n_loaded = 0
            for root, _, files in _os.walk(rules_dir):
                for fn in files:
                    if fn.endswith((".yar", ".yara")):
                        path = _os.path.join(root, fn)
                        ns = f"r{n_loaded}"
                        rule_files[ns] = path
                        n_loaded += 1
                        if n_loaded >= 800:  # cap to avoid OOM
                            break
                if n_loaded >= 800: break
            _log.info(f"Loading {n_loaded} YARA rule files...")
            _YARA_RULES_CACHE = _yara.compile(filepaths=rule_files)
            _log.info("YARA rules compiled successfully")
            return _YARA_RULES_CACHE
        except Exception as e:
            _log.warning(f"YARA load failed: {e}")
            _YARA_RULES_CACHE = False
            return False

def _yara_scan(data):
    """Run YARA rules against file data. Returns matched rule names + meta."""
    rules = _load_yara_rules()
    if not rules:
        return {"available": False, "reason": "yara unavailable or rules not loaded"}
    try:
        matches = rules.match(data=data, timeout=30)
        result = []
        for m in matches[:30]:
            result.append({
                "rule":      m.rule,
                "namespace": m.namespace,
                "tags":      list(m.tags) if hasattr(m, "tags") else [],
                "meta":      dict(m.meta) if hasattr(m, "meta") else {},
            })
        return {"available": True, "match_count": len(matches), "matches": result}
    except Exception as e:
        return {"available": True, "error": str(e)[:200]}

# ── Full analysis pipeline ──────────────────────────────────────────────
def _analyze_file_data(data, filename=""):
    """Run all layers on file bytes. Returns structured result."""
    result = {"filename": filename}
    hashes = _hash_file_bytes(data)
    result["hashes"] = hashes
    result["file_type"] = _detect_file_type(data, filename)
    result["entropy"] = _calculate_entropy(data)
    result["suspicious_strings"] = _scan_suspicious_strings(data)
    result["iocs"] = _find_iocs(data)
    # Format-specific analysis
    mime = result["file_type"]["mime"]
    if "pdf" in mime:
        result["pdf"] = _analyze_pdf(data)
    if "ole" in mime or "msword" in mime or "officedocument" in mime:
        result["office"] = _analyze_office(data)
    # YARA
    result["yara"] = _yara_scan(data)
    # Threat intel by sha256
    result["intel"] = _query_all_intel(hashes["sha256"])
    result["verdict"] = _synthesize_verdict(result["intel"])
    # Bump verdict if yara/macros/suspicious_strings suggest malicious
    if result["verdict"]["level"] == "clean":
        suspicious_signals = 0
        if result["yara"].get("match_count", 0) > 0: suspicious_signals += 2
        if result.get("office", {}).get("has_macros"): suspicious_signals += 1
        if result.get("pdf", {}).get("has_javascript"): suspicious_signals += 1
        if result["entropy"] > 7.5 and "exec" in mime: suspicious_signals += 1
        if len(result["suspicious_strings"]) >= 5: suspicious_signals += 1
        if suspicious_signals >= 2:
            result["verdict"] = {
                "level":      "suspicious",
                "label":      "Suspicious indicators",
                "summary":    f"This file is not in malware databases but exhibits {suspicious_signals} suspicious indicators (YARA matches, embedded macros/JS, suspicious strings, or high entropy). Manual review recommended.",
                "confidence": "medium",
                "sources_hit": 0,
            }
    return result

# ── Routes ─────────────────────────────────────────────────────────────
@app.route("/hash-lookup", methods=["GET", "OPTIONS"])
def hash_lookup():
    """Look up a single hash across abuse.ch sources."""
    if request.method == "OPTIONS":
        resp = jsonify({"ok": True})
        resp.headers["Access-Control-Allow-Origin"]  = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp
    h = (request.args.get("hash") or "").strip().lower()
    htype = _detect_hash_type(h)
    if not htype:
        resp = jsonify({"error": "Invalid hash. Must be MD5 (32 chars), SHA1 (40), or SHA256 (64) hex."})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400
    intel = _query_all_intel(h)
    verdict = _synthesize_verdict(intel)
    resp = jsonify({
        "hash":     h,
        "type":     htype,
        "intel":    intel,
        "verdict":  verdict,
    })
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/file-analyze", methods=["POST", "OPTIONS"])
def file_analyze():
    """Upload a file (≤10MB) for full multi-layer analysis."""
    if request.method == "OPTIONS":
        resp = jsonify({"ok": True})
        resp.headers["Access-Control-Allow-Origin"]  = "*"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp
    if "file" not in request.files:
        resp = jsonify({"error": "No file uploaded"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400
    f = request.files["file"]
    data = f.read()
    if len(data) > 10 * 1024 * 1024:
        resp = jsonify({"error": "File exceeds 10MB limit"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400
    try:
        result = _analyze_file_data(data, filename=f.filename or "")
    except Exception as e:
        _log.exception("file-analyze failed")
        resp = jsonify({"error": f"Analysis failed: {str(e)[:200]}"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 500
    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/eml-analyze", methods=["POST", "OPTIONS"])
def eml_analyze():
    """Upload .eml — extract every attachment, analyze each."""
    if request.method == "OPTIONS":
        resp = jsonify({"ok": True})
        resp.headers["Access-Control-Allow-Origin"]  = "*"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp
    if "file" not in request.files:
        resp = jsonify({"error": "No .eml file uploaded"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400
    raw = request.files["file"].read()
    if len(raw) > 25 * 1024 * 1024:
        resp = jsonify({"error": ".eml exceeds 25MB limit"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400
    try:
        msg = _email.message_from_bytes(raw)
        meta = {
            "from":    msg.get("From"),
            "to":      msg.get("To"),
            "subject": msg.get("Subject"),
            "date":    msg.get("Date"),
            "message_id": msg.get("Message-ID"),
        }
        attachments = []
        body_text = ""
        for part in msg.walk():
            cd = part.get("Content-Disposition") or ""
            ct = part.get_content_type()
            if "attachment" in cd or part.get_filename():
                try:
                    payload = part.get_payload(decode=True)
                    if payload and len(payload) <= 10 * 1024 * 1024:
                        attachments.append(_analyze_file_data(payload, filename=part.get_filename() or "attachment"))
                    elif payload:
                        attachments.append({"filename": part.get_filename(), "error": "Attachment exceeds 10MB"})
                except Exception as e:
                    attachments.append({"filename": part.get_filename(), "error": str(e)[:120]})
            elif ct in ("text/plain", "text/html") and not body_text:
                try:
                    body_text = (part.get_payload(decode=True) or b"").decode("utf-8", errors="ignore")[:5000]
                except Exception: pass
        # Pull URLs from body
        body_urls = list({m.group(0) for m in _re.finditer(r"https?://[a-zA-Z0-9\.\-_/?&=%]+", body_text)})[:50]
        resp = jsonify({
            "meta":         meta,
            "body_excerpt": body_text[:2000],
            "body_urls":    body_urls,
            "attachments":  attachments,
        })
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp
    except Exception as e:
        _log.exception("eml-analyze failed")
        resp = jsonify({"error": f"Analysis failed: {str(e)[:200]}"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 500

@app.route("/archive-analyze", methods=["POST", "OPTIONS"])
def archive_analyze():
    """Upload .zip — extract members, analyze each (≤10MB each)."""
    if request.method == "OPTIONS":
        resp = jsonify({"ok": True})
        resp.headers["Access-Control-Allow-Origin"]  = "*"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp
    if "file" not in request.files:
        resp = jsonify({"error": "No archive uploaded"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400
    raw = request.files["file"].read()
    if len(raw) > 25 * 1024 * 1024:
        resp = jsonify({"error": "Archive exceeds 25MB limit"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 400
    members = []
    archive_type = "unknown"
    try:
        if raw.startswith(b"PK\x03\x04"):
            archive_type = "zip"
            with _zipfile.ZipFile(_io.BytesIO(raw)) as zf:
                for info in zf.infolist()[:50]:
                    if info.is_dir(): continue
                    if info.file_size > 10 * 1024 * 1024:
                        members.append({"filename": info.filename, "error": "Member exceeds 10MB"})
                        continue
                    try:
                        data = zf.read(info.filename)
                        members.append(_analyze_file_data(data, filename=info.filename))
                    except Exception as e:
                        members.append({"filename": info.filename, "error": str(e)[:120]})
        elif raw.startswith(b"Rar!"):
            archive_type = "rar"
            try:
                import rarfile
                with rarfile.RarFile(_io.BytesIO(raw)) as rf:
                    for info in rf.infolist()[:50]:
                        if info.isdir(): continue
                        if info.file_size > 10 * 1024 * 1024:
                            members.append({"filename": info.filename, "error": "Member exceeds 10MB"})
                            continue
                        try:
                            data = rf.read(info.filename)
                            members.append(_analyze_file_data(data, filename=info.filename))
                        except Exception as e:
                            members.append({"filename": info.filename, "error": str(e)[:120]})
            except Exception as e:
                resp = jsonify({"error": f"RAR support not available: {str(e)[:120]}"})
                resp.headers["Access-Control-Allow-Origin"] = "*"
                return resp, 500
        elif raw.startswith(b"7z\xbc\xaf\x27\x1c"):
            archive_type = "7z"
            try:
                import py7zr
                with py7zr.SevenZipFile(_io.BytesIO(raw), mode="r") as zf:
                    extracted = zf.readall() or {}
                    for name, bio in list(extracted.items())[:50]:
                        data = bio.read() if hasattr(bio, "read") else bytes(bio)
                        if len(data) > 10 * 1024 * 1024:
                            members.append({"filename": name, "error": "Member exceeds 10MB"})
                            continue
                        members.append(_analyze_file_data(data, filename=name))
            except Exception as e:
                resp = jsonify({"error": f"7z support not available: {str(e)[:120]}"})
                resp.headers["Access-Control-Allow-Origin"] = "*"
                return resp, 500
        else:
            resp = jsonify({"error": "Unrecognized archive format. Supported: ZIP, RAR, 7Z."})
            resp.headers["Access-Control-Allow-Origin"] = "*"
            return resp, 400
        resp = jsonify({"archive_type": archive_type, "members": members})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp
    except Exception as e:
        _log.exception("archive-analyze failed")
        resp = jsonify({"error": f"Analysis failed: {str(e)[:200]}"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 500


# ══════════════════════════════════════════════════════════════════════════════
# METADATA EXTRACTOR + SCRUBBER — paste-in routes for app.py
#
# Routes:
#   /metadata-extract      — extract every piece of metadata from a file
#   /metadata-scrub        — return file with metadata stripped
#   /metadata-bulk-extract — analyze multiple files, return per-file leakiness scores
#   /metadata-bulk-scrub   — clean multiple files, return as zip
#   /metadata-compare      — diff metadata between two files
#
# Dependencies (add to requirements.txt):
#   python-docx==1.1.2
#   olefile==0.47
#   mutagen==1.47.0
#
# (pypdf, python-magic, beautifulsoup4 already added by previous tools)
#
# System deps (add via Render build script):
#   apt-get install -y libimage-exiftool-perl
#
# Notes:
#   exiftool is the heavyweight star here — handles ~250 file types for both
#   reading AND writing/stripping metadata. The Python libraries are fallbacks
#   for cases exiftool doesn't cover, plus revision-history reconstruction
#   (which exiftool doesn't do).
# ══════════════════════════════════════════════════════════════════════════════

import os as _os
import io as _io
import re as _re
import json as _json
import shutil as _shutil
import zipfile as _zipfile
import tempfile as _tempfile
import subprocess as _subprocess
import logging as _logging
from datetime import datetime as _datetime

_mlog = _logging.getLogger("metadata-tool")

# ── exiftool wrapper ────────────────────────────────────────────────────
def _exiftool_extract(filepath):
    """Run exiftool, return parsed JSON metadata. None if exiftool unavailable."""
    try:
        result = _subprocess.run(
            ["exiftool", "-j", "-G", "-a", "-u", "-ee", "-api", "largefilesupport=1", filepath],
            capture_output=True, timeout=30, check=False
        )
        if result.returncode != 0:
            _mlog.debug(f"exiftool nonzero rc={result.returncode} stderr={result.stderr[:200]}")
        out = (result.stdout or b"").decode("utf-8", errors="replace").strip()
        if not out:
            return None
        data = _json.loads(out)
        return data[0] if isinstance(data, list) and data else data
    except FileNotFoundError:
        _mlog.warning("exiftool not installed — metadata extraction degraded")
        return None
    except _subprocess.TimeoutExpired:
        _mlog.warning("exiftool timed out")
        return None
    except Exception as e:
        _mlog.debug(f"exiftool error: {e}")
        return None

def _exiftool_strip(filepath, output_path):
    """Use exiftool to write a copy with all metadata stripped."""
    try:
        # -all= removes everything; -overwrite_original_in_place would replace input file.
        # We want to write to output_path:
        _shutil.copy2(filepath, output_path)
        result = _subprocess.run(
            ["exiftool", "-all=", "-overwrite_original", output_path],
            capture_output=True, timeout=60, check=False
        )
        if result.returncode != 0:
            _mlog.warning(f"exiftool strip rc={result.returncode} stderr={result.stderr[:200]}")
            return False
        return True
    except FileNotFoundError:
        return False
    except Exception as e:
        _mlog.error(f"exiftool strip error: {e}")
        return False

# ── Office document deeper analysis (docx/xlsx/pptx) ────────────────────
def _analyze_office_docx(filepath):
    """Pull docx-specific data: revisions, comments, hidden text, custom properties."""
    out = {
        "tracked_changes":   [],
        "comments":          [],
        "hidden_text_count": 0,
        "custom_properties": {},
        "revision_count":    None,
    }
    try:
        with _zipfile.ZipFile(filepath) as z:
            namelist = z.namelist()
            # Revisions / tracked changes — in word/document.xml as w:ins, w:del
            if "word/document.xml" in namelist:
                doc_xml = z.read("word/document.xml").decode("utf-8", errors="ignore")
                # Insertions
                for m in _re.finditer(r'<w:ins[^>]*w:author="([^"]*)"[^>]*w:date="([^"]*)"', doc_xml):
                    out["tracked_changes"].append({
                        "kind":   "insert",
                        "author": m.group(1),
                        "date":   m.group(2),
                    })
                # Deletions
                for m in _re.finditer(r'<w:del[^>]*w:author="([^"]*)"[^>]*w:date="([^"]*)"', doc_xml):
                    out["tracked_changes"].append({
                        "kind":   "delete",
                        "author": m.group(1),
                        "date":   m.group(2),
                    })
                # Hidden text — w:vanish element
                out["hidden_text_count"] = len(_re.findall(r"<w:vanish[/ ]", doc_xml))
            # Comments
            for cf in ("word/comments.xml",):
                if cf in namelist:
                    c_xml = z.read(cf).decode("utf-8", errors="ignore")
                    for m in _re.finditer(r'<w:comment[^>]*w:author="([^"]*)"[^>]*w:date="([^"]*)"[^>]*>(.*?)</w:comment>',
                                          c_xml, _re.DOTALL):
                        # Extract comment text (remove inner XML tags)
                        text = _re.sub(r"<[^>]+>", " ", m.group(3)).strip()[:300]
                        out["comments"].append({
                            "author": m.group(1),
                            "date":   m.group(2),
                            "text":   text,
                        })
            # Custom properties
            if "docProps/custom.xml" in namelist:
                cp_xml = z.read("docProps/custom.xml").decode("utf-8", errors="ignore")
                for m in _re.finditer(r'<property[^>]*name="([^"]*)"[^>]*>\s*<[^>]+>([^<]*)<', cp_xml):
                    out["custom_properties"][m.group(1)] = m.group(2)
            # Revision count from app.xml
            if "docProps/app.xml" in namelist:
                app_xml = z.read("docProps/app.xml").decode("utf-8", errors="ignore")
                rev_match = _re.search(r"<TotalTime>(\d+)</TotalTime>", app_xml)
                if rev_match:
                    out["total_edit_time_min"] = int(rev_match.group(1))
                rev_match = _re.search(r"<Revision>(\d+)</Revision>", app_xml)
                if rev_match:
                    out["revision_count"] = int(rev_match.group(1))
    except Exception as e:
        out["error"] = str(e)[:200]
    return out

def _analyze_office_xlsx(filepath):
    """Pull xlsx-specific data: hidden sheets, hidden rows/columns."""
    out = {
        "hidden_sheets":      [],
        "hidden_named_ranges":[],
    }
    try:
        with _zipfile.ZipFile(filepath) as z:
            if "xl/workbook.xml" in z.namelist():
                wb = z.read("xl/workbook.xml").decode("utf-8", errors="ignore")
                # Hidden sheets — state="hidden" or "veryHidden"
                for m in _re.finditer(r'<sheet[^>]*name="([^"]*)"[^>]*state="(hidden|veryHidden)"', wb):
                    out["hidden_sheets"].append({
                        "name":  m.group(1),
                        "state": m.group(2),
                    })
                for m in _re.finditer(r'<definedName[^>]*name="([^"]*)"[^>]*hidden="1"', wb):
                    out["hidden_named_ranges"].append(m.group(1))
    except Exception as e:
        out["error"] = str(e)[:200]
    return out

def _analyze_office_pptx(filepath):
    """Pull pptx-specific data: hidden slides, speaker notes."""
    out = {
        "hidden_slides":  [],
        "slide_notes":    [],
        "total_slides":   0,
    }
    try:
        with _zipfile.ZipFile(filepath) as z:
            slides = sorted(n for n in z.namelist() if _re.match(r"ppt/slides/slide\d+\.xml$", n))
            out["total_slides"] = len(slides)
            for s in slides:
                xml = z.read(s).decode("utf-8", errors="ignore")
                if 'show="0"' in xml:
                    idx = int(_re.search(r"slide(\d+)\.xml", s).group(1))
                    out["hidden_slides"].append(idx)
            notes = sorted(n for n in z.namelist() if _re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n))
            for n in notes[:50]:
                xml = z.read(n).decode("utf-8", errors="ignore")
                text = _re.sub(r"<[^>]+>", " ", xml)
                text = _re.sub(r"\s+", " ", text).strip()
                if text:
                    idx = int(_re.search(r"notesSlide(\d+)\.xml", n).group(1))
                    out["slide_notes"].append({"slide": idx, "text": text[:400]})
    except Exception as e:
        out["error"] = str(e)[:200]
    return out

# ── PDF revision reconstruction ─────────────────────────────────────────
def _analyze_pdf_revisions(filepath):
    """
    PDFs use incremental updates — older versions remain in the file.
    Detect %%EOF markers; each marks the end of one revision.
    Multiple = file has been edited and previous content may still be recoverable.
    """
    out = {
        "revision_count":  1,
        "previous_eofs":   [],
        "annotations":     0,
        "form_fields":     0,
        "embedded_files":  0,
    }
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        # %%EOF markers
        eofs = [m.start() for m in _re.finditer(rb"%%EOF", data)]
        out["revision_count"] = len(eofs)
        if len(eofs) > 1:
            out["previous_eofs"] = eofs[:-1]
        # Annotation / form / embedded counts
        out["annotations"]    = len(_re.findall(rb"/Annot\b", data))
        out["form_fields"]    = len(_re.findall(rb"/AcroForm\b", data))
        out["embedded_files"] = len(_re.findall(rb"/EmbeddedFile\b", data))
        # Try pypdf for richer metadata
        try:
            import pypdf
            r = pypdf.PdfReader(filepath)
            out["page_count"] = len(r.pages)
            if r.metadata:
                meta = {}
                for k, v in r.metadata.items():
                    key = str(k).lstrip("/")
                    meta[key] = str(v)[:300]
                out["pdf_info_dict"] = meta
        except Exception as e:
            out["pypdf_error"] = str(e)[:120]
    except Exception as e:
        out["error"] = str(e)[:200]
    return out

# ── Ghost data detection ────────────────────────────────────────────────
def _detect_ghost_data(filepath, mime, ext_meta):
    """
    Surface content that's hidden from normal view but present in the file.
    Returns list of {kind, count, severity, description}.
    """
    ghosts = []
    try:
        # Office .docx / .xlsx / .pptx
        if filepath.lower().endswith(".docx"):
            office = _analyze_office_docx(filepath)
            if office.get("tracked_changes"):
                ghosts.append({
                    "kind":        "tracked_changes",
                    "count":       len(office["tracked_changes"]),
                    "severity":    "high",
                    "description": f"{len(office['tracked_changes'])} tracked insertions/deletions — recipient may see edit history if they enable Track Changes view",
                    "details":     office["tracked_changes"][:20],
                })
            if office.get("comments"):
                ghosts.append({
                    "kind":        "comments",
                    "count":       len(office["comments"]),
                    "severity":    "high",
                    "description": f"{len(office['comments'])} reviewer comments embedded",
                    "details":     office["comments"][:20],
                })
            if office.get("hidden_text_count"):
                ghosts.append({
                    "kind":        "hidden_text",
                    "count":       office["hidden_text_count"],
                    "severity":    "high",
                    "description": f"{office['hidden_text_count']} hidden-text elements (w:vanish) — invisible in normal view",
                })
            if office.get("custom_properties"):
                ghosts.append({
                    "kind":        "custom_properties",
                    "count":       len(office["custom_properties"]),
                    "severity":    "low",
                    "description": "Custom document properties present",
                    "details":     office["custom_properties"],
                })

        elif filepath.lower().endswith((".xlsx", ".xlsm")):
            xlsx = _analyze_office_xlsx(filepath)
            if xlsx.get("hidden_sheets"):
                ghosts.append({
                    "kind":        "hidden_sheets",
                    "count":       len(xlsx["hidden_sheets"]),
                    "severity":    "high",
                    "description": f"{len(xlsx['hidden_sheets'])} hidden sheet(s) — not visible in normal view",
                    "details":     xlsx["hidden_sheets"],
                })
            if xlsx.get("hidden_named_ranges"):
                ghosts.append({
                    "kind":        "hidden_named_ranges",
                    "count":       len(xlsx["hidden_named_ranges"]),
                    "severity":    "medium",
                    "description": "Hidden named ranges present",
                })

        elif filepath.lower().endswith(".pptx"):
            pptx = _analyze_office_pptx(filepath)
            if pptx.get("hidden_slides"):
                ghosts.append({
                    "kind":        "hidden_slides",
                    "count":       len(pptx["hidden_slides"]),
                    "severity":    "high",
                    "description": f"{len(pptx['hidden_slides'])} hidden slide(s) — not shown in presentation mode but recoverable",
                    "details":     pptx["hidden_slides"],
                })
            if pptx.get("slide_notes"):
                ghosts.append({
                    "kind":        "speaker_notes",
                    "count":       len(pptx["slide_notes"]),
                    "severity":    "medium",
                    "description": f"Speaker notes on {len(pptx['slide_notes'])} slide(s) — recipient sees these",
                    "details":     pptx["slide_notes"][:5],
                })

        # PDF
        if "pdf" in (mime or "").lower() or filepath.lower().endswith(".pdf"):
            pdf = _analyze_pdf_revisions(filepath)
            if pdf.get("revision_count", 1) > 1:
                ghosts.append({
                    "kind":        "pdf_revisions",
                    "count":       pdf["revision_count"],
                    "severity":    "high",
                    "description": f"PDF has {pdf['revision_count']} incremental revisions — earlier versions of content may be recoverable, including potentially redacted text",
                })
            if pdf.get("annotations", 0) > 0:
                ghosts.append({
                    "kind":        "pdf_annotations",
                    "count":       pdf["annotations"],
                    "severity":    "medium",
                    "description": f"{pdf['annotations']} PDF annotations (comments/highlights/sticky notes)",
                })
            if pdf.get("form_fields", 0) > 0:
                ghosts.append({
                    "kind":        "pdf_form_fields",
                    "count":       pdf["form_fields"],
                    "severity":    "low",
                    "description": "PDF form fields present",
                })
            if pdf.get("embedded_files", 0) > 0:
                ghosts.append({
                    "kind":        "pdf_embedded_files",
                    "count":       pdf["embedded_files"],
                    "severity":    "high",
                    "description": f"{pdf['embedded_files']} embedded file(s) in PDF — additional documents hidden inside",
                })

    except Exception as e:
        _mlog.debug(f"ghost detection error: {e}")
    return ghosts

# ── Leakiness score ─────────────────────────────────────────────────────
def _calculate_leakiness(ext_meta, ghosts, hashes):
    """
    Score 0-100 — HIGHER = MORE LEAKED INFO (more concerning).
    100 = severe (full author identity, GPS, original device path)
    50  = moderate (creator software + dates + revision)
    0   = clean (no identifying metadata)
    """
    score = 0
    flags = []  # {sym, text, severity}

    if not ext_meta:
        return {
            "score":      0,
            "label":      "Unknown",
            "summary":    "Could not extract metadata to assess leakiness.",
            "flags":      [],
        }

    # Author / creator identity (high cost)
    author = ext_meta.get("XMP:Creator") or ext_meta.get("PDF:Author") or ext_meta.get("Author")
    last_modified_by = ext_meta.get("XMP:LastModifiedBy") or ext_meta.get("ZIP:ZipModifyDate") or ext_meta.get("LastModifiedBy")
    company = ext_meta.get("XMP:Company") or ext_meta.get("Company") or ext_meta.get("XMP-xmp:CreatorTool")
    if author:
        score += 25
        flags.append({"sym":"⚠", "text":f"Author identity: {author}", "severity":"high"})
    if last_modified_by and last_modified_by != author:
        score += 15
        flags.append({"sym":"⚠", "text":f"Last modified by: {last_modified_by}", "severity":"high"})
    if company:
        score += 10
        flags.append({"sym":"⚠", "text":f"Organization: {company}", "severity":"medium"})

    # GPS location (huge cost — physical location leaked)
    gps_lat = ext_meta.get("EXIF:GPSLatitude") or ext_meta.get("Composite:GPSLatitude") or ext_meta.get("GPSLatitude")
    gps_lon = ext_meta.get("EXIF:GPSLongitude") or ext_meta.get("Composite:GPSLongitude") or ext_meta.get("GPSLongitude")
    if gps_lat and gps_lon:
        score += 35
        flags.append({"sym":"⊗", "text":f"GPS coordinates: {gps_lat}, {gps_lon}", "severity":"critical"})

    # Device identity (camera serial, machine ID)
    serial = ext_meta.get("EXIF:SerialNumber") or ext_meta.get("MakerNotes:SerialNumber") or ext_meta.get("SerialNumber")
    if serial:
        score += 15
        flags.append({"sym":"⚠", "text":f"Device serial number: {serial}", "severity":"high"})
    if ext_meta.get("EXIF:Make") or ext_meta.get("Make"):
        score += 5
        flags.append({"sym":"·", "text":f"Camera/device: {ext_meta.get('EXIF:Make') or ext_meta.get('Make')} {ext_meta.get('EXIF:Model') or ext_meta.get('Model','')}", "severity":"low"})

    # File path / network path leakage (severe)
    for k in ext_meta.keys():
        v = ext_meta.get(k)
        if not isinstance(v, str): continue
        if _re.search(r"[A-Z]:\\(Users|Documents|Desktop)|/Users/|/home/", v):
            score += 20
            flags.append({"sym":"⊗", "text":f"File path leaked in {k.split(':')[-1]}: {v[:80]}", "severity":"critical"})
            break

    # Software fingerprint (low)
    creator_app = ext_meta.get("XMP:CreatorTool") or ext_meta.get("PDF:Producer") or ext_meta.get("PDF:Creator") or ext_meta.get("Software")
    if creator_app:
        score += 5
        flags.append({"sym":"·", "text":f"Creator software: {creator_app}", "severity":"low"})

    # Timestamps (medium)
    if ext_meta.get("EXIF:DateTimeOriginal") or ext_meta.get("XMP:CreateDate"):
        score += 5
        flags.append({"sym":"·", "text":"Original creation timestamp embedded", "severity":"low"})

    # Ghost data (moderate-to-high based on what)
    for g in ghosts:
        sev = g.get("severity", "low")
        if sev == "critical":
            score += 30
        elif sev == "high":
            score += 15
        elif sev == "medium":
            score += 8
        else:
            score += 3
        flags.append({
            "sym":      "⚠" if sev in ("high","critical") else "·",
            "text":     g.get("description", ""),
            "severity": sev,
        })

    # Comments and tracked changes name authors directly — extra cost
    for g in ghosts:
        if g.get("kind") in ("tracked_changes", "comments"):
            authors = {x.get("author") for x in (g.get("details") or []) if x.get("author")}
            if authors:
                score += min(15, len(authors) * 5)
                flags.append({"sym":"⚠", "text":f"Authors named in {g['kind']}: {', '.join(sorted(authors))}", "severity":"high"})

    # Cap
    score = min(100, score)

    # Bucket label
    if score >= 70:    label, summary = "Severe", "Significant identifying metadata. Do not share without scrubbing."
    elif score >= 40:  label, summary = "Moderate", "Notable identifying metadata. Review before sharing."
    elif score >= 15:  label, summary = "Minor", "Some metadata present (mostly benign). Generally safe to share."
    else:              label, summary = "Clean", "Minimal or no identifying metadata."

    return {
        "score":   score,
        "label":   label,
        "summary": summary,
        "flags":   flags,
    }

# ── Main analyze function ───────────────────────────────────────────────
def _analyze_file(filepath, original_filename):
    """Full metadata extract pipeline."""
    out = {"filename": original_filename}

    # Hashes + size
    import hashlib
    with open(filepath, "rb") as f:
        data = f.read()
    out["hashes"] = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size":   len(data),
    }

    # File type detection
    try:
        import magic
        mime = magic.from_buffer(data, mime=True)
        desc = magic.from_buffer(data, mime=False)
    except Exception:
        mime = "application/octet-stream"
        desc = "unknown"
        # Header sniff fallback
        if data.startswith(b"%PDF"):                  mime, desc = "application/pdf", "PDF"
        elif data.startswith(b"PK\x03\x04"):          mime, desc = "application/zip", "ZIP/Office"
        elif data.startswith(b"\xff\xd8"):            mime, desc = "image/jpeg", "JPEG"
        elif data.startswith(b"\x89PNG"):             mime, desc = "image/png", "PNG"
        elif data.startswith(b"\xd0\xcf\x11\xe0"):    mime, desc = "application/x-ole-storage", "OLE / Office97"
    out["file_type"] = {"mime": mime, "description": desc}

    # exiftool extraction
    ext_meta = _exiftool_extract(filepath)
    if ext_meta:
        # Filter out filesystem-only fields that aren't useful
        filtered = {}
        SKIP = {"SourceFile", "ExifTool:ExifToolVersion", "File:Directory",
                "File:FileAccessDate", "File:FileInodeChangeDate",
                "File:FilePermissions", "File:FileUserID", "File:FileGroupID"}
        for k, v in ext_meta.items():
            if k in SKIP: continue
            filtered[k] = v
        out["exiftool"] = filtered
    else:
        out["exiftool"] = None
        out["exiftool_unavailable"] = True

    # Format-specific deeper analysis
    fp_lower = filepath.lower()
    if fp_lower.endswith(".docx"):
        out["docx_analysis"] = _analyze_office_docx(filepath)
    elif fp_lower.endswith((".xlsx", ".xlsm")):
        out["xlsx_analysis"] = _analyze_office_xlsx(filepath)
    elif fp_lower.endswith(".pptx"):
        out["pptx_analysis"] = _analyze_office_pptx(filepath)
    elif fp_lower.endswith(".pdf") or "pdf" in mime.lower():
        out["pdf_analysis"] = _analyze_pdf_revisions(filepath)

    # Ghost data
    out["ghost_data"] = _detect_ghost_data(filepath, mime, ext_meta or {})

    # Leakiness score
    out["leakiness"] = _calculate_leakiness(ext_meta or {}, out["ghost_data"], out["hashes"])

    return out

# ── Routes ─────────────────────────────────────────────────────────────
def _cors_options():
    resp = jsonify({"ok": True})
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/metadata-extract", methods=["POST", "OPTIONS"])
def metadata_extract():
    """Upload a file (≤50MB) for full metadata extraction + leakiness scoring."""
    if request.method == "OPTIONS":
        return _cors_options()
    if "file" not in request.files:
        return _cors(jsonify({"error": "No file uploaded"})), 400
    f = request.files["file"]
    raw = f.read()
    if len(raw) > 50 * 1024 * 1024:
        return _cors(jsonify({"error": "File exceeds 50MB limit"})), 400

    with _tempfile.NamedTemporaryFile(delete=False, suffix=_os.path.splitext(f.filename or "")[1]) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name
    try:
        result = _analyze_file(tmp_path, f.filename or "uploaded")
    except Exception as e:
        _mlog.exception("metadata-extract failed")
        return _cors(jsonify({"error": f"Analysis failed: {str(e)[:200]}"})), 500
    finally:
        try: _os.unlink(tmp_path)
        except Exception: pass
    return _cors(jsonify(result))

@app.route("/metadata-scrub", methods=["POST", "OPTIONS"])
def metadata_scrub():
    """Upload a file, return scrubbed copy + report of what was removed."""
    if request.method == "OPTIONS":
        return _cors_options()
    if "file" not in request.files:
        return _cors(jsonify({"error": "No file uploaded"})), 400
    f = request.files["file"]
    raw = f.read()
    if len(raw) > 50 * 1024 * 1024:
        return _cors(jsonify({"error": "File exceeds 50MB limit"})), 400

    original_name = f.filename or "uploaded"
    suffix = _os.path.splitext(original_name)[1]

    with _tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_in:
        tmp_in.write(raw)
        tmp_in_path = tmp_in.name
    tmp_out_path = tmp_in_path + ".clean" + suffix

    try:
        # Pre-scrub analysis (what's in the file?)
        pre = _analyze_file(tmp_in_path, original_name)
        # Scrub
        success = _exiftool_strip(tmp_in_path, tmp_out_path)
        # Office-specific: also clear core.xml authors and revision count
        if success and tmp_out_path.lower().endswith((".docx", ".xlsx", ".pptx")):
            _scrub_office_xml(tmp_out_path)
        # PDF-specific: pypdf to clear /Info dict if exiftool didn't catch everything
        if success and tmp_out_path.lower().endswith(".pdf"):
            _scrub_pdf_info(tmp_out_path)

        if not success:
            return _cors(jsonify({"error": "Scrubbing failed — exiftool may not be installed on server"})), 500

        # Post-scrub verification
        post = _analyze_file(tmp_out_path, original_name)

        # Stream cleaned file back as base64 for easy frontend handling
        import base64
        with open(tmp_out_path, "rb") as f_out:
            cleaned_bytes = f_out.read()
        cleaned_b64 = base64.b64encode(cleaned_bytes).decode("ascii")

        # Diff what was removed
        removed = _compute_metadata_diff(pre.get("exiftool") or {}, post.get("exiftool") or {})

        return _cors(jsonify({
            "filename":        original_name,
            "original_size":   len(raw),
            "cleaned_size":    len(cleaned_bytes),
            "cleaned_b64":     cleaned_b64,
            "pre_leakiness":   pre.get("leakiness"),
            "post_leakiness":  post.get("leakiness"),
            "fields_removed":  removed,
            "removed_count":   len(removed),
            "ghosts_pre":      pre.get("ghost_data") or [],
            "ghosts_post":     post.get("ghost_data") or [],
        }))

    except Exception as e:
        _mlog.exception("metadata-scrub failed")
        return _cors(jsonify({"error": f"Scrub failed: {str(e)[:200]}"})), 500
    finally:
        for p in (tmp_in_path, tmp_out_path):
            try: _os.unlink(p)
            except Exception: pass

def _scrub_office_xml(filepath):
    """Replace docProps/core.xml and app.xml authors/dates with empty values."""
    try:
        with _zipfile.ZipFile(filepath, "r") as zin:
            namelist = zin.namelist()
            data = {n: zin.read(n) for n in namelist}
        # Clear core.xml
        if "docProps/core.xml" in data:
            xml = data["docProps/core.xml"].decode("utf-8", errors="ignore")
            xml = _re.sub(r"<dc:creator>[^<]*</dc:creator>", "<dc:creator></dc:creator>", xml)
            xml = _re.sub(r"<cp:lastModifiedBy>[^<]*</cp:lastModifiedBy>", "<cp:lastModifiedBy></cp:lastModifiedBy>", xml)
            xml = _re.sub(r"<dc:title>[^<]*</dc:title>", "<dc:title></dc:title>", xml)
            xml = _re.sub(r"<dc:subject>[^<]*</dc:subject>", "<dc:subject></dc:subject>", xml)
            xml = _re.sub(r"<dc:description>[^<]*</dc:description>", "<dc:description></dc:description>", xml)
            xml = _re.sub(r"<cp:keywords>[^<]*</cp:keywords>", "<cp:keywords></cp:keywords>", xml)
            xml = _re.sub(r"<cp:revision>[^<]*</cp:revision>", "<cp:revision>1</cp:revision>", xml)
            data["docProps/core.xml"] = xml.encode("utf-8")
        # Clear app.xml
        if "docProps/app.xml" in data:
            xml = data["docProps/app.xml"].decode("utf-8", errors="ignore")
            xml = _re.sub(r"<Company>[^<]*</Company>", "<Company></Company>", xml)
            xml = _re.sub(r"<Manager>[^<]*</Manager>", "<Manager></Manager>", xml)
            xml = _re.sub(r"<TotalTime>[^<]*</TotalTime>", "<TotalTime>0</TotalTime>", xml)
            data["docProps/app.xml"] = xml.encode("utf-8")
        # Custom properties
        if "docProps/custom.xml" in data:
            data["docProps/custom.xml"] = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"></Properties>'
        # Re-zip
        with _zipfile.ZipFile(filepath, "w", _zipfile.ZIP_DEFLATED) as zout:
            for n, d in data.items():
                zout.writestr(n, d)
    except Exception as e:
        _mlog.warning(f"office xml scrub error: {e}")

def _scrub_pdf_info(filepath):
    """Use pypdf to clear PDF /Info dictionary."""
    try:
        import pypdf
        reader = pypdf.PdfReader(filepath)
        writer = pypdf.PdfWriter()
        for p in reader.pages:
            writer.add_page(p)
        # Clear metadata
        writer.add_metadata({})
        with open(filepath, "wb") as f:
            writer.write(f)
    except Exception as e:
        _mlog.warning(f"pdf info scrub error: {e}")

def _compute_metadata_diff(pre, post):
    """Return list of {key, old_value} for fields present pre-scrub but absent (or empty) post-scrub."""
    removed = []
    for k, v in (pre or {}).items():
        if k.startswith("File:"): continue  # Filesystem fields will always change
        post_v = post.get(k)
        if v and (not post_v or str(post_v) != str(v)):
            removed.append({
                "field":    k,
                "old_value": str(v)[:200],
            })
    return removed

@app.route("/metadata-bulk-extract", methods=["POST", "OPTIONS"])
def metadata_bulk_extract():
    """Upload multiple files, return per-file leakiness scores."""
    if request.method == "OPTIONS":
        return _cors_options()
    files = request.files.getlist("files")
    if not files:
        return _cors(jsonify({"error": "No files uploaded"})), 400
    if len(files) > 25:
        return _cors(jsonify({"error": "Maximum 25 files per bulk operation"})), 400

    total_size = 0
    results = []
    for f in files:
        raw = f.read()
        total_size += len(raw)
        if total_size > 100 * 1024 * 1024:
            results.append({"filename": f.filename, "error": "Total upload exceeds 100MB"})
            break
        if len(raw) > 50 * 1024 * 1024:
            results.append({"filename": f.filename, "error": "File exceeds 50MB"})
            continue
        with _tempfile.NamedTemporaryFile(delete=False, suffix=_os.path.splitext(f.filename or "")[1]) as tmp:
            tmp.write(raw)
            tmp_path = tmp.name
        try:
            r = _analyze_file(tmp_path, f.filename or "uploaded")
            # Slim result for bulk view — keep score + key fields only
            results.append({
                "filename":  r["filename"],
                "size":      r["hashes"]["size"],
                "mime":      r["file_type"]["mime"],
                "leakiness": r["leakiness"],
                "ghost_count": len(r.get("ghost_data") or []),
                "key_authors": _extract_key_authors(r),
                "sha256":    r["hashes"]["sha256"],
            })
        except Exception as e:
            results.append({"filename": f.filename, "error": str(e)[:200]})
        finally:
            try: _os.unlink(tmp_path)
            except Exception: pass

    # Sort by leakiness descending
    results.sort(key=lambda r: -(r.get("leakiness", {}).get("score", 0)))
    return _cors(jsonify({"results": results, "count": len(results)}))

def _extract_key_authors(result):
    """Pull author/last-modified from extracted metadata."""
    ext = result.get("exiftool") or {}
    authors = set()
    for k in ["XMP:Creator", "PDF:Author", "Author", "XMP:LastModifiedBy", "LastModifiedBy"]:
        v = ext.get(k)
        if v: authors.add(str(v))
    # Also pull from tracked changes / comments
    for analysis_key in ("docx_analysis","pptx_analysis"):
        a = result.get(analysis_key) or {}
        for ch in (a.get("tracked_changes") or []):
            if ch.get("author"): authors.add(ch["author"])
        for c in (a.get("comments") or []):
            if c.get("author"): authors.add(c["author"])
    return sorted(authors)

@app.route("/metadata-bulk-scrub", methods=["POST", "OPTIONS"])
def metadata_bulk_scrub():
    """Upload multiple files, return all cleaned versions packed in a zip."""
    if request.method == "OPTIONS":
        return _cors_options()
    files = request.files.getlist("files")
    if not files:
        return _cors(jsonify({"error": "No files uploaded"})), 400
    if len(files) > 25:
        return _cors(jsonify({"error": "Maximum 25 files per bulk operation"})), 400

    out_zip_buf = _io.BytesIO()
    summary = []
    total_size = 0

    with _zipfile.ZipFile(out_zip_buf, "w", _zipfile.ZIP_DEFLATED) as zout:
        for f in files:
            raw = f.read()
            total_size += len(raw)
            if total_size > 100 * 1024 * 1024:
                summary.append({"filename": f.filename, "error": "Total exceeds 100MB"})
                break
            if len(raw) > 50 * 1024 * 1024:
                summary.append({"filename": f.filename, "error": "File exceeds 50MB"})
                continue
            ext = _os.path.splitext(f.filename or "")[1]
            with _tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_in:
                tmp_in.write(raw); tmp_in_path = tmp_in.name
            tmp_out_path = tmp_in_path + ".clean" + ext
            try:
                pre = _analyze_file(tmp_in_path, f.filename or "uploaded")
                ok = _exiftool_strip(tmp_in_path, tmp_out_path)
                if ok and tmp_out_path.lower().endswith((".docx", ".xlsx", ".pptx")):
                    _scrub_office_xml(tmp_out_path)
                if ok and tmp_out_path.lower().endswith(".pdf"):
                    _scrub_pdf_info(tmp_out_path)
                if not ok:
                    summary.append({"filename": f.filename, "error": "Scrub failed"})
                    continue
                post = _analyze_file(tmp_out_path, f.filename or "uploaded")
                with open(tmp_out_path, "rb") as fc:
                    cleaned = fc.read()
                # Add to zip
                clean_name = _os.path.splitext(f.filename or "file")[0] + "-clean" + ext
                zout.writestr(clean_name, cleaned)
                summary.append({
                    "filename":         f.filename,
                    "cleaned_filename": clean_name,
                    "size_pre":         len(raw),
                    "size_post":        len(cleaned),
                    "leakiness_pre":    pre["leakiness"]["score"],
                    "leakiness_post":   post["leakiness"]["score"],
                    "ok":               True,
                })
            except Exception as e:
                summary.append({"filename": f.filename, "error": str(e)[:200]})
            finally:
                for p in (tmp_in_path, tmp_out_path):
                    try: _os.unlink(p)
                    except Exception: pass
        # Add summary report
        zout.writestr("_scrub-report.json", _json.dumps(summary, indent=2))

    out_zip_buf.seek(0)
    import base64
    zip_b64 = base64.b64encode(out_zip_buf.read()).decode("ascii")
    return _cors(jsonify({
        "zip_b64": zip_b64,
        "summary": summary,
        "filename": f"metadata-scrubbed-{_datetime.now().strftime('%Y%m%d-%H%M%S')}.zip",
    }))

@app.route("/metadata-compare", methods=["POST", "OPTIONS"])
def metadata_compare():
    """Compare metadata between two uploaded files."""
    if request.method == "OPTIONS":
        return _cors_options()
    f1 = request.files.get("file1")
    f2 = request.files.get("file2")
    if not f1 or not f2:
        return _cors(jsonify({"error": "Two files required (file1 + file2)"})), 400
    raw1, raw2 = f1.read(), f2.read()
    if len(raw1) > 50*1024*1024 or len(raw2) > 50*1024*1024:
        return _cors(jsonify({"error": "Each file must be ≤50MB"})), 400

    with _tempfile.NamedTemporaryFile(delete=False, suffix=_os.path.splitext(f1.filename or "")[1]) as t1:
        t1.write(raw1); p1 = t1.name
    with _tempfile.NamedTemporaryFile(delete=False, suffix=_os.path.splitext(f2.filename or "")[1]) as t2:
        t2.write(raw2); p2 = t2.name
    try:
        r1 = _analyze_file(p1, f1.filename or "file1")
        r2 = _analyze_file(p2, f2.filename or "file2")
        # Diff metadata
        ext1 = r1.get("exiftool") or {}
        ext2 = r2.get("exiftool") or {}
        keys1 = set(ext1.keys())
        keys2 = set(ext2.keys())
        only_in_1 = sorted(keys1 - keys2)
        only_in_2 = sorted(keys2 - keys1)
        differing = []
        for k in sorted(keys1 & keys2):
            if k.startswith("File:"): continue
            if str(ext1[k]) != str(ext2[k]):
                differing.append({
                    "field": k,
                    "value1": str(ext1[k])[:200],
                    "value2": str(ext2[k])[:200],
                })
        return _cors(jsonify({
            "file1":          {"filename": r1["filename"], "leakiness": r1["leakiness"], "hashes": r1["hashes"]},
            "file2":          {"filename": r2["filename"], "leakiness": r2["leakiness"], "hashes": r2["hashes"]},
            "same_content":   r1["hashes"]["sha256"] == r2["hashes"]["sha256"],
            "only_in_file1":  [{"field":k, "value":str(ext1[k])[:200]} for k in only_in_1[:50]],
            "only_in_file2":  [{"field":k, "value":str(ext2[k])[:200]} for k in only_in_2[:50]],
            "differing":      differing[:50],
        }))
    except Exception as e:
        _mlog.exception("metadata-compare failed")
        return _cors(jsonify({"error": str(e)[:200]})), 500
    finally:
        for p in (p1, p2):
            try: _os.unlink(p)
            except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
# PDF HIDDEN CONTENT REVEALER — paste-in routes for app.py
#
# Routes:
#   /pdf-reveal-all       — main analysis: text, layers, redactions, JS, OCGs, off-page
#   /pdf-render-page      — render one page as PNG (visible vs all-layers-on)
#   /pdf-revisions        — walk %%EOF markers, return per-revision text dumps
#   /pdf-compare-versions — diff two revisions of the same file
#
# Dependencies (add to requirements.txt):
#   pdfminer.six==20240706
#   pdf2image==1.17.0
#
# (pypdf, python-magic already added by previous tools)
#
# System deps (add to Render build command):
#   apt-get install -y poppler-utils
#
# poppler-utils provides: pdftotext, pdftoppm, pdfinfo
# ══════════════════════════════════════════════════════════════════════════════

import os as _pdfos
import io as _pdfio
import re as _pdfre
import json as _pdfjson
import shutil as _pdfshutil
import zipfile as _pdfzip
import tempfile as _pdftempfile
import subprocess as _pdfsubprocess
import logging as _pdflogging
import base64 as _pdfbase64
from datetime import datetime as _pdfdatetime

_pdflog = _pdflogging.getLogger("pdf-revealer")

# ── Helpers ────────────────────────────────────────────────────────────
def _pdf_save_temp(file_storage):
    suffix = ".pdf"
    fd, path = _pdftempfile.mkstemp(suffix=suffix)
    _pdfos.close(fd)
    raw = file_storage.read() if hasattr(file_storage, "read") else file_storage
    with open(path, "wb") as f:
        f.write(raw)
    return path, len(raw)

def _pdf_cleanup(*paths):
    for p in paths:
        try: _pdfos.unlink(p)
        except Exception: pass

def _pdf_pdfinfo(filepath):
    """Run pdfinfo, return dict."""
    try:
        result = _pdfsubprocess.run(
            ["pdfinfo", "-isodates", filepath],
            capture_output=True, timeout=15, check=False
        )
        out = (result.stdout or b"").decode("utf-8", errors="ignore")
        info = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return info
    except FileNotFoundError:
        return {"_error": "pdfinfo not installed"}
    except Exception as e:
        return {"_error": str(e)[:120]}

def _pdf_pdftotext(filepath, layout=True, raw=False, first_page=None, last_page=None):
    """Run pdftotext, return extracted text."""
    cmd = ["pdftotext"]
    if layout: cmd.append("-layout")
    if raw:    cmd.append("-raw")
    if first_page: cmd.extend(["-f", str(first_page)])
    if last_page:  cmd.extend(["-l", str(last_page)])
    cmd.extend([filepath, "-"])
    try:
        result = _pdfsubprocess.run(cmd, capture_output=True, timeout=60, check=False)
        if result.returncode != 0:
            _pdflog.debug(f"pdftotext rc={result.returncode}: {result.stderr[:200]}")
        return (result.stdout or b"").decode("utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except Exception as e:
        _pdflog.warning(f"pdftotext error: {e}")
        return None

def _pdf_count_eof_markers(filepath):
    """Count %%EOF occurrences — each marks end of one revision."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        eofs = [m.start() for m in _pdfre.finditer(rb"%%EOF", data)]
        return eofs, data
    except Exception:
        return [], b""

# ── Layer (OCG) extraction via pdfminer ────────────────────────────────
def _pdf_extract_ocgs(filepath):
    """Extract Optional Content Groups (PDF layers) and their default state."""
    try:
        from pdfminer.pdfparser import PDFParser
        from pdfminer.pdfdocument import PDFDocument
        from pdfminer.pdftypes import resolve1
        with open(filepath, "rb") as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)
            catalog = resolve1(doc.catalog) if hasattr(doc, "catalog") else doc.catalog
            ocp = catalog.get("OCProperties")
            if not ocp:
                return {"layers": [], "has_layers": False}
            ocp = resolve1(ocp)
            ocgs = ocp.get("OCGs") or []
            d = resolve1(ocp.get("D")) or {}
            on_list_raw = d.get("ON") or []
            off_list_raw = d.get("OFF") or []
            on_refs = {(getattr(x, "objid", None) or x) for x in on_list_raw}
            off_refs = {(getattr(x, "objid", None) or x) for x in off_list_raw}
            layers = []
            for g in ocgs:
                ocg = resolve1(g)
                if not isinstance(ocg, dict): continue
                name = ocg.get("Name", b"unnamed")
                if isinstance(name, bytes):
                    try: name = name.decode("utf-8", errors="ignore")
                    except: name = str(name)
                gid = getattr(g, "objid", None)
                state = "on"
                if gid in off_refs: state = "off (default-hidden)"
                elif gid in on_refs: state = "on"
                else:
                    base_state = d.get("BaseState") or "ON"
                    if isinstance(base_state, bytes):
                        base_state = base_state.decode("utf-8", errors="ignore")
                    state = "off (default-hidden)" if "OFF" in str(base_state).upper() else "on"
                layers.append({"name": str(name), "default_state": state, "id": gid})
            return {"layers": layers, "has_layers": len(layers) > 0}
    except Exception as e:
        _pdflog.debug(f"OCG extraction failed: {e}")
        return {"layers": [], "has_layers": False, "error": str(e)[:200]}

# ── JavaScript extraction ───────────────────────────────────────────────
def _pdf_extract_javascript(filepath):
    """Pull all JavaScript from the PDF."""
    js_chunks = []
    try:
        from pdfminer.pdfparser import PDFParser
        from pdfminer.pdfdocument import PDFDocument
        from pdfminer.pdftypes import resolve1, PDFStream
        with open(filepath, "rb") as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)
            for xref in doc.xrefs:
                for objid in xref.get_objids():
                    try:
                        obj = doc.getobj(objid)
                        obj = resolve1(obj)
                        if isinstance(obj, dict):
                            if obj.get("S") == "/JavaScript" or "JS" in obj or obj.get("Type") == "JavaScript":
                                js = obj.get("JS")
                                if js is not None:
                                    js = resolve1(js)
                                    if isinstance(js, PDFStream):
                                        try:
                                            data = js.get_data()
                                            text = data.decode("utf-8", errors="ignore")
                                            js_chunks.append(text[:5000])
                                        except Exception: pass
                                    elif isinstance(js, (str, bytes)):
                                        text = js.decode("utf-8", errors="ignore") if isinstance(js, bytes) else js
                                        js_chunks.append(text[:5000])
                    except Exception: continue
    except Exception as e:
        _pdflog.debug(f"JS extraction error: {e}")
    return js_chunks[:20]

# ── Failed redaction detection (THE feature) ───────────────────────────
def _pdf_detect_failed_redactions(filepath, max_pages=50):
    """
    Detect places where text exists at the same coordinates as a filled
    black/dark rectangle drawn on top of it.

    The classic failed redaction:
      - Acrobat draws a black rectangle over text
      - The text below is unchanged in the content stream
      - pdftotext extracts it like nothing happened
    """
    findings = []
    try:
        from pdfminer.high_level import extract_pages
        from pdfminer.layout import LTTextContainer, LTRect, LTChar, LAParams

        for pageno, page in enumerate(extract_pages(filepath, laparams=LAParams()), start=1):
            if pageno > max_pages: break

            # Collect filled rectangles (potential redaction boxes)
            rects = []
            for el in page:
                if isinstance(el, LTRect):
                    # We want filled, dark rectangles. pdfminer exposes fill on .fill (bool)
                    fill = getattr(el, "fill", False)
                    if fill:
                        rects.append({
                            "x0": el.x0, "y0": el.y0, "x1": el.x1, "y1": el.y1,
                            "stroke_color": getattr(el, "stroking_color", None),
                            "fill_color":   getattr(el, "non_stroking_color", None),
                            "linewidth":    getattr(el, "linewidth", 0),
                        })

            if not rects: continue

            # Heuristic: keep only rects that look like redactions
            # (filled dark color OR width > 30 pts and height < 40 pts — typical text-line rect)
            redaction_rects = []
            for r in rects:
                w, h = r["x1"]-r["x0"], r["y1"]-r["y0"]
                if w < 8 or h < 4: continue  # too small to be a redaction
                fc = r["fill_color"]
                is_dark = False
                if fc is None:
                    is_dark = True  # default fill is black
                elif isinstance(fc, (int, float)):
                    is_dark = fc < 0.4
                elif isinstance(fc, (tuple, list)) and len(fc) >= 1:
                    try:
                        avg = sum(c for c in fc[:3] if isinstance(c, (int, float))) / max(1, min(3, len(fc)))
                        is_dark = avg < 0.4
                    except Exception:
                        is_dark = False
                # Also flag white rects covering text (white-on-white redactions)
                is_white = False
                if isinstance(fc, (int, float)) and fc > 0.9:
                    is_white = True
                if is_dark or is_white or (w > 30 and h < 30):
                    r["likely_redaction"] = True
                    r["dark"] = is_dark
                    r["white"] = is_white
                    redaction_rects.append(r)

            if not redaction_rects: continue

            # Now find text overlapping with any redaction rectangle
            page_findings = []
            def _walk(container):
                if isinstance(container, LTTextContainer):
                    text = container.get_text().strip()
                    if not text: return
                    cx0, cy0, cx1, cy1 = container.x0, container.y0, container.x1, container.y1
                    for r in redaction_rects:
                        # Check overlap
                        overlap_x = max(0, min(cx1, r["x1"]) - max(cx0, r["x0"]))
                        overlap_y = max(0, min(cy1, r["y1"]) - max(cy0, r["y0"]))
                        if overlap_x > 0 and overlap_y > 0:
                            text_w = cx1 - cx0 or 1
                            text_h = cy1 - cy0 or 1
                            overlap_pct = (overlap_x * overlap_y) / (text_w * text_h)
                            if overlap_pct > 0.3:  # at least 30% covered
                                page_findings.append({
                                    "page": pageno,
                                    "hidden_text": text[:500],
                                    "overlap_pct": round(overlap_pct, 2),
                                    "redaction_dark": r["dark"],
                                    "redaction_white": r["white"],
                                    "rect": [round(r["x0"],1), round(r["y0"],1), round(r["x1"],1), round(r["y1"],1)],
                                    "text_box": [round(cx0,1), round(cy0,1), round(cx1,1), round(cy1,1)],
                                })
                                break
                if hasattr(container, "__iter__"):
                    for child in container:
                        try: _walk(child)
                        except Exception: pass
            for el in page:
                _walk(el)
            findings.extend(page_findings)
    except Exception as e:
        _pdflog.warning(f"redaction detection failed: {e}")
        return {"findings": [], "error": str(e)[:200]}
    return {"findings": findings, "count": len(findings)}

# ── Off-page text detection ────────────────────────────────────────────
def _pdf_detect_off_page_text(filepath, max_pages=50):
    """Find text positioned outside the page's MediaBox."""
    findings = []
    try:
        from pdfminer.high_level import extract_pages
        from pdfminer.layout import LTTextContainer, LAParams
        for pageno, page in enumerate(extract_pages(filepath, laparams=LAParams()), start=1):
            if pageno > max_pages: break
            page_w = page.width
            page_h = page.height
            def _walk(container):
                if isinstance(container, LTTextContainer):
                    text = container.get_text().strip()
                    if not text: return
                    if (container.x1 < 0 or container.x0 > page_w or
                        container.y1 < 0 or container.y0 > page_h):
                        findings.append({
                            "page": pageno,
                            "text": text[:500],
                            "position": [round(container.x0,1), round(container.y0,1), round(container.x1,1), round(container.y1,1)],
                            "page_size": [round(page_w,1), round(page_h,1)],
                        })
                if hasattr(container, "__iter__"):
                    for child in container:
                        try: _walk(child)
                        except Exception: pass
            for el in page:
                _walk(el)
    except Exception as e:
        _pdflog.warning(f"off-page detection failed: {e}")
        return {"findings": [], "error": str(e)[:200]}
    return {"findings": findings, "count": len(findings)}

# ── Annotations ────────────────────────────────────────────────────────
def _pdf_extract_annotations(filepath):
    """Pull all annotations (comments, highlights, sticky notes) with text + author."""
    annotations = []
    try:
        import pypdf
        reader = pypdf.PdfReader(filepath)
        for pi, page in enumerate(reader.pages, start=1):
            try:
                annots = page.get("/Annots")
                if not annots: continue
                annots = annots if isinstance(annots, list) else [annots]
                for a in annots:
                    try:
                        obj = a.get_object() if hasattr(a, "get_object") else a
                        if not isinstance(obj, dict): continue
                        subtype = str(obj.get("/Subtype", "")).strip("/")
                        contents = obj.get("/Contents")
                        if isinstance(contents, bytes):
                            contents = contents.decode("utf-8", errors="ignore")
                        author = obj.get("/T") or obj.get("/Author")
                        if isinstance(author, bytes):
                            author = author.decode("utf-8", errors="ignore")
                        date = obj.get("/M") or obj.get("/CreationDate")
                        if isinstance(date, bytes):
                            date = date.decode("utf-8", errors="ignore")
                        if contents or author or subtype not in ("Link",):
                            annotations.append({
                                "page": pi,
                                "type": subtype or "Unknown",
                                "contents": str(contents)[:500] if contents else "",
                                "author": str(author) if author else "",
                                "date": str(date) if date else "",
                            })
                    except Exception: continue
            except Exception: continue
    except Exception as e:
        _pdflog.debug(f"annotations error: {e}")
    return annotations[:200]

# ── Form fields ────────────────────────────────────────────────────────
def _pdf_extract_form_fields(filepath):
    """Get all form fields with default + current values."""
    fields = []
    try:
        import pypdf
        reader = pypdf.PdfReader(filepath)
        try:
            form = reader.get_form_text_fields() or {}
            for name, value in form.items():
                fields.append({
                    "name":  name,
                    "value": value if value else "",
                    "type":  "text",
                })
        except Exception: pass
        # Try to get full field data including defaults
        try:
            f = reader.get_fields() or {}
            existing = {x["name"] for x in fields}
            for name, fld in f.items():
                if name in existing: continue
                fields.append({
                    "name":  name,
                    "value": str(fld.get("/V", ""))[:200] if isinstance(fld, dict) else "",
                    "default": str(fld.get("/DV", ""))[:200] if isinstance(fld, dict) else "",
                    "type":  str(fld.get("/FT", "Unknown")).strip("/") if isinstance(fld, dict) else "Unknown",
                })
        except Exception: pass
    except Exception as e:
        _pdflog.debug(f"form fields error: {e}")
    return fields[:100]

# ── Hidden severity score ──────────────────────────────────────────────
def _pdf_calculate_hidden_score(reveal_data):
    """Compute 0-100 hidden-content severity (higher = more hidden stuff = bigger problem)."""
    score = 0
    flags = []

    redact = reveal_data.get("failed_redactions", {}).get("count", 0)
    if redact:
        score += min(60, redact * 8)
        flags.append({"sym":"⊗", "text":f"{redact} text region(s) under apparent redaction boxes — content extractable", "severity":"critical"})

    layers = reveal_data.get("layers", {}).get("layers", []) or []
    hidden_layers = [l for l in layers if "off" in l.get("default_state","").lower()]
    if hidden_layers:
        score += min(20, len(hidden_layers) * 5)
        flags.append({"sym":"⚠", "text":f"{len(hidden_layers)} hidden layer(s) configured to default-off: {', '.join(l['name'] for l in hidden_layers[:5])}", "severity":"high"})
    elif layers:
        flags.append({"sym":"·", "text":f"{len(layers)} optional content layer(s) (all visible by default)", "severity":"low"})

    revisions = reveal_data.get("revision_count", 1)
    if revisions > 1:
        score += min(15, (revisions-1) * 5)
        flags.append({"sym":"⚠", "text":f"{revisions} incremental revisions — earlier versions of content may be recoverable", "severity":"high"})

    js = reveal_data.get("javascript", []) or []
    if js:
        score += 10
        flags.append({"sym":"⚠", "text":f"{len(js)} JavaScript block(s) embedded in PDF", "severity":"high"})

    off_page = reveal_data.get("off_page_text", {}).get("count", 0)
    if off_page:
        score += min(15, off_page * 3)
        flags.append({"sym":"⚠", "text":f"{off_page} text region(s) positioned outside visible page boundaries", "severity":"high"})

    annotations = reveal_data.get("annotations", []) or []
    annot_with_text = [a for a in annotations if a.get("contents")]
    if annot_with_text:
        score += min(10, len(annot_with_text) * 2)
        flags.append({"sym":"·", "text":f"{len(annot_with_text)} annotation(s) with reviewer comments", "severity":"medium"})

    embedded = reveal_data.get("embedded_files_count", 0)
    if embedded:
        score += min(15, embedded * 5)
        flags.append({"sym":"⚠", "text":f"{embedded} embedded file(s) inside PDF", "severity":"high"})

    score = min(100, score)
    if score >= 60:    label, summary = "Severe", "This PDF contains significant hidden content. Treat the file as if it leaks all of this."
    elif score >= 30:  label, summary = "Moderate", "Hidden content present. Review before sharing or trusting redactions."
    elif score >= 10:  label, summary = "Minor", "Some hidden artifacts (typically benign)."
    else:              label, summary = "Clean", "No significant hidden content detected."
    return {"score": score, "label": label, "summary": summary, "flags": flags}

# ── Page rendering ──────────────────────────────────────────────────────
def _pdf_render_page(filepath, page_num, dpi=120):
    """Render a single page as PNG bytes via pdftoppm."""
    try:
        out_dir = _pdftempfile.mkdtemp()
        out_prefix = _pdfos.path.join(out_dir, "page")
        result = _pdfsubprocess.run(
            ["pdftoppm", "-png", "-r", str(dpi), "-f", str(page_num), "-l", str(page_num),
             filepath, out_prefix],
            capture_output=True, timeout=30, check=False
        )
        if result.returncode != 0:
            _pdflog.debug(f"pdftoppm rc={result.returncode}: {result.stderr[:200]}")
            return None
        for fn in _pdfos.listdir(out_dir):
            if fn.endswith(".png"):
                with open(_pdfos.path.join(out_dir, fn), "rb") as f:
                    data = f.read()
                _pdfshutil.rmtree(out_dir, ignore_errors=True)
                return data
        _pdfshutil.rmtree(out_dir, ignore_errors=True)
        return None
    except FileNotFoundError:
        _pdflog.warning("pdftoppm not installed")
        return None
    except Exception as e:
        _pdflog.warning(f"render failed: {e}")
        return None

# ── Main reveal pipeline ───────────────────────────────────────────────
def _pdf_reveal_all(filepath):
    """Comprehensive analysis of a PDF for hidden content."""
    info = _pdf_pdfinfo(filepath)
    eofs, _ = _pdf_count_eof_markers(filepath)
    page_count = 0
    try:
        page_count = int(info.get("Pages", "0") or 0)
    except Exception: pass

    visible_text = _pdf_pdftotext(filepath, layout=False) or ""
    layout_text  = _pdf_pdftotext(filepath, layout=True) or ""

    # Counts of visible-vs-extractable text
    text_stats = {
        "visible_chars": len(visible_text),
        "layout_chars":  len(layout_text),
        "delta":         abs(len(layout_text) - len(visible_text)),
    }

    out = {
        "pdfinfo":           info,
        "page_count":        page_count,
        "revision_count":    len(eofs),
        "extracted_text":    layout_text[:50000],
        "raw_text":          visible_text[:50000],
        "text_stats":        text_stats,
    }
    out["layers"]              = _pdf_extract_ocgs(filepath)
    out["javascript"]          = _pdf_extract_javascript(filepath)
    out["failed_redactions"]   = _pdf_detect_failed_redactions(filepath)
    out["off_page_text"]       = _pdf_detect_off_page_text(filepath)
    out["annotations"]         = _pdf_extract_annotations(filepath)
    out["form_fields"]         = _pdf_extract_form_fields(filepath)

    # Embedded files via pypdf
    try:
        import pypdf
        reader = pypdf.PdfReader(filepath)
        attachments = reader.attachments or {}
        out["embedded_files_count"] = len(attachments)
        out["embedded_filenames"]   = list(attachments.keys())[:20]
    except Exception:
        out["embedded_files_count"] = 0
        out["embedded_filenames"]   = []

    out["verdict"] = _pdf_calculate_hidden_score(out)
    return out

# ── Per-revision text via incremental update slicing ───────────────────
def _pdf_revisions(filepath):
    """For each %%EOF marker, extract the text up to that point as its own PDF revision."""
    eofs, data = _pdf_count_eof_markers(filepath)
    if len(eofs) <= 1:
        return {"revision_count": len(eofs), "revisions": []}
    revisions = []
    for i, eof_pos in enumerate(eofs, start=1):
        # Slice the file up to and including this EOF + linefeed
        end = eof_pos + len(b"%%EOF") + 2
        slice_data = data[:end]
        # Write to temp and try to extract text
        with _pdftempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(slice_data)
            tmp_path = tmp.name
        try:
            text = _pdf_pdftotext(tmp_path, layout=True) or ""
            info = _pdf_pdfinfo(tmp_path)
            revisions.append({
                "revision":    i,
                "size_bytes":  len(slice_data),
                "text":        text[:30000],
                "text_chars":  len(text),
                "page_count":  int((info.get("Pages") or "0").strip() or 0),
                "extractable": bool(text.strip()),
            })
        except Exception as e:
            revisions.append({"revision": i, "error": str(e)[:200]})
        finally:
            _pdf_cleanup(tmp_path)
    return {"revision_count": len(eofs), "revisions": revisions}

# ── Routes ─────────────────────────────────────────────────────────────
def _pdfresp_options():
    resp = jsonify({"ok": True})
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

def _pdfresp_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/pdf-reveal-all", methods=["POST", "OPTIONS"])
def pdf_reveal_all():
    """Upload PDF (≤50MB) for full hidden content analysis."""
    if request.method == "OPTIONS":
        return _pdfresp_options()
    if "file" not in request.files:
        return _pdfresp_cors(jsonify({"error": "No file uploaded"})), 400
    f = request.files["file"]
    raw = f.read()
    if len(raw) > 50 * 1024 * 1024:
        return _pdfresp_cors(jsonify({"error": "File exceeds 50MB limit"})), 400
    if not raw.startswith(b"%PDF"):
        return _pdfresp_cors(jsonify({"error": "Not a PDF file (missing %PDF header)"})), 400
    fd, tmp_path = _pdftempfile.mkstemp(suffix=".pdf")
    _pdfos.close(fd)
    try:
        with open(tmp_path, "wb") as out: out.write(raw)
        result = _pdf_reveal_all(tmp_path)
        result["filename"] = f.filename or "uploaded.pdf"
        return _pdfresp_cors(jsonify(result))
    except Exception as e:
        _pdflog.exception("pdf-reveal-all failed")
        return _pdfresp_cors(jsonify({"error": f"Analysis failed: {str(e)[:200]}"})), 500
    finally:
        _pdf_cleanup(tmp_path)

@app.route("/pdf-render-page", methods=["POST", "OPTIONS"])
def pdf_render_page_route():
    """Render a single PDF page as PNG (base64). For visual comparison."""
    if request.method == "OPTIONS":
        return _pdfresp_options()
    if "file" not in request.files:
        return _pdfresp_cors(jsonify({"error": "No file uploaded"})), 400
    f = request.files["file"]
    raw = f.read()
    if len(raw) > 50 * 1024 * 1024:
        return _pdfresp_cors(jsonify({"error": "File exceeds 50MB limit"})), 400
    try:
        page_num = int(request.form.get("page", "1"))
    except Exception:
        page_num = 1
    try:
        dpi = int(request.form.get("dpi", "120"))
        dpi = max(60, min(300, dpi))
    except Exception:
        dpi = 120
    fd, tmp_path = _pdftempfile.mkstemp(suffix=".pdf")
    _pdfos.close(fd)
    try:
        with open(tmp_path, "wb") as out: out.write(raw)
        png = _pdf_render_page(tmp_path, page_num, dpi=dpi)
        if not png:
            return _pdfresp_cors(jsonify({"error": "Render failed (pdftoppm may not be installed)"})), 500
        return _pdfresp_cors(jsonify({
            "page":      page_num,
            "dpi":       dpi,
            "png_b64":   _pdfbase64.b64encode(png).decode("ascii"),
        }))
    except Exception as e:
        _pdflog.exception("pdf-render-page failed")
        return _pdfresp_cors(jsonify({"error": f"Render failed: {str(e)[:200]}"})), 500
    finally:
        _pdf_cleanup(tmp_path)

@app.route("/pdf-revisions", methods=["POST", "OPTIONS"])
def pdf_revisions_route():
    """Walk PDF revisions (%%EOF markers), extract text from each revision."""
    if request.method == "OPTIONS":
        return _pdfresp_options()
    if "file" not in request.files:
        return _pdfresp_cors(jsonify({"error": "No file uploaded"})), 400
    f = request.files["file"]
    raw = f.read()
    if len(raw) > 50 * 1024 * 1024:
        return _pdfresp_cors(jsonify({"error": "File exceeds 50MB limit"})), 400
    fd, tmp_path = _pdftempfile.mkstemp(suffix=".pdf")
    _pdfos.close(fd)
    try:
        with open(tmp_path, "wb") as out: out.write(raw)
        result = _pdf_revisions(tmp_path)
        return _pdfresp_cors(jsonify(result))
    except Exception as e:
        _pdflog.exception("pdf-revisions failed")
        return _pdfresp_cors(jsonify({"error": f"Failed: {str(e)[:200]}"})), 500
    finally:
        _pdf_cleanup(tmp_path)


# ══════════════════════════════════════════════════════════════════════════════
# X (TWITTER) ACCOUNT FORENSICS — paste-in routes for app.py
#
# Routes:
#   /x-status         — single handle: status, earliest archive, history
#   /x-timeline       — full Wayback snapshot timeline for a handle
#   /x-tweet-recover  — given tweet URL, find archived versions
#   /x-bulk-status    — batch up to 50 handles
#   /x-fingerprint    — compare two handles for sock-puppet patterns
#
# All free, no API keys required.
# Sources used:
#   - Wayback Machine CDX API (https://web.archive.org/cdx/search/cdx)
#   - memory.lol (https://api.memory.lol) — handle history
#   - Live HTTP probe of twitter.com/x.com profile pages
#
# Optional: X API key support — frontend can pass user-provided key for richer data
# ══════════════════════════════════════════════════════════════════════════════

import re as _xre
import json as _xjson
import logging as _xlog
from datetime import datetime as _xdatetime, timezone as _xtimezone
from concurrent.futures import ThreadPoolExecutor as _xpool

_xlogger = _xlog.getLogger("x-forensics")

# ── Helpers ─────────────────────────────────────────────────────────────
_X_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; IntelDeskBot/1.0; +https://inteldesk.io)"
}

def _x_clean_handle(raw):
    """Normalize handle — accept @user, twitter.com/user, x.com/user, full URL."""
    if not raw: return None
    s = str(raw).strip()
    # Strip URL prefix
    s = _xre.sub(r"^https?://(?:www\.|mobile\.|m\.)?(?:twitter\.com|x\.com)/", "", s, flags=_xre.IGNORECASE)
    s = s.lstrip("@/")
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if not _xre.fullmatch(r"[A-Za-z0-9_]{1,15}", s):
        return None
    return s.lower()

def _x_wayback_cdx(url_pattern, limit=200, from_date=None, to_date=None):
    """Query Wayback CDX API. Returns list of {timestamp, original, statuscode, mimetype}."""
    params = {
        "url":      url_pattern,
        "output":   "json",
        "limit":    str(limit),
        "filter":   "statuscode:200",
        "fl":       "timestamp,original,statuscode,mimetype",
        "collapse": "digest",
    }
    if from_date: params["from"] = from_date
    if to_date:   params["to"]   = to_date
    try:
        r = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params=params, headers=_X_HEADERS, timeout=15
        )
        if r.status_code != 200:
            return []
        data = r.json()
        if not data or len(data) < 2:
            return []
        # First row is column names
        cols = data[0]
        rows = data[1:]
        return [dict(zip(cols, r)) for r in rows]
    except Exception as e:
        _xlogger.debug(f"wayback cdx error: {e}")
        return []

def _x_memory_lol(handle):
    """Query memory.lol for handle history. Free, public, run by Tim Hwang's archive project."""
    try:
        r = requests.get(
            f"https://api.memory.lol/v1/tw/{handle}",
            headers=_X_HEADERS, timeout=10
        )
        if r.status_code != 200:
            return None
        data = r.json()
        accounts = data.get("accounts") or []
        if not accounts:
            return {"found": False}
        # Each account has id_str + screen_names dict {name: [date_first, date_last]}
        return {
            "found":    True,
            "accounts": [{
                "id":            a.get("id_str"),
                "screen_names":  [
                    {"handle": h, "first_seen": dates[0] if isinstance(dates, list) and dates else None,
                                 "last_seen":  dates[-1] if isinstance(dates, list) and dates else None}
                    for h, dates in (a.get("screen_names") or {}).items()
                ],
            } for a in accounts]
        }
    except Exception as e:
        _xlogger.debug(f"memory.lol error: {e}")
        return None

def _x_live_probe(handle):
    """Quickly probe x.com/handle and twitter.com/handle to detect status."""
    result = {"x_com": None, "twitter_com": None}
    for domain_key, url in [
        ("x_com",       f"https://x.com/{handle}"),
        ("twitter_com", f"https://twitter.com/{handle}"),
    ]:
        try:
            r = requests.get(url, headers=_X_HEADERS, timeout=10, allow_redirects=True)
            text = r.text[:50000].lower() if r.text else ""
            status = "unknown"
            if r.status_code == 404:
                status = "not_found"
            elif "account suspended" in text or "/account/suspended" in r.url.lower():
                status = "suspended"
            elif "this account doesn" in text or "doesn't exist" in text:
                status = "deleted"
            elif r.status_code == 200:
                status = "alive"
            result[domain_key] = {
                "status":      status,
                "http_code":   r.status_code,
                "final_url":   r.url,
            }
        except Exception as e:
            result[domain_key] = {"status": "error", "error": str(e)[:120]}
    return result

def _x_estimate_creation(snapshots, handle_history):
    """
    Provide a defensible LOWER BOUND on account age.
    We CANNOT get the actual creation date without API. Be honest about this.
    """
    earliest_dates = []
    if snapshots:
        ts = snapshots[0].get("timestamp") if snapshots else None
        if ts and len(ts) >= 8:
            earliest_dates.append(_x_parse_wayback_ts(ts))
    if handle_history and handle_history.get("found"):
        for acct in handle_history.get("accounts", []):
            for sn in acct.get("screen_names", []):
                fs = sn.get("first_seen")
                if fs:
                    try:
                        earliest_dates.append(_xdatetime.fromisoformat(fs.split("T")[0]))
                    except Exception:
                        pass
    if not earliest_dates:
        return None
    earliest = min(earliest_dates)
    return {
        "earliest_known": earliest.isoformat()[:10],
        "source":         "wayback + memory.lol",
        "caveat":         "This is a LOWER BOUND. The account existed at least by this date — its actual creation date may be earlier and is not knowable without X API access.",
        "years_ago":      round((_xdatetime.utcnow() - earliest).days / 365.25, 1),
    }

def _x_parse_wayback_ts(ts):
    """Wayback timestamp YYYYMMDDhhmmss → datetime."""
    try:
        return _xdatetime.strptime(ts[:14], "%Y%m%d%H%M%S")
    except Exception:
        try:
            return _xdatetime.strptime(ts[:8], "%Y%m%d")
        except Exception:
            return _xdatetime.utcnow()

def _x_detect_patterns(snapshots, handle_history, live):
    """Detect suspicious-pattern signals — sock puppet, identity-laundering, dormancy."""
    flags = []

    # No snapshots at all — suspicious if account is alive (could mean very new OR scrubbed)
    if not snapshots:
        if live and any(v and v.get("status") == "alive" for v in live.values()):
            flags.append({
                "kind":        "no_archive_history",
                "severity":    "medium",
                "description": "Account is currently alive but has zero Wayback snapshots — may be very new, or has actively avoided/blocked archival.",
            })

    # Many handle renames in short period → identity laundering
    if handle_history and handle_history.get("found"):
        for acct in handle_history["accounts"]:
            sns = acct.get("screen_names", [])
            if len(sns) >= 3:
                flags.append({
                    "kind":        "frequent_renames",
                    "severity":    "high",
                    "description": f"Account has used {len(sns)} different handles. Identity-laundering pattern (changing handles to deflect attention from past activity).",
                    "details":     [s.get("handle") for s in sns],
                })

    # Long dormancy → reactivated
    if len(snapshots) >= 5:
        dates = sorted([_x_parse_wayback_ts(s["timestamp"]) for s in snapshots if s.get("timestamp")])
        gaps = []
        for i in range(1, len(dates)):
            gap_days = (dates[i] - dates[i-1]).days
            if gap_days > 365 * 2:  # 2+ year gap
                gaps.append({"gap_days": gap_days, "before": dates[i-1].isoformat()[:10], "after": dates[i].isoformat()[:10]})
        if gaps:
            flags.append({
                "kind":        "dormancy_reactivation",
                "severity":    "medium",
                "description": f"Account has {len(gaps)} multi-year gap(s) in archived activity, suggesting periods of dormancy followed by reactivation.",
                "details":     gaps[:5],
            })

    # Currently suspended/deleted — surface prominently
    if live:
        for k, v in live.items():
            if v and v.get("status") in ("suspended", "deleted"):
                flags.append({
                    "kind":        f"currently_{v['status']}",
                    "severity":    "high",
                    "description": f"Account is currently {v['status']} on {k.replace('_', '.')}. Archived content may still be retrievable via Wayback.",
                })
                break

    return flags

# ── Routes ──────────────────────────────────────────────────────────────
def _xresp_options():
    resp = jsonify({"ok": True})
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

def _xresp_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/x-status", methods=["GET", "OPTIONS"])
def x_status():
    """Single-handle full forensic check."""
    if request.method == "OPTIONS":
        return _xresp_options()
    handle_raw = (request.args.get("handle") or "").strip()
    handle = _x_clean_handle(handle_raw)
    if not handle:
        return _xresp_cors(jsonify({"error": "Invalid handle"})), 400

    # Run three queries in parallel
    with _xpool(max_workers=3) as ex:
        f_cdx     = ex.submit(_x_wayback_cdx, f"twitter.com/{handle}*", 200)
        f_history = ex.submit(_x_memory_lol, handle)
        f_live    = ex.submit(_x_live_probe, handle)
        snapshots = []
        try: snapshots = f_cdx.result(timeout=20) or []
        except Exception: pass
        history = None
        try: history = f_history.result(timeout=15)
        except Exception: pass
        live = None
        try: live = f_live.result(timeout=15)
        except Exception: pass

    # Also try x.com/* in CDX (newer URL prefix)
    snapshots_xcom = _x_wayback_cdx(f"x.com/{handle}*", 100)
    snapshots = snapshots + snapshots_xcom
    # Sort all snapshots by timestamp
    snapshots.sort(key=lambda s: s.get("timestamp", ""))

    creation = _x_estimate_creation(snapshots, history)
    flags    = _x_detect_patterns(snapshots, history, live)

    # Determine current status
    current_status = "unknown"
    if live:
        for v in live.values():
            if v and v.get("status") == "alive":
                current_status = "alive"; break
            if v and v.get("status") == "suspended":
                current_status = "suspended"
            if v and v.get("status") == "deleted" and current_status == "unknown":
                current_status = "deleted"
            if v and v.get("status") == "not_found" and current_status == "unknown":
                current_status = "not_found"
    if current_status == "unknown" and snapshots:
        current_status = "deleted_or_unknown"

    return _xresp_cors(jsonify({
        "handle":          handle,
        "current_status":  current_status,
        "live":            live,
        "creation":        creation,
        "snapshot_count":  len(snapshots),
        "earliest_snapshot": snapshots[0].get("timestamp") if snapshots else None,
        "latest_snapshot":   snapshots[-1].get("timestamp") if snapshots else None,
        "handle_history":  history,
        "patterns":        flags,
        "snapshots_sample": snapshots[:30] + (snapshots[-30:] if len(snapshots) > 60 else []),
    }))

@app.route("/x-timeline", methods=["GET", "OPTIONS"])
def x_timeline():
    """Full Wayback snapshot timeline for a handle."""
    if request.method == "OPTIONS":
        return _xresp_options()
    handle = _x_clean_handle(request.args.get("handle") or "")
    if not handle:
        return _xresp_cors(jsonify({"error": "Invalid handle"})), 400

    snapshots_a = _x_wayback_cdx(f"twitter.com/{handle}*", 500)
    snapshots_b = _x_wayback_cdx(f"x.com/{handle}*", 200)
    snapshots = snapshots_a + snapshots_b
    snapshots.sort(key=lambda s: s.get("timestamp", ""))

    # Group by month
    by_month = {}
    for s in snapshots:
        ts = s.get("timestamp", "")
        if len(ts) < 6: continue
        month_key = ts[:6]  # YYYYMM
        by_month.setdefault(month_key, []).append({
            "timestamp": ts,
            "url":       s.get("original"),
            "wayback":   f"https://web.archive.org/web/{ts}/{s.get('original','')}",
        })

    return _xresp_cors(jsonify({
        "handle":         handle,
        "total_snapshots": len(snapshots),
        "by_month":       by_month,
        "first":          snapshots[0] if snapshots else None,
        "last":           snapshots[-1] if snapshots else None,
    }))

@app.route("/x-tweet-recover", methods=["GET", "OPTIONS"])
def x_tweet_recover():
    """Given tweet URL or status ID, find Wayback archives."""
    if request.method == "OPTIONS":
        return _xresp_options()
    raw = (request.args.get("tweet") or "").strip()
    if not raw:
        return _xresp_cors(jsonify({"error": "No tweet URL or ID provided"})), 400

    # Parse: full URL, status URL, or just tweet ID
    tweet_id = None
    handle = None
    m = _xre.search(r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]+)/status(?:es)?/(\d+)", raw)
    if m:
        handle  = m.group(1).lower()
        tweet_id = m.group(2)
    elif _xre.fullmatch(r"\d+", raw):
        tweet_id = raw
    else:
        return _xresp_cors(jsonify({"error": "Could not parse tweet URL or ID. Provide a status URL like https://x.com/user/status/123 or a numeric tweet ID."})), 400

    # Search Wayback for tweet status URLs (both twitter.com and x.com variants)
    patterns = [
        f"twitter.com/*/status/{tweet_id}",
        f"twitter.com/*/status/{tweet_id}*",
        f"x.com/*/status/{tweet_id}",
        f"x.com/*/status/{tweet_id}*",
    ]
    if handle:
        patterns.extend([
            f"twitter.com/{handle}/status/{tweet_id}",
            f"x.com/{handle}/status/{tweet_id}",
        ])

    all_snapshots = []
    seen = set()
    for p in patterns:
        for s in _x_wayback_cdx(p, 50):
            ts = s.get("timestamp", "")
            url = s.get("original", "")
            key = (ts, url)
            if key in seen: continue
            seen.add(key)
            s["wayback_url"] = f"https://web.archive.org/web/{ts}/{url}"
            all_snapshots.append(s)
    all_snapshots.sort(key=lambda s: s.get("timestamp", ""))

    return _xresp_cors(jsonify({
        "tweet_id":    tweet_id,
        "handle":      handle,
        "found":       len(all_snapshots) > 0,
        "snapshot_count": len(all_snapshots),
        "snapshots":   all_snapshots[:50],
    }))

@app.route("/x-bulk-status", methods=["POST", "OPTIONS"])
def x_bulk_status():
    """Batch status check up to 50 handles."""
    if request.method == "OPTIONS":
        return _xresp_options()
    body = request.get_json(silent=True) or {}
    raw_handles = body.get("handles") or []
    if not isinstance(raw_handles, list):
        return _xresp_cors(jsonify({"error": "Body must contain handles: [array]"})), 400
    if len(raw_handles) > 50:
        raw_handles = raw_handles[:50]

    cleaned = []
    for h in raw_handles:
        c = _x_clean_handle(h)
        if c: cleaned.append(c)
    if not cleaned:
        return _xresp_cors(jsonify({"error": "No valid handles provided"})), 400

    def _check_one(handle):
        try:
            cdx = _x_wayback_cdx(f"twitter.com/{handle}*", 50)
            live = _x_live_probe(handle)
            current = "unknown"
            if live:
                for v in live.values():
                    if v and v.get("status") == "alive": current = "alive"; break
                    if v and v.get("status") in ("suspended", "deleted", "not_found"):
                        current = v.get("status")
            return {
                "handle":          handle,
                "current_status":  current,
                "snapshot_count":  len(cdx),
                "earliest":        cdx[0].get("timestamp") if cdx else None,
                "latest":          cdx[-1].get("timestamp") if cdx else None,
            }
        except Exception as e:
            return {"handle": handle, "error": str(e)[:120]}

    results = []
    with _xpool(max_workers=6) as ex:
        for r in ex.map(_check_one, cleaned):
            results.append(r)
    return _xresp_cors(jsonify({"count": len(results), "results": results}))

@app.route("/x-fingerprint", methods=["GET", "OPTIONS"])
def x_fingerprint():
    """Compare two handles for sock-puppet patterns."""
    if request.method == "OPTIONS":
        return _xresp_options()
    h1 = _x_clean_handle(request.args.get("h1") or "")
    h2 = _x_clean_handle(request.args.get("h2") or "")
    if not h1 or not h2:
        return _xresp_cors(jsonify({"error": "Both h1 and h2 handles required"})), 400

    def _fingerprint_one(handle):
        snapshots = _x_wayback_cdx(f"twitter.com/{handle}*", 200) + _x_wayback_cdx(f"x.com/{handle}*", 100)
        snapshots.sort(key=lambda s: s.get("timestamp", ""))
        history = _x_memory_lol(handle)
        # Build month-buckets to compare activity patterns
        months = {}
        for s in snapshots:
            ts = s.get("timestamp", "")
            if len(ts) >= 6:
                m = ts[:6]
                months[m] = months.get(m, 0) + 1
        return {
            "handle":         handle,
            "snapshot_count": len(snapshots),
            "earliest":       snapshots[0].get("timestamp") if snapshots else None,
            "latest":         snapshots[-1].get("timestamp") if snapshots else None,
            "active_months":  list(months.keys()),
            "month_buckets":  months,
            "renames":        [
                sn.get("handle")
                for a in (history or {}).get("accounts", [])
                for sn in a.get("screen_names", [])
            ] if history else [],
        }

    with _xpool(max_workers=2) as ex:
        f1 = ex.submit(_fingerprint_one, h1)
        f2 = ex.submit(_fingerprint_one, h2)
        a = f1.result(timeout=30)
        b = f2.result(timeout=30)

    # Compute overlap signals
    months_a = set(a["active_months"])
    months_b = set(b["active_months"])
    overlap_months = sorted(months_a & months_b)
    only_a = sorted(months_a - months_b)
    only_b = sorted(months_b - months_a)

    # Suspicious pattern: if the months are mutually exclusive (one active when other dormant)
    mutual_exclusion_score = 0
    if months_a and months_b:
        total = len(months_a | months_b)
        if total > 0:
            mutual_exclusion_score = round((1.0 - len(overlap_months)/total) * 100)

    similarities = []
    if a["renames"] and b["renames"]:
        common_renames = set(a["renames"]) & set(b["renames"])
        if common_renames:
            similarities.append({
                "kind":     "shared_handle_history",
                "evidence": list(common_renames),
                "weight":   "very_strong",
            })
    if mutual_exclusion_score > 70 and (a["snapshot_count"] >= 5 and b["snapshot_count"] >= 5):
        similarities.append({
            "kind":     "mutually_exclusive_activity",
            "score":    mutual_exclusion_score,
            "weight":   "moderate",
            "summary":  f"{mutual_exclusion_score}% of active months are mutually exclusive — when one is active, the other is dormant.",
        })

    return _xresp_cors(jsonify({
        "handle_1":              a,
        "handle_2":              b,
        "overlap_months":        overlap_months,
        "only_in_handle_1":      only_a[:50],
        "only_in_handle_2":      only_b[:50],
        "mutual_exclusion_pct":  mutual_exclusion_score,
        "similarity_signals":    similarities,
    }))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
