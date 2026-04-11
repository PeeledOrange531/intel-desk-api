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



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
