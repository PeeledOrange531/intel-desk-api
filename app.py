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



# ── AIS STREAM — vessel positions cache ───────────────────────────────────────
import threading
import json
import time

AIS_KEY = os.environ.get("AISSTREAM_KEY", "f192af54ec4e47a4e1dc7c2f7d2c86edd6e81cf4")
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

HIVE_KEY_ID  = os.environ.get("HIVE_KEY_ID",  "HaDgN8P57x8baTQr")
HIVE_SECRET  = os.environ.get("HIVE_SECRET",  "UvliQHC6K+o0LapQyDeD1w==")
HF_TOKEN     = os.environ.get("HF_TOKEN",     "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")

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

    img_file = request.files["image"]
    img_bytes = img_file.read()
    img_b64   = _b64.b64encode(img_bytes).decode()
    mime_type = img_file.content_type or "image/jpeg"
    file_size = len(img_bytes)

    result = {
        "file_size":  file_size,
        "mime_type":  mime_type,
        "hive":       None,
        "huggingface":None,
        "metadata":   None,
    }

    # ── Signal 1: Hive AI Detection ──────────────────────────────────────────
    try:
        import hmac as _hmac
        import time as _time

        # Build Hive V3 auth signature
        ts        = str(int(_time.time() * 1000))
        path      = "/api/v3/task/sync/media_analyzer"
        body_str  = ""  # no body hash for multipart
        sig_str   = f"{HIVE_KEY_ID}{ts}{path}"
        sig       = _hmac.new(
            HIVE_SECRET.encode(),
            sig_str.encode(),
            _hashlib.sha256
        ).hexdigest()

        hive_resp = requests.post(
            "https://api.thehive.ai/api/v3/task/sync/media_analyzer",
            headers={
                "Api-Key": HIVE_KEY_ID,
                "Authorization": f"Token {HIVE_KEY_ID}",
            },
            files={"media": (img_file.filename or "image.jpg", img_bytes, mime_type)},
            data={"models": "ai-generated-and-deepfake-content-detection"},
            timeout=30,
        )
        if hive_resp.status_code == 200:
            result["hive"] = hive_resp.json()
        else:
            # Try alternate endpoint
            hive_resp2 = requests.post(
                "https://api.thehive.ai/api/v2/task/sync",
                headers={"Authorization": f"Token {HIVE_KEY_ID}"},
                files={"media": (img_file.filename or "image.jpg", img_bytes, mime_type)},
                timeout=30,
            )
            if hive_resp2.status_code == 200:
                result["hive"] = hive_resp2.json()
            else:
                result["hive"] = {"error": f"HTTP {hive_resp.status_code}", "detail": hive_resp.text[:200]}
    except Exception as e:
        result["hive"] = {"error": str(e)[:100]}

    # ── Signal 2: HuggingFace — AI image detector ─────────────────────────────
    try:
        hf_resp = requests.post(
            "https://api-inference.huggingface.co/models/Organika/sdxl-detector",
            headers={"Authorization": f"Bearer {HF_TOKEN}"},
            data=img_bytes,
            timeout=30,
        )
        if hf_resp.status_code == 200:
            result["huggingface"] = hf_resp.json()
        else:
            # Fallback model
            hf_resp2 = requests.post(
                "https://api-inference.huggingface.co/models/umm-maybe/AI-image-detector",
                headers={"Authorization": f"Bearer {HF_TOKEN}"},
                data=img_bytes,
                timeout=30,
            )
            if hf_resp2.status_code == 200:
                result["huggingface"] = hf_resp2.json()
            else:
                result["huggingface"] = {"error": f"HTTP {hf_resp.status_code}"}
    except Exception as e:
        result["huggingface"] = {"error": str(e)[:100]}

    # ── Signal 3: Basic metadata check ───────────────────────────────────────
    try:
        import io as _io
        # Check for EXIF via raw bytes
        meta = {}
        if img_bytes[:2] == b"\xff\xd8":
            meta["format"] = "JPEG"
        elif img_bytes[:8] == b"\x89PNG\r\n\x1a\n":
            meta["format"] = "PNG"
        elif img_bytes[:4] in (b"RIFF", b"WEBP"):
            meta["format"] = "WEBP"
        else:
            meta["format"] = "Unknown"

        # Check for common AI generator signatures in bytes
        raw_str = img_bytes[:4096].decode("latin-1", errors="ignore").lower()
        ai_sigs = {
            "stable diffusion": "stable diffusion" in raw_str or "diffusion" in raw_str,
            "midjourney":       "midjourney" in raw_str,
            "dall-e":           "dall-e" in raw_str or "openai" in raw_str,
            "firefly":          "firefly" in raw_str or "adobe firefly" in raw_str,
            "comfyui":          "comfyui" in raw_str,
            "automatic1111":    "automatic1111" in raw_str or "webui" in raw_str,
            "novelai":          "novelai" in raw_str,
        }
        meta["ai_signatures"] = {k: v for k, v in ai_sigs.items() if v}
        meta["has_ai_signature"] = any(ai_sigs.values())

        # File size heuristic — AI images often lack progressive JPEG data
        meta["file_size_kb"] = round(file_size / 1024, 1)

        result["metadata"] = meta
    except Exception as e:
        result["metadata"] = {"error": str(e)[:100]}

    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
