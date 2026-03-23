"""
The Intel Desk — Sanctions List Proxy
======================================
Sits on Render as a tiny Flask service. Fetches sanctions lists from
official government sources and returns them to the frontend with
correct CORS headers. Caches each list for 6 hours to be respectful
to upstream servers and keep response times fast.

Deploy on Render as a Web Service:
  Build command:  pip install -r requirements.txt
  Start command:  gunicorn app:app
"""

import os
import time
import logging
import requests
from flask import Flask, Response, jsonify, request
from functools import wraps

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
CACHE_TTL      = int(os.environ.get("CACHE_TTL", 6 * 3600))
FETCH_TIMEOUT  = int(os.environ.get("FETCH_TIMEOUT", 30))

# ── Source URLs ───────────────────────────────────────────────────────────────
SOURCES = {
    "ofac": {
        "label": "OFAC SDN List (USA)",
        "url":   "https://www.treasury.gov/ofac/downloads/sdn.xml",
    },
    "un": {
        "label": "UN Security Council Consolidated List",
        "url":   "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
    },
    "eu": {
        "label": "EU Consolidated Sanctions List",
        "url":   "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw",
    },
    "uk": {
        "label": "UK Sanctions List (FCDO)",
        "url":   "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.xml",  # Updated Jan 2026 — FCDO UKSL replaces OFSI Consolidated List
    },
}

# ── In-memory cache ───────────────────────────────────────────────────────────
_cache = {}

def get_cached(key):
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        log.info(f"Cache HIT for {key}")
        return entry
    return None

def set_cache(key, data, content_type):
    _cache[key] = {"data": data, "ts": time.time(), "content_type": content_type}
    log.info(f"Cache SET for {key} ({len(data)} bytes)")

# ── CORS ──────────────────────────────────────────────────────────────────────
def cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"]  = ALLOWED_ORIGIN
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

def corsify(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return cors_headers(Response("", status=204))
        return cors_headers(f(*args, **kwargs))
    return wrapper

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({
        "service": "The Intel Desk — Sanctions Proxy",
        "status":  "ok",
        "endpoints": [f"/sanctions/{k}" for k in SOURCES],
        "cache_ttl_seconds": CACHE_TTL,
    })

@app.route("/sanctions/<source>", methods=["GET","OPTIONS"])
@corsify
def fetch_sanctions(source):
    if source not in SOURCES:
        return Response('{"error":"Unknown source"}', status=404, mimetype="application/json")

    cached = get_cached(source)
    if cached:
        resp = Response(cached["data"], status=200, mimetype=cached["content_type"])
        resp.headers["X-Cache"] = "HIT"
        resp.headers["X-Cache-Age"] = str(int(time.time() - _cache[source]["ts"]))
        return resp

    src = SOURCES[source]
    log.info(f"Fetching {source} from {src['url']}")
    try:
        upstream = requests.get(src["url"], timeout=FETCH_TIMEOUT,
            headers={"User-Agent": "IntelDesk-SanctionsProxy/1.0"})
        upstream.raise_for_status()
    except requests.exceptions.Timeout:
        return Response('{"error":"Upstream timed out"}', status=504, mimetype="application/json")
    except requests.exceptions.RequestException as e:
        return Response(f'{{"error":"{str(e)}"}}', status=502, mimetype="application/json")

    ct   = upstream.headers.get("Content-Type", "application/xml")
    data = upstream.content
    set_cache(source, data, ct)
    resp = Response(data, status=200, mimetype=ct)
    resp.headers["X-Cache"]  = "MISS"
    resp.headers["X-Source"] = src["label"]
    return resp

@app.route("/sanctions/<source>/status", methods=["GET","OPTIONS"])
@corsify
def source_status(source):
    if source not in SOURCES:
        return Response('{"error":"Unknown source"}', status=404, mimetype="application/json")
    cached = _cache.get(source)
    if cached:
        age = int(time.time() - cached["ts"])
        return jsonify({"source": source, "cached": True,
            "age_seconds": age, "expires_in": max(0, CACHE_TTL - age),
            "size_bytes": len(cached["data"])})
    return jsonify({"source": source, "cached": False})

@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    secret = os.environ.get("CACHE_CLEAR_SECRET","")
    if secret and request.headers.get("X-Secret") != secret:
        return Response('{"error":"Unauthorized"}', status=401, mimetype="application/json")
    _cache.clear()
    return jsonify({"cleared": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)


# ── what3words routes ─────────────────────────────────────────────────────────
W3W_API_KEY = os.environ.get("W3W_API_KEY", "")

@app.route("/w3w", methods=["GET", "OPTIONS"])
@corsify
def what3words_forward():
    """Lat/lng → what3words. Query: ?lat=39.188&lng=-76.815"""
    if not W3W_API_KEY:
        return Response('{"error":"W3W_API_KEY not set"}', status=503, mimetype="application/json")
    lat = request.args.get("lat","").strip()
    lng = request.args.get("lng","").strip()
    if not lat or not lng:
        return Response('{"error":"lat and lng required"}', status=400, mimetype="application/json")
    try:
        r = requests.get("https://api.what3words.com/v3/convert-to-3wa",
            params={"coordinates":f"{lat},{lng}","language":"en","format":"json","key":W3W_API_KEY},
            timeout=8, headers={"User-Agent":"IntelDesk/1.0"})
        r.raise_for_status()
        d = r.json()
        if "words" in d:
            return jsonify({"words":d["words"],"nearestPlace":d.get("nearestPlace",""),"country":d.get("country","")})
        return Response(f'{{"error":"{d.get("error",{}).get("message","w3w error")}"}}', status=400, mimetype="application/json")
    except requests.exceptions.Timeout:
        return Response('{"error":"w3w API timed out"}', status=504, mimetype="application/json")
    except Exception as e:
        return Response(f'{{"error":"{str(e)}"}}', status=502, mimetype="application/json")


@app.route("/w3w-reverse", methods=["GET", "OPTIONS"])
@corsify
def what3words_reverse():
    """what3words → lat/lng. Query: ?words=filled.count.soap"""
    if not W3W_API_KEY:
        return Response('{"error":"W3W_API_KEY not set"}', status=503, mimetype="application/json")
    words = request.args.get("words","").strip().lower().lstrip("/")
    if not words or len(words.split(".")) != 3:
        return Response('{"error":"Provide three dot-separated words"}', status=400, mimetype="application/json")
    try:
        r = requests.get("https://api.what3words.com/v3/convert-to-coordinates",
            params={"words":words,"format":"json","key":W3W_API_KEY},
            timeout=8, headers={"User-Agent":"IntelDesk/1.0"})
        r.raise_for_status()
        d = r.json()
        if "coordinates" in d:
            return jsonify({
                "lat":   d["coordinates"]["lat"],
                "lng":   d["coordinates"]["lng"],
                "words": d.get("words", words),
                "nearestPlace": d.get("nearestPlace",""),
                "country": d.get("country",""),
            })
        return Response(f'{{"error":"{d.get("error",{}).get("message","w3w error")}"}}', status=400, mimetype="application/json")
    except requests.exceptions.Timeout:
        return Response('{"error":"w3w API timed out"}', status=504, mimetype="application/json")
    except Exception as e:
        return Response(f'{{"error":"{str(e)}"}}', status=502, mimetype="application/json")
