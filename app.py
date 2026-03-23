import subprocess
import sys
import os
from flask import Flask, Response, request, jsonify
from flask_cors import CORS
import json
import threading
import queue

app = Flask(__name__)
CORS(app, origins="*")

def stream_command(cmd, q):
    """Run a shell command and stream output line by line into a queue."""
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False
        )
        for line in iter(process.stdout.readline, ''):
            q.put(line)
        process.stdout.close()
        process.wait()
        q.put(None)  # sentinel
    except Exception as e:
        q.put(f"[error] {str(e)}\n")
        q.put(None)

def generate_stream(cmd):
    """Generator that yields SSE-formatted lines from a command."""
    q = queue.Queue()
    t = threading.Thread(target=stream_command, args=(cmd, q))
    t.daemon = True
    t.start()
    while True:
        line = q.get()
        if line is None:
            yield "data: [DONE]\n\n"
            break
        # strip ANSI color codes
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
        yield f"data: {json.dumps(clean)}\n\n"

# ── HEALTH CHECK ──────────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({"status": "ok", "service": "The Intel Desk API"})

# ── EMAIL TOOLS ───────────────────────────────────────────────
@app.route("/api/holehe")
def holehe():
    email = request.args.get("email", "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email"}), 400
    cmd = [sys.executable, "-m", "holehe", email, "--no-color"]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

@app.route("/api/ghunt")
def ghunt():
    email = request.args.get("email", "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email"}), 400
    cmd = [sys.executable, "-m", "ghunt", "email", email]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

@app.route("/api/theharvester")
def theharvester():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    cmd = ["theHarvester", "-d", domain, "-b", "all", "-l", "100"]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

# ── USERNAME TOOLS ────────────────────────────────────────────
@app.route("/api/sherlock")
def sherlock():
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"error": "Invalid username"}), 400
    cmd = [sys.executable, "-m", "sherlock", username, "--print-found", "--no-color"]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

@app.route("/api/maigret")
def maigret():
    username = request.args.get("username", "").strip()
    if not username:
        return jsonify({"error": "Invalid username"}), 400
    cmd = [sys.executable, "-m", "maigret", username, "--no-color", "--timeout", "15"]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

# ── PHONE TOOLS ───────────────────────────────────────────────
@app.route("/api/phoneinfoga")
def phoneinfoga():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"error": "Invalid number"}), 400
    cmd = ["phoneinfoga", "scan", "-n", number]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

@app.route("/api/ignorant")
def ignorant():
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"error": "Invalid number"}), 400
    cmd = [sys.executable, "-m", "ignorant", number, "--no-color"]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

# ── DOMAIN / IP TOOLS ─────────────────────────────────────────
@app.route("/api/subfinder")
def subfinder():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    cmd = ["subfinder", "-d", domain, "-silent"]
    return Response(generate_stream(cmd), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})

# ── PUBLIC API TOOLS (no CLI needed) ─────────────────────────
@app.route("/api/hudsonrock")
def hudsonrock():
    import urllib.request
    email = request.args.get("email", "").strip()
    if not email:
        return jsonify({"error": "Invalid email"}), 400
    try:
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?username={email}"
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read())
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/emailrep")
def emailrep():
    import urllib.request
    email = request.args.get("email", "").strip()
    if not email:
        return jsonify({"error": "Invalid email"}), 400
    try:
        req = urllib.request.Request(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "TheIntelDesk/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ipinfo")
def ipinfo():
    import urllib.request
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "Invalid IP"}), 400
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=10) as r:
            data = json.loads(r.read())
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/abuseipdb")
def abuseipdb():
    import urllib.request
    ip = request.args.get("ip", "").strip()
    key = os.environ.get("ABUSEIPDB_KEY", "")
    if not ip:
        return jsonify({"error": "Invalid IP"}), 400
    if not key:
        return jsonify({"error": "AbuseIPDB API key not configured"}), 500
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": key, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
