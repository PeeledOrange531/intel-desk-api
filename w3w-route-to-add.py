# ─────────────────────────────────────────────────────────────────────────────
# ADD THESE TWO BLOCKS TO YOUR EXISTING app.py ON RENDER
# ─────────────────────────────────────────────────────────────────────────────
#
# BLOCK 1 — Add this near the top of app.py, after your other imports:
#
#   W3W_API_KEY = os.environ.get("W3W_API_KEY", "")
#
#
# BLOCK 2 — Add this route anywhere after your existing routes:

@app.route("/w3w", methods=["GET", "OPTIONS"])
@corsify
def what3words():
    """
    Convert lat/lng to a what3words address.
    Query params: ?lat=39.188756&lng=-76.815275
    Returns: { "words": "filled.count.soap", "nearestPlace": "..." }
    """
    if not W3W_API_KEY:
        return jsonify({"error": "W3W_API_KEY not configured on server"}), 503

    lat = request.args.get("lat", "").strip()
    lng = request.args.get("lng", "").strip()

    if not lat or not lng:
        return jsonify({"error": "lat and lng parameters required"}), 400

    try:
        float(lat); float(lng)
    except ValueError:
        return jsonify({"error": "lat and lng must be numeric"}), 400

    try:
        resp = requests.get(
            "https://api.what3words.com/v3/convert-to-3wa",
            params={
                "coordinates": f"{lat},{lng}",
                "language":    "en",
                "format":      "json",
                "key":         W3W_API_KEY,
            },
            timeout=8,
            headers={"User-Agent": "IntelDesk-CoordConverter/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()

        if "words" in data:
            return jsonify({
                "words":        data["words"],
                "nearestPlace": data.get("nearestPlace", ""),
                "country":      data.get("country", ""),
                "language":     data.get("language", "en"),
            })
        else:
            err = data.get("error", {}).get("message", "Unknown w3w error")
            return jsonify({"error": err}), 400

    except requests.exceptions.Timeout:
        return jsonify({"error": "what3words API timed out"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 502
