"""
influence_tracer.py
===================
Flask Blueprint — CGTN Affiliate Network / Influence Infrastructure Tracer

Registers routes under /influence/:
  POST /influence/analyze   — analyze a single domain
  POST /influence/expand    — expand from a known state actor node
  GET  /influence/ping      — health check

All external calls use free, no-key APIs:
  - ipinfo.io           (IP → ASN, country)
  - crt.sh              (SSL certificate SAN harvest)
  - rdap.org            (WHOIS/RDAP)
  - hackertarget.com    (reverse IP lookup)
  - requests + bs4      (HTML scrape)

Methodology is transparent: every signal returned includes
its source citation from seed_database.json.
"""

import json
import os
import re
import socket
import time
import logging
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from flask import Blueprint, jsonify, request

# ── Setup ─────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

influence_bp = Blueprint("influence", __name__, url_prefix="/influence")

# Load seed database (same directory as this file)
_DB_PATH = os.path.join(os.path.dirname(__file__), "seed_database.json")
try:
    with open(_DB_PATH) as f:
        SEED_DB = json.load(f)
    logger.info("Influence tracer: seed database loaded OK")
except Exception as e:
    logger.error(f"Influence tracer: could not load seed database: {e}")
    SEED_DB = {}

# Request headers — polite bot identification
HEADERS = {
    "User-Agent": "IntelDesk-InfluenceTracer/1.0 (https://inteldesk.io; research tool)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Timeouts for external calls (seconds)
HTTP_TIMEOUT   = 10
SCRAPE_TIMEOUT = 12


# ── Helpers ───────────────────────────────────────────────────────────────────

def clean_domain(raw: str) -> str:
    """Strip protocol, path, and www. from user input."""
    raw = raw.strip().lower()
    if not raw.startswith("http"):
        raw = "https://" + raw
    parsed = urlparse(raw)
    domain = parsed.netloc or parsed.path
    domain = re.sub(r"^www\.", "", domain)
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    return domain


def safe_get(url: str, timeout: int = HTTP_TIMEOUT, **kwargs) -> requests.Response | None:
    """GET with error handling. Returns None on any failure."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        logger.debug(f"safe_get {url}: {e}")
        return None


# ── Signal collectors ─────────────────────────────────────────────────────────

def resolve_ip(domain: str) -> dict:
    """Resolve domain → IP."""
    try:
        ip = socket.gethostbyname(domain)
        return {"ip": ip, "error": None}
    except Exception as e:
        return {"ip": None, "error": str(e)}


def get_asn_info(ip: str) -> dict:
    """
    ipinfo.io free tier — IP → ASN, org, country, city.
    No API key required for basic lookups (up to 50k/month).
    """
    if not ip:
        return {}
    r = safe_get(f"https://ipinfo.io/{ip}/json")
    if not r:
        return {}
    try:
        data = r.json()
        return {
            "ip":      data.get("ip"),
            "org":     data.get("org", ""),       # e.g. "AS37963 Alibaba Cloud"
            "asn":     data.get("org", "").split()[0] if data.get("org") else "",
            "country": data.get("country", ""),
            "city":    data.get("city", ""),
            "region":  data.get("region", ""),
            "hostname":data.get("hostname", ""),
        }
    except Exception:
        return {}


def get_ssl_sans(domain: str) -> list[str]:
    """
    Query crt.sh for all SSL certificate SANs associated with this domain.
    Returns a deduplicated list of related domains from the same certificates.
    Free, no key, run by Sectigo.
    """
    r = safe_get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not r:
        return []
    try:
        certs = r.json()
        sans = set()
        for cert in certs[:50]:  # cap at 50 certs
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name and "." in name and name != domain:
                    sans.add(name)
        return sorted(sans)[:100]  # cap return at 100
    except Exception:
        return []


def get_rdap_whois(domain: str) -> dict:
    """
    RDAP lookup via rdap.org — registrar, registrant org, creation date.
    Free, no key. Returns partial data gracefully on failure.
    """
    r = safe_get(f"https://rdap.org/domain/{domain}")
    if not r:
        return {}
    try:
        data = r.json()
        result = {
            "registrar":       None,
            "registrant_org":  None,
            "created":         None,
            "updated":         None,
            "nameservers":     [],
            "status":          [],
        }
        # Registrar
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if vcard and len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            result["registrar"] = field[3]
            if "registrant" in roles:
                vcard = entity.get("vcardArray", [])
                if vcard and len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "org":
                            result["registrant_org"] = field[3]
        # Dates
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                result["created"] = event.get("eventDate", "")[:10]
            if event.get("eventAction") == "last changed":
                result["updated"] = event.get("eventDate", "")[:10]
        # Nameservers
        result["nameservers"] = [
            ns.get("ldhName", "").lower()
            for ns in data.get("nameservers", [])
        ]
        result["status"] = data.get("status", [])
        return result
    except Exception:
        return {}


def get_reverse_ip(ip: str) -> list[str]:
    """
    HackerTarget reverse IP lookup — find other domains on same IP.
    Free tier: 100 requests/day, no key.
    """
    if not ip:
        return []
    r = safe_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if not r or "error" in r.text.lower():
        return []
    domains = [d.strip() for d in r.text.strip().split("\n") if "." in d]
    return domains[:50]  # cap at 50


def scrape_page_signals(domain: str) -> dict:
    """
    Fetch the homepage and extract:
    - Analytics IDs (GA4, GTM, Yandex, Baidu Tongji, custom)
    - Outbound links to known state media domains
    - WPBakery/CMS fingerprint
    - Presence of Yan Limeng attack article pattern
    - Has editorial staff page
    - Language hints
    """
    result = {
        "reachable":        False,
        "status_code":      None,
        "analytics_ids":    [],
        "outbound_links":   [],
        "cms_signals":      [],
        "content_signals":  [],
        "title":            "",
        "language":         "",
        "error":            None,
    }

    try:
        url = f"https://{domain}"
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=SCRAPE_TIMEOUT,
            allow_redirects=True,
            verify=False,  # some influence sites have dodgy certs
        )
        result["reachable"]   = True
        result["status_code"] = resp.status_code
        html = resp.text

        soup = BeautifulSoup(html, "html.parser")

        # Title
        title_tag = soup.find("title")
        result["title"] = title_tag.get_text(strip=True)[:200] if title_tag else ""

        # Language from html tag or meta
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            result["language"] = html_tag["lang"][:10]

        # ── Analytics ID extraction ──────────────────────────────────────────
        ids_found = []

        # Google Analytics 4 / Universal Analytics
        for match in re.findall(r'["\']?(G-[A-Z0-9]{6,}|UA-\d{5,}-\d+)["\']?', html):
            ids_found.append({"type": "Google Analytics", "id": match})

        # Google Tag Manager
        for match in re.findall(r'["\']?(GTM-[A-Z0-9]{5,})["\']?', html):
            ids_found.append({"type": "Google Tag Manager", "id": match})

        # Yandex Metrica
        for match in re.findall(r'ym\((\d{7,}),\s*["\']init["\']', html):
            ids_found.append({"type": "Yandex Metrica", "id": match})

        # Baidu Tongji
        for match in re.findall(r'hm\.baidu\.com/hm\.js\?([a-f0-9]{32})', html):
            ids_found.append({"type": "Baidu Tongji", "id": match})

        # Haimai / custom ad IDs (pattern from CL-174 methodology)
        for match in re.findall(r'["\']?(haimai[_\-]?[a-z0-9]{4,})["\']?', html, re.IGNORECASE):
            ids_found.append({"type": "Haimai Ad ID", "id": match, "weight": "critical"})

        # Deduplicate
        seen = set()
        for item in ids_found:
            key = f"{item['type']}:{item['id']}"
            if key not in seen:
                seen.add(key)
                result["analytics_ids"].append(item)

        # ── Outbound links to known state media ─────────────────────────────
        state_media_domains = [
            "cgtn.com", "xinhuanet.com", "globaltimes.cn", "chinadaily.com.cn",
            "people.com.cn", "cri.cn", "timesnewswire.com",
            "rt.com", "tass.ru", "sputniknews.com", "ria.ru", "lenta.ru",
        ]
        links_found = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            for sm in state_media_domains:
                if sm in href:
                    links_found.add(sm)
        result["outbound_links"] = sorted(links_found)

        # ── CMS / template fingerprinting ────────────────────────────────────
        cms = []
        if "wpbakery" in html.lower() or "vc_row" in html or "wpb_wrapper" in html:
            cms.append({"signal": "wpbakery", "description": "WPBakery page builder detected"})
        if "wp-content" in html or "wp-includes" in html:
            cms.append({"signal": "wordpress", "description": "WordPress detected"})
        if "drupal" in html.lower():
            cms.append({"signal": "drupal", "description": "Drupal detected"})
        result["cms_signals"] = cms

        # ── Content signals ──────────────────────────────────────────────────
        content = []
        html_lower = html.lower()

        if "yan limeng" in html_lower or "yan li-meng" in html_lower:
            content.append({
                "signal":   "yan_limeng_article",
                "weight":   "critical",
                "source":   "CL-174",
                "note":     "Article attacking Li-Meng Yan found. Present on every active PAPERWALL site as of Dec 2023."
            })

        # Check for absence of editorial staff (heuristic)
        has_about   = bool(soup.find("a", href=re.compile(r'about|contact|team|staff|editorial', re.I)))
        has_bylines = bool(soup.find(attrs={"class": re.compile(r'author|byline|reporter', re.I)}))
        if not has_about and not has_bylines:
            content.append({
                "signal": "no_editorial_staff",
                "weight": "low",
                "note":   "No author bylines, About page, or contact info detected."
            })

        result["content_signals"] = content

    except requests.exceptions.SSLError:
        result["error"] = "SSL certificate error (may indicate dodgy cert)"
        result["reachable"] = True  # site exists but cert is bad — still signal
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:120]}"
    except Exception as e:
        result["error"] = f"Scrape error: {str(e)[:120]}"

    return result


# ── Scoring engine ─────────────────────────────────────────────────────────────

def compute_score(signals: dict) -> dict:
    """
    Calculate confidence score from collected signals.
    Returns score (0-100), label, color, and per-signal breakdown.
    """
    weights = SEED_DB.get("scoring", {}).get("weights", {})
    thresholds = SEED_DB.get("scoring", {}).get("thresholds", {})

    score     = 0
    breakdown = []

    def add(key: str, label: str, source: str = "", note: str = ""):
        nonlocal score
        w = weights.get(key, 0)
        score += w
        breakdown.append({
            "signal": key,
            "label":  label,
            "points": w,
            "source": source,
            "note":   note,
        })

    # Database match
    db_match = signals.get("db_match", {})
    if db_match.get("tier") == "tier1":
        add("database_match_tier1", "Confirmed state media (Tier 1)", db_match.get("source",""))
    elif db_match.get("tier") == "tier2":
        add("database_match_tier2", "Confirmed affiliate (Tier 2)", db_match.get("source",""))

    # ASN
    asn_info = signals.get("asn_info", {})
    asn = asn_info.get("asn", "")
    org = asn_info.get("org", "").lower()
    if asn in ("AS37963",) or "alibaba" in org:
        add("alibaba_cloud_asn", "Hosted on Alibaba Cloud (CN)", "GRAPHIKA-FA",
            "All 11 Falsos Amigos domains registered/hosted via Alibaba Cloud.")
    elif asn in ("AS45090",) or "tencent" in org:
        add("tencent_cloud_asn", "Hosted on Tencent Cloud (CN)", "CL-174",
            "PAPERWALL Italian domains hosted on Tencent Cloud.")
    elif asn_info.get("country") == "CN":
        if asn in ("AS58461", "AS4134", "AS55967", "AS4837"):
            add("other_cn_state_asn", "Hosted on Chinese state-affiliated ASN", "public-record")

    # Russian ASNs
    if asn in ("AS197695",):
        add("ru_state_asn_high", "Hosted on TigerWeb-linked ASN", "DFRLAB-PV",
            "TigerWeb is the Crimea-based IT company behind the Pravda network.")
    elif asn in ("AS8334",):
        add("ru_state_asn_medium", "Hosted on Russian state-flagged ASN", "DFRLAB-PV")

    # SSL SANs overlap with known domains
    san_overlap = signals.get("ssl_san_overlap", [])
    if san_overlap:
        add("ssl_san_overlap_with_known", "SSL certificate shares domains with known affiliates",
            "methodology", f"Overlapping SANs: {', '.join(san_overlap[:5])}")

    # Reverse IP neighbors overlap
    rip_overlap = signals.get("reverse_ip_overlap", [])
    if rip_overlap:
        add("reverse_ip_neighbor_known", "Shares IP with known affiliated domain",
            "methodology", f"Co-hosted with: {', '.join(rip_overlap[:3])}")

    # Scrape signals
    scrape = signals.get("scrape", {})
    outbound = scrape.get("outbound_links", [])

    if "cgtn.com" in outbound:
        add("cgtn_backlink", "Outbound link to CGTN", "CL-174, GRAPHIKA-FA",
            "95 PAPERWALL domains + all Falsos Amigos sites linked to CGTN.")
    if "timesnewswire.com" in outbound:
        add("timesnewswire_backlink", "Outbound link to Times Newswire", "CL-174",
            "98/123 PAPERWALL domains backlinked to Times Newswire.")
    if "globaltimes.cn" in outbound:
        add("globaltimes_backlink", "Outbound link to Global Times", "CL-174",
            "86 PAPERWALL domains backlinked to Global Times.")
    if "rt.com" in outbound:
        add("rt_backlink", "Outbound link to RT (Russia Today)", "DFRLAB-PV")
    if "tass.ru" in outbound:
        add("tass_backlink", "Outbound link to TASS", "DFRLAB-PV")

    # CMS
    cms_signals = scrape.get("cms_signals", [])
    cms_names = [c["signal"] for c in cms_signals]
    if "wpbakery" in cms_names:
        add("wpbakery_fingerprint", "WPBakery page builder (PAPERWALL template signature)", "CL-174")

    # Content signals
    for cs in scrape.get("content_signals", []):
        if cs["signal"] == "yan_limeng_article":
            add("yan_limeng_article", "Li-Meng Yan attack article detected", "CL-174",
                "Present verbatim on every active PAPERWALL site.")
        if cs["signal"] == "no_editorial_staff":
            add("no_editorial_staff", "No editorial staff, bylines, or contact info", "CL-174, GRAPHIKA-FA")

    # Analytics IDs
    analytics = scrape.get("analytics_ids", [])
    for a in analytics:
        if a["type"] == "Haimai Ad ID":
            add("shared_analytics_id", "Haimai advertising ID detected", "CL-174",
                "This is the primary attribution signal linking PAPERWALL to Haimai (Shenzhen PR firm).")
        if a["type"] == "Yandex Metrica":
            add("shared_analytics_id", "Yandex Metrica analytics (Russian)", "methodology")
        if a["type"] == "Baidu Tongji":
            add("shared_analytics_id", "Baidu Tongji analytics (Chinese)", "methodology")

    # Pravda domain pattern
    domain = signals.get("domain", "")
    if re.search(r"pravda[-.]|[-.]pravda\.|news-pravda", domain):
        add("pravda_pattern_domain", "Domain matches Pravda network naming pattern", "DFRLAB-PV, VIGINUM-PK")

    # WHOIS: batch registration check (flagged externally)
    if signals.get("batch_registration_flag"):
        add("batch_registration_window", "Registered in batch window with other flagged domains", "CL-174")

    # Cap at 100
    score = min(score, 100)

    # Determine label/color
    label = "No significant signals"
    color = "#4ec994"
    icon  = "✓"
    for range_key, props in thresholds.items():
        lo, hi = map(int, range_key.split("-"))
        if lo <= score <= hi:
            label = props["label"]
            color = props["color"]
            icon  = props["icon"]
            break

    return {
        "score":     score,
        "label":     label,
        "color":     color,
        "icon":      icon,
        "breakdown": breakdown,
    }


# ── Database lookup ────────────────────────────────────────────────────────────

def check_database(domain: str) -> dict:
    """Check domain against the seed database."""
    match = {"tier": None, "name": None, "notes": None, "source": None}

    for nation in ("cn", "ru"):
        nd = SEED_DB.get(nation, {})

        for entry in nd.get("tier1_state_media", []):
            if entry["domain"] == domain or domain.endswith("." + entry["domain"]):
                return {"tier": "tier1", "nation": nation,
                        "name": entry["name"], "source": entry["source"],
                        "notes": f"Confirmed {nation.upper()} state media."}

        for entry in nd.get("tier2_confirmed_affiliates", []):
            if entry["domain"] == domain or domain.endswith("." + entry["domain"]):
                return {"tier": "tier2", "nation": nation,
                        "name": entry["name"], "source": entry["source"],
                        "notes": entry.get("notes", "")}

        for d in nd.get("paperwall_sample_domains", {}).get("domains", []):
            if d == domain:
                return {"tier": "tier2", "nation": "cn",
                        "name": "PAPERWALL domain", "source": "CL-174",
                        "notes": "Confirmed PAPERWALL network domain (Citizen Lab Report 174)."}

    return match


def find_san_overlap(sans: list[str]) -> list[str]:
    """Check SSL SANs against known affiliated domains."""
    known = set()
    for nation in ("cn", "ru"):
        nd = SEED_DB.get(nation, {})
        for e in nd.get("tier1_state_media", []):
            known.add(e["domain"])
        for e in nd.get("tier2_confirmed_affiliates", []):
            known.add(e["domain"])
        for d in nd.get("paperwall_sample_domains", {}).get("domains", []):
            known.add(d)

    return [s for s in sans if any(s == k or s.endswith("." + k) for k in known)]


def find_rip_overlap(neighbors: list[str]) -> list[str]:
    """Check reverse-IP neighbors against known affiliated domains."""
    known = set()
    for nation in ("cn", "ru"):
        nd = SEED_DB.get(nation, {})
        for e in nd.get("tier1_state_media", []):
            known.add(e["domain"])
        for e in nd.get("tier2_confirmed_affiliates", []):
            known.add(e["domain"])

    return [n for n in neighbors if any(n == k or n.endswith("." + k) for k in known)]


# ── Main analysis pipeline ─────────────────────────────────────────────────────

def analyze_domain(domain: str) -> dict:
    """
    Full pipeline for a single domain.
    Returns a structured result dict.
    """
    domain = clean_domain(domain)
    result = {
        "domain":       domain,
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "db_match":     {},
        "ip_info":      {},
        "asn_info":     {},
        "whois":        {},
        "ssl_sans":     [],
        "ssl_san_overlap": [],
        "reverse_ip":   [],
        "reverse_ip_overlap": [],
        "scrape":       {},
        "score":        {},
        "error":        None,
    }

    try:
        # 1. Database check (instant)
        result["db_match"] = check_database(domain)

        # 2. Resolve IP
        ip_result = resolve_ip(domain)
        result["ip_info"] = ip_result

        # 3. ASN / geo
        if ip_result["ip"]:
            result["asn_info"] = get_asn_info(ip_result["ip"])

        # 4. WHOIS/RDAP
        result["whois"] = get_rdap_whois(domain)

        # 5. SSL SANs
        sans = get_ssl_sans(domain)
        result["ssl_sans"] = sans
        result["ssl_san_overlap"] = find_san_overlap(sans)

        # 6. Reverse IP
        if ip_result["ip"]:
            neighbors = get_reverse_ip(ip_result["ip"])
            result["reverse_ip"] = neighbors
            result["reverse_ip_overlap"] = find_rip_overlap(neighbors)

        # 7. HTML scrape
        result["scrape"] = scrape_page_signals(domain)

        # 8. Score
        result["score"] = compute_score({
            "domain":               domain,
            "db_match":             result["db_match"],
            "asn_info":             result["asn_info"],
            "ssl_san_overlap":      result["ssl_san_overlap"],
            "reverse_ip_overlap":   result["reverse_ip_overlap"],
            "scrape":               result["scrape"],
        })

    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"analyze_domain({domain}) failed")

    return result


# ── Expand pipeline (top-down from known state actor) ─────────────────────────

def expand_from_actor(actor_domain: str, depth: int = 1) -> dict:
    """
    Start from a known state media domain (e.g. cgtn.com) and find
    infrastructure neighbors:
      - SSL SANs
      - Reverse IP neighbors
      - Analyze each neighbor at depth=1

    depth=1 means: analyze the actor, find neighbors, analyze neighbors.
    depth=2 would go one level further (expensive — not enabled by default).
    """
    actor_domain = clean_domain(actor_domain)
    result = {
        "root":     actor_domain,
        "nodes":    [],
        "edges":    [],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Analyze root
    root_analysis = analyze_domain(actor_domain)
    root_node = {
        "id":       actor_domain,
        "label":    actor_domain,
        "type":     "root",
        "analysis": root_analysis,
    }
    result["nodes"].append(root_node)

    # Collect neighbors from SSL SANs + reverse IP
    neighbors = set()
    for san in root_analysis.get("ssl_sans", [])[:30]:
        neighbors.add(san)
        result["edges"].append({
            "source": actor_domain, "target": san,
            "signal": "ssl_san", "label": "SSL SAN",
        })
    for rip in root_analysis.get("reverse_ip", [])[:20]:
        neighbors.add(rip)
        result["edges"].append({
            "source": actor_domain, "target": rip,
            "signal": "shared_ip", "label": "Shared IP",
        })

    # Analyze each neighbor (depth=1, capped at 15 to avoid timeout)
    for neighbor in list(neighbors)[:15]:
        if neighbor == actor_domain:
            continue
        try:
            analysis = analyze_domain(neighbor)
            result["nodes"].append({
                "id":       neighbor,
                "label":    neighbor,
                "type":     "neighbor",
                "analysis": analysis,
            })
            time.sleep(0.3)  # be polite
        except Exception as e:
            logger.debug(f"expand neighbor {neighbor}: {e}")

    return result


# ── Flask routes ───────────────────────────────────────────────────────────────

@influence_bp.route("/ping", methods=["GET"])
def ping():
    db_loaded = bool(SEED_DB)
    return jsonify({
        "status":    "ok",
        "db_loaded": db_loaded,
        "cn_tier1":  len(SEED_DB.get("cn", {}).get("tier1_state_media", [])),
        "ru_tier1":  len(SEED_DB.get("ru", {}).get("tier1_state_media", [])),
    })


@influence_bp.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return _cors_preflight()

    data   = request.get_json(force=True, silent=True) or {}
    domain = (data.get("domain") or "").strip()

    if not domain:
        return jsonify({"error": "domain parameter required"}), 400

    # Basic sanity check
    if len(domain) > 253 or not re.match(r'^[a-zA-Z0-9._\-/:\[\]]+$', domain):
        return jsonify({"error": "Invalid domain format"}), 400

    result = analyze_domain(domain)
    return jsonify(result)


@influence_bp.route("/expand", methods=["POST", "OPTIONS"])
def expand():
    if request.method == "OPTIONS":
        return _cors_preflight()

    data   = request.get_json(force=True, silent=True) or {}
    domain = (data.get("domain") or "").strip()
    depth  = int(data.get("depth", 1))

    if not domain:
        return jsonify({"error": "domain parameter required"}), 400

    depth = max(1, min(depth, 1))  # lock to 1 for now
    result = expand_from_actor(domain, depth=depth)
    return jsonify(result)


def _cors_preflight():
    from flask import Response
    r = Response()
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return r, 200
