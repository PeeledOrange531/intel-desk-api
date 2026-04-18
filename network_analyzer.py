"""
network_analyzer.py
===================
Flask Blueprint — Network Analyzer (formerly Influence Network Tracer)

Registers routes under /network/:
  POST /network/analyze   — analyze a single domain, returns 5-dimension scores
  POST /network/expand    — expand from any seed domain
  GET  /network/ping      — health check

Philosophy: graph-first network cartography, nation-neutral.
Every domain — BBC, RT, CGTN, VOA, Al Jazeera — is analyzed on
the same five dimensions. The tool maps networks. Analysts interpret.

Five scoring dimensions (0–10 each):
  1. infrastructure_opacity   — hidden WHOIS, anonymous registrant, batch reg,
                                 opaque hosting chain
  2. ownership_transparency   — named staff, About/Contact pages, disclosed
                                 funding, verifiable legal entity (inverted:
                                 high score = LOW transparency = more opaque)
  3. content_sourcing         — original reporting vs. republished state media
                                 vs. AI-summarized content without attribution
  4. network_centrality       — connection density in the graph being built
                                 (computed client-side, seeded here as 0)
  5. state_media_proximity    — links to / shares infrastructure with ANY
                                 known state media, any country, neutral signal

All external calls use free, no-key APIs.
Methodology citations included on every signal.
"""

import json
import os
import re
import socket
import time
import logging
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from flask import Blueprint, jsonify, request

# ── Setup ──────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

network_bp = Blueprint("network", __name__, url_prefix="/network")

_DB_PATH = os.path.join(os.path.dirname(__file__), "network_database.json")
try:
    with open(_DB_PATH) as f:
        NET_DB = json.load(f)
    logger.info("Network analyzer: database loaded OK")
except Exception as e:
    logger.error(f"Network analyzer: could not load database: {e}")
    NET_DB = {}

HEADERS = {
    "User-Agent": "IntelDesk-NetworkAnalyzer/1.0 (https://inteldesk.io; research tool)",
    "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

HTTP_TIMEOUT   = 10
SCRAPE_TIMEOUT = 14


# ── Helpers ────────────────────────────────────────────────────────────────────

def clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if not raw.startswith("http"):
        raw = "https://" + raw
    parsed = urlparse(raw)
    domain = parsed.netloc or parsed.path
    domain = re.sub(r"^www\.", "", domain)
    return domain.split("/")[0].split("?")[0].split("#")[0]


def safe_get(url: str, timeout: int = HTTP_TIMEOUT, **kwargs):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        logger.debug(f"safe_get {url}: {e}")
        return None


# ── Infrastructure collectors ──────────────────────────────────────────────────

def resolve_ip(domain: str) -> dict:
    try:
        ip = socket.gethostbyname(domain)
        return {"ip": ip, "error": None}
    except Exception as e:
        return {"ip": None, "error": str(e)}


def get_asn_info(ip: str) -> dict:
    if not ip:
        return {}
    r = safe_get(f"https://ipinfo.io/{ip}/json")
    if not r:
        return {}
    try:
        d = r.json()
        org = d.get("org", "")
        return {
            "ip":      d.get("ip"),
            "org":     org,
            "asn":     org.split()[0] if org else "",
            "country": d.get("country", ""),
            "city":    d.get("city", ""),
            "hostname":d.get("hostname", ""),
        }
    except Exception:
        return {}


def get_ssl_sans(domain: str) -> list:
    r = safe_get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not r:
        return []
    try:
        certs = r.json()
        sans  = set()
        for cert in certs[:60]:
            for name in cert.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and "." in name and name != domain:
                    sans.add(name)
        return sorted(sans)[:100]
    except Exception:
        return []


def get_rdap_whois(domain: str) -> dict:
    r = safe_get(f"https://rdap.org/domain/{domain}")
    if not r:
        return {}
    try:
        data   = r.json()
        result = {
            "registrar":            None,
            "registrar_country":    None,
            "registrant_org":       None,
            "registrant_country":   None,
            "registrant_email":     None,
            "privacy_protected":    False,
            "created":              None,
            "updated":              None,
            "nameservers":          [],
            "status":               [],
        }

        def extract_vcard(entity):
            out = {}
            vcard = entity.get("vcardArray", [])
            if not vcard or len(vcard) < 2:
                return out
            for field in vcard[1]:
                if not field or len(field) < 4:
                    continue
                fn, fv = field[0], field[3]
                if fn == "fn":
                    out["name"] = fv
                elif fn == "org":
                    out["org"] = fv
                elif fn == "email":
                    out["email"] = fv
                elif fn == "adr":
                    if isinstance(fv, list) and len(fv) >= 7:
                        out["country"] = str(fv[6]).strip()
                    elif isinstance(fv, str):
                        out["country"] = fv.strip()
                elif fn == "country-name":
                    out["country"] = fv
            return out

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vc    = extract_vcard(entity)

            if "registrar" in roles:
                result["registrar"]         = vc.get("name") or vc.get("org")
                result["registrar_country"] = vc.get("country")

            if "registrant" in roles:
                result["registrant_org"]     = vc.get("org") or vc.get("name")
                result["registrant_country"] = vc.get("country")
                result["registrant_email"]   = vc.get("email")
                # Privacy-protected WHOIS: registrant name/org is a proxy service
                org_lower = (result["registrant_org"] or "").lower()
                privacy_keywords = [
                    "privacy", "redacted", "whoisguard", "domains by proxy",
                    "contact privacy", "withheld", "data protected",
                    "registrant redacted", "gdpr", "not disclosed",
                ]
                if any(kw in org_lower for kw in privacy_keywords):
                    result["privacy_protected"] = True

            for sub in entity.get("entities", []):
                sub_vc = extract_vcard(sub)
                if "registrant" in sub.get("roles", []):
                    result["registrant_org"]     = result["registrant_org"] or sub_vc.get("org")
                    result["registrant_country"] = result["registrant_country"] or sub_vc.get("country")

        for event in data.get("events", []):
            action = event.get("eventAction", "")
            if action == "registration":
                result["created"] = event.get("eventDate", "")[:10]
            elif action == "last changed":
                result["updated"] = event.get("eventDate", "")[:10]

        result["nameservers"] = [
            ns.get("ldhName", "").lower()
            for ns in data.get("nameservers", [])
        ]
        result["status"] = data.get("status", [])
        return result
    except Exception:
        return {}


def get_reverse_ip(ip: str) -> list:
    if not ip:
        return []
    r = safe_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if not r or "error" in r.text.lower():
        return []
    return [d.strip() for d in r.text.strip().split("\n") if "." in d][:50]


# ── Page scraper — expanded for new dimensions ─────────────────────────────────

def scrape_page(domain: str) -> dict:
    """
    Scrape the domain homepage and up to one internal page (About/Contact).
    Returns signals for all five scoring dimensions.
    """
    result = {
        "reachable":            False,
        "status_code":          None,
        "title":                "",
        "language":             "",
        # Analytics
        "analytics_ids":        [],
        # Outbound links (all state media, neutral)
        "state_media_links":    [],   # [{domain, name, category}]
        # CMS
        "cms":                  [],
        # Ownership transparency signals
        "has_about_page":       False,
        "has_contact_page":     False,
        "has_named_authors":    False,
        "has_bylines":          False,
        "has_legal_entity":     False,
        "has_funding_disclosure": False,
        "editorial_staff_count":  0,
        # Content sourcing signals
        "content_sourcing":     [],   # [{type, detail, source}]
        "avg_article_length":   None,
        "has_original_reporting_signals": False,
        # Infrastructure signals (from HTML)
        "shared_id_signals":    [],   # same analytics ID as known network
        "error":                None,
    }

    try:
        url  = f"https://{domain}"
        resp = requests.get(
            url, headers=HEADERS, timeout=SCRAPE_TIMEOUT,
            allow_redirects=True, verify=False,
        )
        result["reachable"]   = True
        result["status_code"] = resp.status_code
        html  = resp.text
        soup  = BeautifulSoup(html, "html.parser")

        # ── Basic metadata ─────────────────────────────────────────────────────
        title_tag = soup.find("title")
        result["title"] = title_tag.get_text(strip=True)[:200] if title_tag else ""

        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            result["language"] = html_tag["lang"][:10]

        # ── Analytics IDs ──────────────────────────────────────────────────────
        ids_found = []
        for m in re.findall(r'["\']?(G-[A-Z0-9]{6,}|UA-\d{5,}-\d+)["\']?', html):
            ids_found.append({"type": "Google Analytics", "id": m})
        for m in re.findall(r'["\']?(GTM-[A-Z0-9]{5,})["\']?', html):
            ids_found.append({"type": "Google Tag Manager", "id": m})
        for m in re.findall(r'ym\((\d{7,}),\s*["\']init["\']', html):
            ids_found.append({"type": "Yandex Metrica", "id": m})
        for m in re.findall(r'hm\.baidu\.com/hm\.js\?([a-f0-9]{32})', html):
            ids_found.append({"type": "Baidu Tongji", "id": m})
        for m in re.findall(r'["\']?(haimai[_\-]?[a-z0-9]{4,})["\']?', html, re.IGNORECASE):
            ids_found.append({"type": "Haimai Ad ID", "id": m})
        # WeChat (Chinese social integration)
        if "weixin.qq.com" in html or "wx.qq.com" in html:
            ids_found.append({"type": "WeChat Integration", "id": "weixin.qq.com"})
        # VK (Russian social)
        if "vk.com/js" in html or "vk.com/widget" in html:
            ids_found.append({"type": "VKontakte Integration", "id": "vk.com"})
        # Deduplicate
        seen = set()
        for item in ids_found:
            key = f"{item['type']}:{item['id']}"
            if key not in seen:
                seen.add(key)
                result["analytics_ids"].append(item)

        # ── State media outbound links — NEUTRAL, covers ALL countries ─────────
        all_state_media = NET_DB.get("state_media_registry", {})
        links_found = {}
        for a in soup.find_all("a", href=True):
            href = a["href"].lower()
            for sm_domain, sm_info in all_state_media.items():
                if sm_domain in href and sm_domain not in links_found:
                    links_found[sm_domain] = {
                        "domain":   sm_domain,
                        "name":     sm_info.get("name", sm_domain),
                        "country":  sm_info.get("country", "?"),
                        "category": sm_info.get("category", "state_media"),
                    }
        result["state_media_links"] = list(links_found.values())

        # ── CMS fingerprinting ─────────────────────────────────────────────────
        cms = []
        if "wpbakery" in html.lower() or "vc_row" in html or "wpb_wrapper" in html:
            cms.append({"signal": "wpbakery",   "note": "WPBakery (PAPERWALL signature)"})
        if "wp-content" in html or "wp-includes" in html:
            cms.append({"signal": "wordpress",  "note": "WordPress"})
        if "drupal" in html.lower():
            cms.append({"signal": "drupal",     "note": "Drupal"})
        if "joomla" in html.lower():
            cms.append({"signal": "joomla",     "note": "Joomla"})
        result["cms"] = cms

        # ── Ownership transparency signals ─────────────────────────────────────
        all_links   = [a.get("href", "").lower() for a in soup.find_all("a", href=True)]
        all_text    = soup.get_text(separator=" ", strip=True).lower()
        all_links_s = " ".join(all_links)

        result["has_about_page"]   = bool(re.search(r'/about|/who-we-are|/our-story|/about-us', all_links_s))
        result["has_contact_page"] = bool(re.search(r'/contact|/reach-us|/write-to-us', all_links_s))

        # Named bylines / author pages
        byline_els = soup.find_all(attrs={"class": re.compile(
            r'author|byline|reporter|journalist|contributor|written.by|post.author', re.I
        )})
        result["has_bylines"] = len(byline_els) > 0

        # Named staff — look for author links with person-like paths
        author_links = [a for a in soup.find_all("a", href=True)
                        if re.search(r'/author/|/reporter/|/journalist/|/staff/', a.get("href",""), re.I)]
        result["editorial_staff_count"] = len(set(a.get("href") for a in author_links))
        result["has_named_authors"]     = result["editorial_staff_count"] > 0

        # Legal entity disclosure
        legal_patterns = [
            r'\bltd\b', r'\bllc\b', r'\binc\b', r'\bgmbh\b', r'\bs\.a\b',
            r'registered in', r'company number', r'registered charity',
            r'press freedom', r'editorial independence',
        ]
        result["has_legal_entity"] = any(
            re.search(p, all_text, re.I) for p in legal_patterns
        )

        # Funding disclosure
        funding_patterns = [
            r'funded by', r'supported by', r'sponsored by',
            r'license fee', r'public funding', r'government funded',
            r'independent funding', r'reader supported',
            r'nonprofit', r'non-profit', r'charitable',
        ]
        result["has_funding_disclosure"] = any(
            re.search(p, all_text, re.I) for p in funding_patterns
        )

        # ── Content sourcing signals ───────────────────────────────────────────
        sourcing = []

        # Explicit attribution to state media in article text
        state_media_names = [
            sm.get("name", "") for sm in all_state_media.values()
        ]
        for name in state_media_names:
            if name and name.lower() in all_text:
                # Check context: is it citation or is it the site itself?
                pattern = rf'(via|source|from|according to|reports?|cited?)\s+{re.escape(name.lower())}'
                if re.search(pattern, all_text, re.I):
                    sourcing.append({
                        "type":   "attributed_republication",
                        "detail": f"Content attributed to {name}",
                        "source": "content_analysis",
                    })
                else:
                    sourcing.append({
                        "type":   "state_media_reference",
                        "detail": f"Reference to {name} in page text",
                        "source": "content_analysis",
                    })

        # Verbatim PAPERWALL article patterns (very specific)
        paperwall_patterns = [
            ("yan limeng",          "yan_limeng_article",
             "Yan Limeng attack article (present on every active PAPERWALL site)", "CL-174"),
            ("yan li-meng",         "yan_limeng_article",
             "Yan Limeng attack article variant", "CL-174"),
            ("haimai",              "haimai_reference",
             "Haimai (PAPERWALL operator) reference in content", "CL-174"),
        ]
        html_lower = html.lower()
        for pattern, sig_type, note, source in paperwall_patterns:
            if pattern in html_lower:
                sourcing.append({
                    "type":   sig_type,
                    "detail": note,
                    "source": source,
                })

        # AI content signals — look for AI disclosure or AI artifact patterns
        ai_patterns = [
            r'generated by ai', r'ai.generated', r'written by ai',
            r'this article was (created|generated|produced) (by|using|with)',
        ]
        if any(re.search(p, all_text, re.I) for p in ai_patterns):
            sourcing.append({
                "type":   "ai_generated_content",
                "detail": "AI content generation disclosure or artifact detected",
                "source": "content_analysis",
            })

        # Press release heavy (indicator of paid content laundering)
        if all_text.count("press release") > 3:
            sourcing.append({
                "type":   "press_release_heavy",
                "detail": "High press release density — possible content laundering",
                "source": "content_analysis",
            })

        # Original reporting signals (reduce sourcing score)
        original_signals = [
            r'\bexclusive\b', r'\binvestigat', r'\bsource[s]? told\b',
            r'\bsaid in an? interview\b', r'\bconfirmed to\b',
            r'\baccording to documents\b', r'\bobtained by\b',
        ]
        if any(re.search(p, all_text, re.I) for p in original_signals):
            sourcing.append({
                "type":   "original_reporting",
                "detail": "Indicators of original reporting detected",
                "source": "content_analysis",
            })
            result["has_original_reporting_signals"] = True

        result["content_sourcing"] = sourcing

    except requests.exceptions.SSLError:
        result["error"]     = "SSL certificate error"
        result["reachable"] = True
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:120]}"
    except Exception as e:
        result["error"] = f"Scrape error: {str(e)[:120]}"

    return result


# ── Country attribution ────────────────────────────────────────────────────────

def derive_attribution(domain: str, whois: dict, asn_info: dict) -> dict:
    signals = {}

    # 1. Registrant country (WHOIS)
    reg_cc = (whois.get("registrant_country") or "").strip().upper()
    if reg_cc and len(reg_cc) <= 3:
        signals["registrant"] = {"value": reg_cc, "confidence": "high",
                                  "source": "WHOIS registrant record"}

    # 2. TLD
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    TLD_MAP = {
        "cn": "CN", "ru": "RU", "ir": "IR", "kp": "KP",
        "by": "BY", "ve": "VE", "sy": "SY", "cu": "CU",
    }
    if tld in TLD_MAP:
        signals["tld"] = {"value": TLD_MAP[tld], "confidence": "high",
                           "source": f".{tld} country-code TLD"}

    # 3. ASN operator
    org = (asn_info.get("org") or "").lower()
    ORG_MAP = [
        (["alibaba", "aliyun"],                   "CN", "Alibaba Cloud"),
        (["tencent"],                              "CN", "Tencent Cloud"),
        (["baidu"],                                "CN", "Baidu Cloud"),
        (["china telecom","chinanet","ctgnet"],    "CN", "China Telecom (state-owned)"),
        (["china unicom"],                         "CN", "China Unicom (state-owned)"),
        (["china mobile"],                         "CN", "China Mobile (state-owned)"),
        (["tigerweb"],                             "RU", "TigerWeb (Pravda operator)"),
        (["reg.ru","marosnet","rusonyx"],          "RU", "Russian hosting provider"),
        (["rostelecom"],                           "RU", "Rostelecom (Russian state)"),
        (["iranserver","shatel","asiatech"],       "IR", "Iranian hosting provider"),
        (["belarusian","beltelecom"],              "BY", "Belarusian state telecom"),
    ]
    for keywords, cc, label in ORG_MAP:
        if any(kw in org for kw in keywords):
            signals["asn_operator"] = {"value": cc, "confidence": "high",
                                        "source": label}
            break

    # 4. Hosting country (lowest confidence — may be CDN)
    asn_cc = (asn_info.get("country") or "").strip().upper()
    cdn_kws = ["cloudflare","fastly","akamai","amazon","google",
               "microsoft","digitalocean","linode","vultr","hetzner"]
    is_cdn  = any(kw in org for kw in cdn_kws)
    if asn_cc:
        signals["hosting"] = {
            "value":      asn_cc,
            "confidence": "low" if is_cdn else "medium",
            "source":     "Server location" + (" (CDN — not operator origin)" if is_cdn else ""),
            "is_cdn":     is_cdn,
        }

    # Primary: walk by confidence
    primary = None
    for key in ["registrant", "tld", "asn_operator", "hosting"]:
        if key in signals and not primary:
            if key == "hosting" and is_cdn:
                continue
            primary = signals[key]["value"]

    return {
        "primary":            primary or asn_cc or "?",
        "signals":            signals,
        "hosting_country":    asn_cc or "?",
        "hosting_is_cdn":     is_cdn,
        "registrant_country": signals.get("registrant", {}).get("value", "?"),
    }


# ── Five-dimension scoring ─────────────────────────────────────────────────────

def compute_dimensions(domain: str, db_match: dict, asn_info: dict,
                        attribution: dict, whois: dict,
                        ssl_san_overlap: list, reverse_ip_overlap: list,
                        scrape: dict) -> dict:
    """
    Returns five independent scores (0–10) plus per-dimension breakdowns.
    No single "threat score" — the analyst reads across dimensions.
    """

    def clamp(v, lo=0, hi=10):
        return max(lo, min(hi, v))

    # ── 1. INFRASTRUCTURE OPACITY (0=transparent, 10=fully hidden) ────────────
    op_score  = 0
    op_notes  = []

    if whois.get("privacy_protected"):
        op_score += 3
        op_notes.append("WHOIS privacy protection active")
    if not whois.get("registrant_org"):
        op_score += 2
        op_notes.append("No registrant org in WHOIS")
    if not whois.get("registrant_country"):
        op_score += 1
        op_notes.append("No registrant country in WHOIS")

    # Hosting opacity — CN/RU state ASN behind no CDN
    asn = asn_info.get("asn", "")
    org = asn_info.get("org", "").lower()
    state_asns = {"AS37963","AS45090","AS55967","AS4134","AS4837",
                  "AS58461","AS197695","AS8334"}
    if asn in state_asns:
        op_score += 2
        op_notes.append(f"Hosted on state-affiliated ASN ({asn})")
    elif attribution.get("hosting_is_cdn") is False and attribution.get("hosting_country") in ("CN","RU","IR","KP","BY"):
        op_score += 1
        op_notes.append("Hosted in restricted/sanctioned-media country")

    # Batch-registration pattern (same registrar, 30-day window) — seeded from DB
    if db_match.get("batch_flag"):
        op_score += 2
        op_notes.append("Domain registered in batch with other flagged domains (CL-174)")

    # WPBakery with no other transparency signals (PAPERWALL pattern)
    cms_names = [c["signal"] for c in scrape.get("cms", [])]
    if "wpbakery" in cms_names:
        op_score += 1
        op_notes.append("WPBakery CMS (consistent with PAPERWALL template — CL-174)")

    # SSL cert with no SAN variety (single domain cert = no cluster)
    sans_count = len(scrape.get("ssl_sans_count", []))  # injected by caller if needed

    # ── 2. OWNERSHIP TRANSPARENCY (0=fully disclosed, 10=completely hidden) ──
    ow_score = 10  # start opaque, subtract for each transparency signal
    ow_notes = []

    if scrape.get("has_about_page"):
        ow_score -= 2
        ow_notes.append("About page present")
    if scrape.get("has_contact_page"):
        ow_score -= 1
        ow_notes.append("Contact page present")
    if scrape.get("has_named_authors") or scrape.get("has_bylines"):
        ow_score -= 2
        ow_notes.append(f"Named authors/bylines ({scrape.get('editorial_staff_count',0)} found)")
    if scrape.get("has_legal_entity"):
        ow_score -= 2
        ow_notes.append("Legal entity disclosure detected")
    if scrape.get("has_funding_disclosure"):
        ow_score -= 2
        ow_notes.append("Funding/ownership disclosure detected")
    if db_match.get("tier") == "tier1":
        # Known overt state media — fully disclosed by definition
        ow_score  = 1
        ow_notes  = ["Confirmed overt state media — ownership publicly disclosed"]

    ow_score = clamp(ow_score)

    # ── 3. CONTENT SOURCING (0=original reporting, 10=covert AI/state republication) ──
    cs_score = 0
    cs_notes = []
    sourcing = scrape.get("content_sourcing", [])
    types    = [s["type"] for s in sourcing]

    if "original_reporting" in types:
        cs_score -= 2
        cs_notes.append("Original reporting signals detected")
    if "attributed_republication" in types:
        cs_score += 1
        cs_notes.append("Attributed republication of external sources")
    if "state_media_reference" in types:
        cs_score += 2
        cs_notes.append("State media content referenced without clear attribution")
    if "press_release_heavy" in types:
        cs_score += 2
        cs_notes.append("High press release density — possible content laundering")
    if "ai_generated_content" in types:
        cs_score += 2
        cs_notes.append("AI content generation detected")
    if "yan_limeng_article" in types:
        cs_score += 4
        cs_notes.append("PAPERWALL verbatim attack article detected (CL-174)")
    if len(scrape.get("state_media_links", [])) > 3:
        cs_score += 1
        cs_notes.append(f"{len(scrape['state_media_links'])} state media outbound links")

    cs_score = clamp(cs_score)

    # ── 4. NETWORK CENTRALITY (seeded at 0 — computed client-side as graph builds) ──
    nc_score = 0
    nc_notes = ["Centrality computed dynamically as investigation graph grows"]
    # Seed hints for client
    nc_hints = {
        "ssl_san_count":        0,   # populated from ssl_sans
        "reverse_ip_count":     0,   # populated from reverse_ip
        "known_overlap_count":  len(ssl_san_overlap) + len(reverse_ip_overlap),
    }

    # ── 5. STATE MEDIA PROXIMITY (0=no connection, 10=deeply embedded) ────────
    sm_score = 0
    sm_notes = []
    state_links = scrape.get("state_media_links", [])

    if state_links:
        sm_score += min(len(state_links) * 2, 4)
        names = [l["name"] for l in state_links[:4]]
        sm_notes.append(f"Links to: {', '.join(names)}")

    if ssl_san_overlap:
        sm_score += min(len(ssl_san_overlap) * 2, 4)
        sm_notes.append(f"SSL cert shares domains with: {', '.join(ssl_san_overlap[:3])}")

    if reverse_ip_overlap:
        sm_score += min(len(reverse_ip_overlap) * 2, 3)
        sm_notes.append(f"Shares IP with: {', '.join(reverse_ip_overlap[:3])}")

    if db_match.get("tier") == "tier1":
        sm_score  = 10
        sm_notes  = [f"This IS a tier-1 state media outlet ({db_match.get('name','')})"]
    elif db_match.get("tier") == "tier2":
        sm_score  = max(sm_score, 7)
        sm_notes.insert(0, f"Confirmed affiliate — {db_match.get('notes','')[:80]}")

    sm_score = clamp(sm_score)

    # ── Assemble result ────────────────────────────────────────────────────────
    return {
        "infrastructure_opacity": {
            "score": clamp(op_score), "max": 10,
            "label": _opacity_label(op_score),
            "notes": op_notes,
            "dimension": "Infrastructure Opacity",
            "description": "How hidden is the domain's ownership and hosting chain?",
        },
        "ownership_transparency": {
            "score": clamp(ow_score), "max": 10,
            "label": _transparency_label(ow_score),
            "notes": ow_notes,
            "dimension": "Ownership Transparency",
            "description": "Does the site disclose who runs it, who funds it, and who writes for it?",
        },
        "content_sourcing": {
            "score": cs_score, "max": 10,
            "label": _sourcing_label(cs_score),
            "notes": cs_notes,
            "dimension": "Content Sourcing",
            "description": "Is content original reporting, attributed republication, or covert laundering?",
        },
        "network_centrality": {
            "score": nc_score, "max": 10,
            "label": "Computed when graph is built",
            "notes": nc_notes,
            "hints": nc_hints,
            "dimension": "Network Centrality",
            "description": "How central is this domain in the network you are building?",
        },
        "state_media_proximity": {
            "score": sm_score, "max": 10,
            "label": _proximity_label(sm_score),
            "notes": sm_notes,
            "dimension": "State Media Proximity",
            "description": "How closely is this domain connected to known state media outlets? (Neutral — applies to all countries.)",
        },
    }


def _opacity_label(s):
    if s >= 7: return "Highly opaque"
    if s >= 4: return "Partially hidden"
    if s >= 2: return "Some opacity"
    return "Largely transparent"

def _transparency_label(s):
    if s >= 8: return "No disclosure"
    if s >= 5: return "Minimal disclosure"
    if s >= 2: return "Partial disclosure"
    return "Fully disclosed"

def _sourcing_label(s):
    if s >= 7: return "Covert republication"
    if s >= 4: return "Mixed / aggregated"
    if s >= 2: return "Attributed sourcing"
    return "Original reporting"

def _proximity_label(s):
    if s >= 8: return "State media node"
    if s >= 5: return "Closely connected"
    if s >= 2: return "Some proximity"
    return "No significant proximity"


# ── Database lookup — nation-neutral ──────────────────────────────────────────

def check_database(domain: str) -> dict:
    """
    Check against state media registry (all countries, neutral).
    Returns tier, nation, name, source.
    """
    registry = NET_DB.get("state_media_registry", {})

    # Direct match
    if domain in registry:
        entry = registry[domain]
        return {
            "tier":   "tier1",
            "nation": entry.get("country", "?"),
            "name":   entry.get("name", domain),
            "source": entry.get("source", "public-record"),
            "notes":  f"Confirmed state media — {entry.get('category','overt')}",
            "overt":  entry.get("overt", True),
        }

    # Subdomain match
    for reg_domain, entry in registry.items():
        if domain.endswith("." + reg_domain):
            return {
                "tier":   "tier1",
                "nation": entry.get("country", "?"),
                "name":   entry.get("name", domain),
                "source": entry.get("source", "public-record"),
                "notes":  f"Subdomain of confirmed state media {reg_domain}",
                "overt":  entry.get("overt", True),
            }

    # Known covert affiliates
    for aff in NET_DB.get("covert_affiliates", []):
        if aff["domain"] == domain:
            return {
                "tier":   "tier2",
                "nation": aff.get("nation", "?"),
                "name":   aff.get("name", domain),
                "source": aff.get("source", ""),
                "notes":  aff.get("notes", ""),
                "overt":  False,
            }

    return {"tier": None, "nation": None, "name": None, "source": None,
            "notes": None, "overt": None}


def find_san_overlap(sans: list) -> list:
    registry = NET_DB.get("state_media_registry", {})
    known    = set(registry.keys())
    for aff in NET_DB.get("covert_affiliates", []):
        known.add(aff["domain"])
    return [s for s in sans if any(s == k or s.endswith("." + k) for k in known)]


def find_rip_overlap(neighbors: list) -> list:
    registry = NET_DB.get("state_media_registry", {})
    known    = set(registry.keys())
    return [n for n in neighbors if any(n == k or n.endswith("." + k) for k in known)]


# ── Main pipeline ──────────────────────────────────────────────────────────────

def analyze_domain(domain: str) -> dict:
    domain = clean_domain(domain)
    result = {
        "domain":       domain,
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "db_match":     {},
        "ip_info":      {},
        "asn_info":     {},
        "attribution":  {},
        "whois":        {},
        "ssl_sans":     [],
        "ssl_san_overlap":    [],
        "reverse_ip":         [],
        "reverse_ip_overlap": [],
        "scrape":       {},
        "dimensions":   {},
        "error":        None,
    }

    try:
        result["db_match"]  = check_database(domain)
        ip_res              = resolve_ip(domain)
        result["ip_info"]   = ip_res

        if ip_res["ip"]:
            result["asn_info"] = get_asn_info(ip_res["ip"])

        result["whois"]      = get_rdap_whois(domain)
        result["attribution"]= derive_attribution(domain, result["whois"], result["asn_info"])

        sans                         = get_ssl_sans(domain)
        result["ssl_sans"]           = sans
        result["ssl_san_overlap"]    = find_san_overlap(sans)

        if ip_res["ip"]:
            nbrs                         = get_reverse_ip(ip_res["ip"])
            result["reverse_ip"]         = nbrs
            result["reverse_ip_overlap"] = find_rip_overlap(nbrs)

        result["scrape"] = scrape_page(domain)

        result["dimensions"] = compute_dimensions(
            domain          = domain,
            db_match        = result["db_match"],
            asn_info        = result["asn_info"],
            attribution     = result["attribution"],
            whois           = result["whois"],
            ssl_san_overlap = result["ssl_san_overlap"],
            reverse_ip_overlap = result["reverse_ip_overlap"],
            scrape          = result["scrape"],
        )

    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"analyze_domain({domain})")

    return result


def expand_from_seed(seed_domain: str) -> dict:
    """
    Analyze seed domain and collect infrastructure neighbors for graph expansion.
    Returns graph-ready nodes and edges.
    """
    seed_domain = clean_domain(seed_domain)
    seed_result = analyze_domain(seed_domain)

    nodes = [{
        "id":       seed_domain,
        "type":     "seed",
        "analysis": seed_result,
    }]
    edges = []

    # SSL SAN neighbors → add as unanalyzed nodes
    for san in seed_result.get("ssl_sans", [])[:30]:
        if san == seed_domain:
            continue
        nodes.append({"id": san, "type": "ssl_san", "analysis": None})
        edges.append({
            "source": seed_domain, "target": san,
            "type": "ssl_san", "label": "SSL SAN",
        })

    # Reverse IP neighbors
    for n in seed_result.get("reverse_ip", [])[:20]:
        if n == seed_domain or any(nd["id"] == n for nd in nodes):
            continue
        nodes.append({"id": n, "type": "shared_ip", "analysis": None})
        edges.append({
            "source": seed_domain, "target": n,
            "type": "shared_ip", "label": "Shared IP",
        })

    return {
        "seed":      seed_domain,
        "nodes":     nodes,
        "edges":     edges,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ── Flask routes ───────────────────────────────────────────────────────────────

def _corsify(r):
    from flask import Response
    resp = Response(r)
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@network_bp.route("/ping", methods=["GET"])
def ping():
    registry = NET_DB.get("state_media_registry", {})
    return jsonify({
        "status":          "ok",
        "db_loaded":       bool(NET_DB),
        "state_media":     len(registry),
        "covert_affiliates": len(NET_DB.get("covert_affiliates", [])),
        "countries_covered": len(set(v.get("country","") for v in registry.values())),
    })


@network_bp.route("/analyze", methods=["POST","OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return _corsify(""), 200
    data   = request.get_json(force=True, silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if len(domain) > 253 or not re.match(r'^[a-zA-Z0-9._\-/:\[\]]+$', domain):
        return jsonify({"error": "Invalid domain format"}), 400
    result = analyze_domain(domain)
    resp   = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@network_bp.route("/expand", methods=["POST","OPTIONS"])
def expand():
    if request.method == "OPTIONS":
        return _corsify(""), 200
    data   = request.get_json(force=True, silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    result = expand_from_seed(domain)
    resp   = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp
