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
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
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

HTTP_TIMEOUT   = 8   # balanced — enough for slow APIs
SCRAPE_TIMEOUT = 8   # scraping
SOCKET_TIMEOUT = 4   # DNS resolution
CRT_TIMEOUT    = 15  # crt.sh is slow for busy domains

# Set socket default timeout so gethostbyname can't hang forever
import socket as _sock
_sock.setdefaulttimeout(SOCKET_TIMEOUT)


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
    """
    Fetch SSL certificate SANs. Tries crt.sh first, falls back to
    certspotter if crt.sh fails or returns 502.
    """
    sans = set()

    # Method 1: crt.sh — retry once on 502
    for attempt in range(2):
        r = safe_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=CRT_TIMEOUT)
        if r and r.status_code == 200:
            try:
                certs = r.json()
                for cert in certs[:60]:
                    for name in cert.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and "." in name and name != domain:
                            sans.add(name)
                if sans:
                    return sorted(sans)[:100]
            except Exception:
                pass
        elif r and r.status_code == 502:
            time.sleep(1)  # brief pause before retry
            continue
        break

    # Method 2: certspotter (100 req/hr free, no key)
    if not sans:
        try:
            r2 = safe_get(
                f"https://api.certspotter.com/v1/issuances?domain={domain}"
                f"&include_subdomains=true&expand=dns_names",
                timeout=10
            )
            if r2 and r2.status_code == 200:
                for cert in r2.json():
                    for name in cert.get("dns_names", []):
                        name = name.strip().lstrip("*.")
                        if name and "." in name and name != domain:
                            sans.add(name)
        except Exception:
            pass

    # Method 3: DNS brute-force common subdomains as last resort
    if not sans:
        common = ["www","mail","ftp","api","cdn","static","media","img","images",
                  "news","en","es","fr","de","ru","ar","app","mobile","m"]
        for sub in common:
            try:
                socket.gethostbyname(f"{sub}.{domain}")
                sans.add(f"{sub}.{domain}")
            except Exception:
                pass

    return sorted(sans)[:100]


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
        # Step 1: instant lookups
        result["db_match"] = check_database(domain)
        ip_res             = resolve_ip(domain)
        result["ip_info"]  = ip_res
        ip                 = ip_res.get("ip")

        # Step 2: fire all slow calls in parallel, collect independently
        executor = ThreadPoolExecutor(max_workers=5)
        f_asn    = executor.submit(get_asn_info,   ip)     if ip else None
        f_whois  = executor.submit(get_rdap_whois, domain)
        f_sans   = executor.submit(get_ssl_sans,   domain)
        f_rip    = executor.submit(get_reverse_ip, ip)     if ip else None
        f_scrape = executor.submit(scrape_page,    domain)

        # Per-call timeouts — crt.sh needs more time than ASN lookup
        TIMEOUTS = {'asn': 10, 'whois': 10, 'ssl_sans': 20, 'reverse_ip': 10, 'scrape': 10}

        def _get(f, default, label):
            if f is None:
                return default
            try:
                return f.result(timeout=TIMEOUTS.get(label, 15))
            except Exception as ex:
                logger.warning(f"analyze_domain({domain}) — {label} failed: {ex}")
                return default

        asn_info = _get(f_asn,    {}, "asn")
        whois    = _get(f_whois,  {}, "whois")
        sans     = _get(f_sans,   [], "ssl_sans")
        rip      = _get(f_rip,    [], "reverse_ip")
        scrape   = _get(f_scrape, {}, "scrape")

        executor.shutdown(wait=False)  # don't block — futures already collected

        result["asn_info"]           = asn_info
        result["whois"]              = whois
        result["ssl_sans"]           = sans
        result["ssl_san_overlap"]    = find_san_overlap(sans)
        result["reverse_ip"]         = rip
        result["reverse_ip_overlap"] = find_rip_overlap(rip)
        result["scrape"]             = scrape
        result["attribution"]        = derive_attribution(domain, whois, asn_info)

        result["dimensions"] = compute_dimensions(
            domain             = domain,
            db_match           = result["db_match"],
            asn_info           = asn_info,
            attribution        = result["attribution"],
            whois              = whois,
            ssl_san_overlap    = result["ssl_san_overlap"],
            reverse_ip_overlap = result["reverse_ip_overlap"],
            scrape             = scrape,
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
    # Load persisted jobs on first ping (startup)
    if not hasattr(ping, '_initialized'):
        ping._initialized = True
        _load_jobs_meta()
    registry = NET_DB.get("state_media_registry", {})

    # Test external API reachability
    api_tests = {}
    test_domains = {
        "crt.sh (example)":  "https://crt.sh/?q=%25.example.com&output=json",
        "crt.sh (cgtn)":    "https://crt.sh/?q=%25.cgtn.com&output=json",
        "certspotter":    "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names",
        "hackertarget":   "https://api.hackertarget.com/reverseiplookup/?q=8.8.8.8",
        "rdap.org":       "https://rdap.org/domain/example.com",
        "ipinfo.io":      "https://ipinfo.io/8.8.8.8/json",
    }
    for name, url in test_domains.items():
        try:
            r = requests.get(url, timeout=5, headers=HEADERS)
            api_tests[name] = {"status": r.status_code, "ok": r.status_code == 200}
        except Exception as e:
            api_tests[name] = {"status": 0, "ok": False, "error": str(e)[:80]}

    return jsonify({
        "status":           "ok",
        "db_loaded":        bool(NET_DB),
        "state_media":      len(registry),
        "covert_affiliates": len(NET_DB.get("covert_affiliates", [])),
        "countries_covered": len(set(v.get("country","") for v in registry.values())),
        "api_reachability": api_tests,
    })


@network_bp.route("/debug", methods=["GET"])
def debug():
    """Returns a synthetic result with known structure — for frontend testing."""
    from flask import Response
    import json
    synthetic = {
        "domain": "debug-test.example.com",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "db_match": {"tier": None, "nation": None, "name": None, "source": None, "notes": None, "overt": None},
        "ip_info": {"ip": "1.2.3.4", "error": None},
        "asn_info": {"ip": "1.2.3.4", "org": "AS12345 Test Hosting", "asn": "AS12345", "country": "US", "city": "Test City", "hostname": ""},
        "attribution": {"primary": "US", "signals": {}, "hosting_country": "US", "hosting_is_cdn": False, "registrant_country": "US"},
        "whois": {"registrar": "Test Registrar", "registrant_org": "Test Org", "registrant_country": "US", "privacy_protected": False, "created": "2020-01-01", "updated": "2023-01-01", "nameservers": [], "status": []},
        "ssl_sans": ["neighbor1.example.com", "neighbor2.example.com"],
        "ssl_san_overlap": [],
        "reverse_ip": ["cohost1.example.com", "cohost2.example.com"],
        "reverse_ip_overlap": [],
        "scrape": {
            "reachable": True, "status_code": 200, "title": "Debug Test Site",
            "language": "en", "analytics_ids": [], "state_media_links": [],
            "cms": [], "has_about_page": True, "has_contact_page": True,
            "has_named_authors": True, "has_bylines": True, "has_legal_entity": True,
            "has_funding_disclosure": False, "editorial_staff_count": 3,
            "content_sourcing": [{"type": "original_reporting", "detail": "Test", "source": "test"}],
            "has_original_reporting_signals": True, "shared_id_signals": [], "error": None
        },
        "dimensions": {
            "infrastructure_opacity": {"score": 2, "max": 10, "label": "Some opacity", "notes": ["Test note"], "dimension": "Infrastructure Opacity", "description": "Test"},
            "ownership_transparency": {"score": 3, "max": 10, "label": "Partial disclosure", "notes": ["About page present"], "dimension": "Ownership Transparency", "description": "Test"},
            "content_sourcing": {"score": 0, "max": 10, "label": "Original reporting", "notes": ["Original reporting signals"], "dimension": "Content Sourcing", "description": "Test"},
            "network_centrality": {"score": 0, "max": 10, "label": "Computed when graph is built", "notes": ["Centrality computed dynamically"], "dimension": "Network Centrality", "description": "Test", "hints": {"ssl_san_count": 2, "reverse_ip_count": 2, "known_overlap_count": 0}},
            "state_media_proximity": {"score": 0, "max": 10, "label": "No significant proximity", "notes": [], "dimension": "State Media Proximity", "description": "Test"}
        },
        "error": None
    }
    r = Response(json.dumps(synthetic), mimetype="application/json")
    r.headers["Access-Control-Allow-Origin"] = "*"
    return r


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

    # Hard 25-second wall-clock timeout — Render kills at 30s
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FT
    with ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(analyze_domain, domain)
        try:
            result = future.result(timeout=25)
        except FT:
            result = {
                "domain": domain, "error": "Analysis timed out after 25s",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "db_match": check_database(domain),
                "ip_info": {}, "asn_info": {}, "attribution": {}, "whois": {},
                "ssl_sans": [], "ssl_san_overlap": [], "reverse_ip": [], "reverse_ip_overlap": [],
                "scrape": {}, "dimensions": {}
            }
        except Exception as e:
            result = {
                "domain": domain, "error": str(e),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "db_match": {}, "ip_info": {}, "asn_info": {}, "attribution": {}, "whois": {},
                "ssl_sans": [], "ssl_san_overlap": [], "reverse_ip": [], "reverse_ip_overlap": [],
                "scrape": {}, "dimensions": {}
            }

    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp



@network_bp.route("/id-search", methods=["POST","OPTIONS"])
def id_search():
    """
    Given a domain, extract all analytics/ad IDs from its HTML,
    then search PublicWWW for other domains using each ID.
    Returns a list of affiliate domains with the ID that connected them.
    """
    if request.method == "OPTIONS":
        return _corsify(""), 200

    data   = request.get_json(force=True, silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    result = {
        "domain":     domain,
        "ids_found":  [],
        "affiliates": [],   # [{domain, id_type, id_value, source}]
        "errors":     [],
        "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Step 1: scrape the domain and extract IDs
    # Re-use existing scrape function
    try:
        scrape = scrape_page(domain)
        analytics_ids = scrape.get("analytics_ids", [])
        result["ids_found"] = analytics_ids
    except Exception as e:
        result["errors"].append(f"Scrape failed: {str(e)}")
        resp = jsonify(result)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    if not analytics_ids:
        result["errors"].append("No trackable IDs found in page source")
        resp = jsonify(result)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    # Step 2: for each ID, search PublicWWW
    # Only search IDs that are meaningful for cross-site attribution
    # (skip generic WeChat/VK integrations, focus on specific numeric/alphanumeric IDs)
    SKIP_TYPES = {"WeChat Integration", "VKontakte Integration"}
    affiliates_seen = set()

    for id_entry in analytics_ids:
        id_type  = id_entry.get("type", "")
        id_value = id_entry.get("id", "")

        if id_type in SKIP_TYPES or not id_value:
            continue

        # Build the search query string for PublicWWW
        # PublicWWW indexes raw HTML source — search for the exact ID string
        search_domains = _publicwww_search(id_value, id_type)

        for found_domain in search_domains:
            found_domain = found_domain.strip().lower()
            # Clean up — remove protocol and path
            found_domain = re.sub(r'^https?://', '', found_domain)
            found_domain = found_domain.split('/')[0].strip()
            if not found_domain or found_domain == domain:
                continue
            key = f"{found_domain}:{id_value}"
            if key in affiliates_seen:
                continue
            affiliates_seen.add(key)
            result["affiliates"].append({
                "domain":   found_domain,
                "id_type":  id_type,
                "id_value": id_value,
                "source":   "PublicWWW",
                "signal":   "shared_tracking_id",
            })

    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def _publicwww_search(id_value: str, id_type: str) -> list:
    """
    Search PublicWWW for pages containing the given ID.
    Free tier — no API key required for basic searches.
    Returns list of domain strings.
    """
    domains = []
    try:
        # PublicWWW search URL — quoted string search in page source
        query    = requests.utils.quote(f'"{id_value}"')
        url      = f"https://publicwww.com/websites/{query}/"
        headers  = {
            "User-Agent": "Mozilla/5.0 (compatible; IntelDesk-Research/1.0; +https://inteldesk.io)",
            "Accept":     "text/html,application/xhtml+xml,*/*;q=0.8",
        }
        r = requests.get(url, headers=headers, timeout=12, allow_redirects=True)
        if not r or r.status_code != 200:
            return []

        # Parse the results page — PublicWWW lists domains in <a> tags with class "badge"
        soup  = BeautifulSoup(r.text, "html.parser")

        # Method 1: domain badges in search results
        for a in soup.find_all("a", href=True):
            href = a.get("href", "")
            text = a.get_text(strip=True)
            # PublicWWW result links look like /websites/domain.com/
            if href.startswith("/websites/") and href.endswith("/"):
                extracted = href.replace("/websites/", "").rstrip("/")
                if "." in extracted and len(extracted) > 3:
                    domains.append(extracted)
            # Also catch domain text that looks like a domain
            elif re.match(r'^[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}$', text, re.I):
                domains.append(text)

        # Deduplicate, cap at 50
        seen = set()
        result = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                result.append(d)
        return result[:50]

    except Exception as e:
        logger.debug(f"PublicWWW search for {id_value}: {e}")
        return []


@network_bp.route("/tool-expand", methods=["POST","OPTIONS"])
def tool_expand():
    """
    Run a single named investigation tool against a domain.
    Returns a list of discovered domains with their method.

    Tools:
      ssl_cert   — SSL certificate SAN expansion
      reverse_ip — Reverse IP lookup
      nameserver — Shared nameserver lookup
      whois_batch — WHOIS registrant/registrar cluster
    """
    if request.method == "OPTIONS":
        return _corsify(""), 200

    data   = request.get_json(force=True, silent=True) or {}
    domain = clean_domain((data.get("domain") or "").strip())
    tool   = (data.get("tool") or "").strip()

    if not domain:
        return jsonify({"error": "domain required"}), 400
    if not tool:
        return jsonify({"error": "tool required"}), 400

    results = []
    error   = None

    try:
        if tool == "ssl_cert":
            sans = get_ssl_sans(domain)
            results = [{"domain": s, "method": "ssl_cert",
                        "note": "Shares SSL certificate SAN"} for s in sans if s != domain]

        elif tool == "reverse_ip":
            ip_res = resolve_ip(domain)
            ip = ip_res.get("ip")
            if ip:
                neighbors = get_reverse_ip(ip)
                results = [{"domain": n, "method": "reverse_ip",
                            "note": f"Co-hosted on {ip}"} for n in neighbors if n != domain]
            else:
                error = f"Could not resolve IP for {domain}"

        elif tool == "nameserver":
            whois = get_rdap_whois(domain)
            nameservers = whois.get("nameservers", [])
            if not nameservers:
                # Try getting nameservers from a simple dig-style lookup
                try:
                    import dns.resolver
                    ns_records = dns.resolver.resolve(domain, 'NS')
                    nameservers = [str(r).rstrip('.').lower() for r in ns_records]
                except Exception:
                    pass

            if not nameservers:
                error = f"No nameservers found for {domain}"
            else:
                found_domains = set()
                for ns in nameservers[:3]:  # check first 3 nameservers
                    ns_results = _hackertarget_nameserver_lookup(ns)
                    found_domains.update(ns_results)
                found_domains.discard(domain)
                results = [{"domain": d, "method": "nameserver",
                            "note": f"Shares nameserver with {domain}"}
                           for d in sorted(found_domains)]

        elif tool == "whois_batch":
            whois = get_rdap_whois(domain)
            registrar = whois.get("registrar", "")
            registrant_org = whois.get("registrant_org", "")
            created = whois.get("created", "")

            if not registrar and not registrant_org:
                error = "No WHOIS registrar/registrant data available"
            else:
                # Use HackerTarget to find domains by same registrar
                found_domains = _hackertarget_registrar_lookup(registrar, domain)
                results = [{"domain": d, "method": "whois_batch",
                            "note": f"Same registrar: {registrar}"}
                           for d in found_domains if d != domain]

        else:
            error = f"Unknown tool: {tool}"

    except Exception as e:
        error = str(e)
        logger.exception(f"tool_expand({domain}, {tool})")

    resp = jsonify({
        "domain":   domain,
        "tool":     tool,
        "results":  results[:50],  # cap at 50
        "count":    len(results),
        "error":    error,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def _hackertarget_nameserver_lookup(nameserver: str) -> list:
    """Find domains sharing a nameserver via HackerTarget."""
    r = safe_get(f"https://api.hackertarget.com/findsharednameserver/?q={nameserver}")
    if not r or "error" in r.text.lower() or "API count" in r.text:
        return []
    domains = [d.strip() for d in r.text.strip().split("\n") if "." in d and len(d) > 3]
    return domains[:100]


def _hackertarget_registrar_lookup(registrar: str, seed_domain: str) -> list:
    """
    HackerTarget doesn't have a registrar API — use a zone file approach.
    Fall back to returning empty list with note to check manually.
    For now, return empty — this is a placeholder for a future
    integration with WhoisXML or DomainTools APIs.
    """
    return []

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




# ══════════════════════════════════════════════════════════════════════════════
# DEEP ANALYSIS — Tier 2 investigation
# Historical DNS, Wayback, full cert chain, BGP, registrar history
# ══════════════════════════════════════════════════════════════════════════════

def get_historical_dns(domain: str) -> dict:
    """
    Fetch historical DNS records via SecurityTrails-compatible free APIs.
    Uses HackerTarget DNS history as primary source.
    """
    result = {"a_records": [], "ns_history": [], "mx_records": [], "error": None}
    try:
        # HackerTarget DNS lookup — current records
        r = safe_get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if r and r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    record_type = parts[1].upper() if len(parts) > 2 else ""
                    value = parts[-1]
                    if "A" == record_type and value not in result["a_records"]:
                        result["a_records"].append(value)
                    elif "NS" == record_type and value not in result["ns_history"]:
                        result["ns_history"].append(value)
                    elif "MX" == record_type and value not in result["mx_records"]:
                        result["mx_records"].append(value)

        # HackerTarget reverse DNS history
        r2 = safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if r2 and r2.status_code == 200 and "error" not in r2.text.lower():
            hosts = [l.split(",")[0] for l in r2.text.strip().split("\n") if "," in l]
            result["subdomains_found"] = hosts[:30]

    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def get_wayback_snapshots(domain: str) -> dict:
    """
    Check Wayback Machine for archived snapshots.
    Returns count, first/last seen dates, and sample URLs.
    """
    result = {"available": False, "first_seen": None, "last_seen": None,
              "snapshot_count": 0, "sample_urls": [], "error": None}
    try:
        # Wayback CDX API — fast, no auth needed
        r = safe_get(
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&limit=5&fl=timestamp,original,statuscode"
            f"&filter=statuscode:200&collapse=timestamp:6",
            timeout=10
        )
        if r and r.status_code == 200:
            data = r.json()
            if len(data) > 1:  # first row is header
                result["available"] = True
                result["snapshot_count"] = len(data) - 1
                timestamps = [row[0] for row in data[1:] if row[0]]
                if timestamps:
                    result["first_seen"] = timestamps[0][:8]   # YYYYMMDD
                    result["last_seen"]  = timestamps[-1][:8]
                result["sample_urls"] = [
                    f"https://web.archive.org/web/{row[0]}/{row[1]}"
                    for row in data[1:4] if len(row) >= 2
                ]

        # Also check availability API for total count
        r2 = safe_get(f"https://archive.org/wayback/available?url={domain}", timeout=8)
        if r2 and r2.status_code == 200:
            snap = r2.json().get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                result["available"] = True
                result["closest_snapshot"] = snap.get("url", "")
                result["closest_timestamp"] = snap.get("timestamp", "")

    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def get_bgp_info(ip: str) -> dict:
    """
    Get BGP routing info — which ASNs route this IP, peering relationships.
    Uses BGPView-compatible free APIs.
    """
    result = {"prefixes": [], "peers": [], "upstreams": [],
              "rir": None, "country": None, "error": None}
    try:
        # Shodan internetdb — free, no key
        r = safe_get(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if r and r.status_code == 200:
            data = r.json()
            result["open_ports"]  = data.get("ports", [])[:10]
            result["cpes"]        = data.get("cpes", [])[:5]
            result["hostnames"]   = data.get("hostnames", [])[:5]
            result["tags"]        = data.get("tags", [])
            result["vulns"]       = data.get("vulns", [])[:5]

        # ipinfo for ASN details
        r2 = safe_get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r2 and r2.status_code == 200:
            d = r2.json()
            result["org"]     = d.get("org", "")
            result["country"] = d.get("country", "")
            result["region"]  = d.get("region", "")
            result["city"]    = d.get("city", "")
            result["loc"]     = d.get("loc", "")  # lat,lng
            result["timezone"]= d.get("timezone", "")

    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def get_full_cert_chain(domain: str) -> dict:
    """
    Get full SSL certificate details — issuer, validity, fingerprint, SANs.
    """
    result = {"issuer": None, "subject": None, "valid_from": None,
              "valid_to": None, "fingerprint": None, "san_count": 0,
              "ca_org": None, "error": None}
    try:
        import ssl as ssl_lib
        ctx = ssl_lib.create_default_context()
        conn = ctx.wrap_socket(
            __import__('socket').socket(), server_hostname=domain
        )
        conn.settimeout(8)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        result["subject"]    = dict(x[0] for x in cert.get("subject", []))
        result["issuer"]     = dict(x[0] for x in cert.get("issuer", []))
        result["valid_from"] = cert.get("notBefore", "")
        result["valid_to"]   = cert.get("notAfter", "")
        result["ca_org"]     = result["issuer"].get("organizationName", "")

        sans = []
        for t, v in cert.get("subjectAltName", []):
            if t == "DNS":
                sans.append(v)
        result["san_count"] = len(sans)
        result["sans_sample"] = sans[:10]

    except Exception as e:
        result["error"] = str(e)[:80]
    return result


def deep_analyze_domain(domain: str) -> dict:
    """
    Tier 2 deep analysis — runs after standard analysis.
    Adds historical DNS, Wayback snapshots, BGP info, full cert chain.
    """
    domain = clean_domain(domain)
    result = {
        "domain":         domain,
        "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "historical_dns": {},
        "wayback":        {},
        "bgp":            {},
        "cert_chain":     {},
        "error":          None,
    }

    try:
        ip_res = resolve_ip(domain)
        ip     = ip_res.get("ip")

        executor = ThreadPoolExecutor(max_workers=4)
        f_dns  = executor.submit(get_historical_dns, domain)
        f_wb   = executor.submit(get_wayback_snapshots, domain)
        f_bgp  = executor.submit(get_bgp_info, ip) if ip else None
        f_cert = executor.submit(get_full_cert_chain, domain)

        def _get(f, default, label):
            if f is None: return default
            try: return f.result(timeout=15)
            except Exception as ex:
                logger.warning(f"deep_analyze({domain}) — {label}: {ex}")
                return default

        result["historical_dns"] = _get(f_dns,  {}, "dns")
        result["wayback"]        = _get(f_wb,   {}, "wayback")
        result["bgp"]            = _get(f_bgp,  {}, "bgp")
        result["cert_chain"]     = _get(f_cert, {}, "cert")
        executor.shutdown(wait=False)

    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"deep_analyze_domain({domain})")

    return result


@network_bp.route("/deep-analyze", methods=["POST", "OPTIONS"])
def deep_analyze():
    if request.method == "OPTIONS":
        return _corsify(""), 200
    data   = request.get_json(force=True, silent=True) or {}
    domain = clean_domain((data.get("domain") or "").strip())
    if not domain:
        return jsonify({"error": "domain required"}), 400
    result = deep_analyze_domain(domain)
    resp   = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp



# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND RECURSIVE CRAWLER
# ══════════════════════════════════════════════════════════════════════════════
import threading
import uuid
from datetime import datetime
from collections import deque

# Crawl store — persisted to disk
_crawls      = {}        # crawl_id → metadata dict
_crawls_lock = threading.Lock()
CRAWL_DIR    = '/tmp'
MAX_DOMAINS  = 500_000

def _crawl_meta_path(crawl_id):
    return os.path.join(CRAWL_DIR, f'crawl_{crawl_id}_meta.json')

def _crawl_results_path(crawl_id):
    return os.path.join(CRAWL_DIR, f'crawl_{crawl_id}_results.jsonl')

def _save_crawl_meta(crawl_id):
    try:
        with _crawls_lock:
            meta = {k:v for k,v in _crawls.get(crawl_id, {}).items()
                    if k not in ('thread',)}
        with open(_crawl_meta_path(crawl_id), 'w') as f:
            json.dump(meta, f)
    except Exception as e:
        logger.warning(f"Could not save crawl meta {crawl_id}: {e}")

def _append_crawl_result(crawl_id, result):
    try:
        with open(_crawl_results_path(crawl_id), 'a') as f:
            f.write(json.dumps(result) + '\n')
    except Exception as e:
        logger.warning(f"Could not append crawl result {crawl_id}: {e}")

def _read_crawl_results(crawl_id, offset=0, limit=500):
    path = _crawl_results_path(crawl_id)
    if not os.path.exists(path):
        return []
    results = []
    try:
        with open(path) as f:
            for i, line in enumerate(f):
                if i < offset: continue
                if len(results) >= limit: break
                line = line.strip()
                if line:
                    try: results.append(json.loads(line))
                    except: pass
    except Exception as e:
        logger.warning(f"Could not read crawl results {crawl_id}: {e}")
    return results

def _count_crawl_results(crawl_id):
    path = _crawl_results_path(crawl_id)
    if not os.path.exists(path): return 0
    try:
        with open(path) as f:
            return sum(1 for l in f if l.strip())
    except: return 0


def _run_crawl(crawl_id):
    """
    Recursive network crawler.
    Starts from seed, follows SSL SANs + reverse IP + nameserver neighbors,
    expanding the graph until max_domains or queue empty.
    """
    with _crawls_lock:
        crawl = _crawls.get(crawl_id)
        if not crawl: return
        crawl['status'] = 'running'

    seed       = crawl.get('seed', '')
    max_doms   = crawl.get('max_domains', MAX_DOMAINS)
    triage_only= crawl.get('triage_only', True)
    seen       = set()   # domains already queued or processed
    queue      = deque([seed])
    seen.add(seed)

    logger.info(f"Crawl {crawl_id} starting from {seed}, max={max_doms}, triage={triage_only}")

    try:
        while queue:
            # Check cancellation
            with _crawls_lock:
                if _crawls.get(crawl_id, {}).get('status') == 'cancelled':
                    return

            # Check cap
            if len(seen) >= max_doms:
                logger.info(f"Crawl {crawl_id} hit max_domains cap {max_doms}")
                break

            domain = queue.popleft()

            # Triage: fast IP + ASN only
            if triage_only:
                result = _triage_domain(domain, dns_only=False)
            else:
                result = analyze_domain(domain)

            result['_crawl_depth'] = crawl.get('depth_map', {}).get(domain, 0)
            _append_crawl_result(crawl_id, result)

            with _crawls_lock:
                c = _crawls.get(crawl_id)
                if c:
                    c['done']       += 1
                    c['queued']      = len(queue)
                    c['seen']        = len(seen)
                    c['updated_at']  = datetime.utcnow().isoformat()

            # Discover neighbors from this domain
            neighbors = _discover_neighbors(domain, result)

            depth_map = crawl.setdefault('depth_map', {})
            cur_depth = depth_map.get(domain, 0)

            for n in neighbors:
                if n not in seen and len(seen) < max_doms:
                    seen.add(n)
                    queue.append(n)
                    depth_map[n] = cur_depth + 1

        # Complete
        with _crawls_lock:
            c = _crawls.get(crawl_id)
            if c and c['status'] == 'running':
                c['status'] = 'complete'
                c['updated_at'] = datetime.utcnow().isoformat()
        _save_crawl_meta(crawl_id)
        logger.info(f"Crawl {crawl_id} complete — {_count_crawl_results(crawl_id)} domains")

    except Exception as e:
        logger.exception(f"Crawl {crawl_id} fatal error: {e}")
        with _crawls_lock:
            c = _crawls.get(crawl_id)
            if c:
                c['status'] = 'error'
                c['error']  = str(e)
        _save_crawl_meta(crawl_id)


def _discover_neighbors(domain, triage_result):
    """
    Given a triage/analysis result, find neighboring domains to expand.
    Uses SSL SANs, reverse IP, and nameserver lookups.
    """
    neighbors = []
    ip = triage_result.get('ip')

    # SSL SANs — most productive expansion signal
    try:
        sans = get_ssl_sans(domain)
        neighbors.extend(sans[:30])
    except Exception:
        pass

    # Reverse IP — find co-hosted domains
    if ip:
        try:
            rip = get_reverse_ip(ip)
            neighbors.extend(rip[:20])
        except Exception:
            pass

    # Nameserver expansion — finds operationally linked domains
    try:
        whois_data = get_rdap_whois(domain)
        for ns in whois_data.get('nameservers', [])[:2]:
            try:
                ns_neighbors = _hackertarget_nameserver_lookup(ns)
                neighbors.extend(ns_neighbors[:15])
            except Exception:
                pass
    except Exception:
        pass

    # Clean and deduplicate
    cleaned = []
    seen_local = set()
    for n in neighbors:
        n = clean_domain(n)
        if n and n != domain and n not in seen_local:
            seen_local.add(n)
            cleaned.append(n)

    return cleaned[:60]  # cap per domain


# ── Crawl routes ───────────────────────────────────────────────────────────────

@network_bp.route("/crawl/start", methods=["POST", "OPTIONS"])
def crawl_start():
    """Start a recursive background crawl from a seed domain."""
    if request.method == "OPTIONS":
        return _corsify(""), 200

    data        = request.get_json(force=True, silent=True) or {}
    seed        = clean_domain((data.get("seed") or "").strip())
    max_domains = min(int(data.get("max_domains", 10000)), MAX_DOMAINS)
    triage_only = bool(data.get("triage_only", True))

    if not seed:
        return jsonify({"error": "seed domain required"}), 400

    crawl_id = str(uuid.uuid4())[:8]
    crawl = {
        "id":          crawl_id,
        "seed":        seed,
        "status":      "queued",
        "done":        0,
        "queued":      1,
        "seen":        1,
        "max_domains": max_domains,
        "triage_only": triage_only,
        "depth_map":   {seed: 0},
        "created_at":  datetime.utcnow().isoformat(),
        "updated_at":  datetime.utcnow().isoformat(),
        "error":       None,
    }

    with _crawls_lock:
        _crawls[crawl_id] = crawl
    _save_crawl_meta(crawl_id)

    # Start in background thread
    t = threading.Thread(target=_run_crawl, args=(crawl_id,), daemon=True)
    t.start()

    resp = jsonify({
        "crawl_id":    crawl_id,
        "seed":        seed,
        "max_domains": max_domains,
        "triage_only": triage_only,
        "status":      "queued",
    })
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@network_bp.route("/crawl/<crawl_id>", methods=["GET"])
def crawl_status(crawl_id):
    """Poll crawl status and get new results since offset."""
    with _crawls_lock:
        crawl = _crawls.get(crawl_id)

    if not crawl:
        # Try loading from disk
        meta_path = _crawl_meta_path(crawl_id)
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    crawl = json.load(f)
                with _crawls_lock:
                    _crawls[crawl_id] = crawl
            except Exception:
                pass

    if not crawl:
        resp = jsonify({"error": "crawl not found"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 404

    since  = int(request.args.get("since", 0))
    limit  = int(request.args.get("limit", 500))
    results = _read_crawl_results(crawl_id, offset=since, limit=limit)
    total   = crawl.get('seen', 0)
    done    = crawl.get('done', 0)
    pct     = round(done / total * 100, 1) if total > 0 else 0

    # ETA
    eta = None
    if crawl.get('status') == 'running' and done > 0:
        try:
            elapsed = (datetime.utcnow() - datetime.fromisoformat(
                crawl['created_at'])).total_seconds()
            rate = done / elapsed
            eta  = int((total - done) / rate) if rate > 0 else None
        except Exception:
            pass

    resp = jsonify({
        "crawl_id":     crawl_id,
        "status":       crawl.get("status"),
        "seed":         crawl.get("seed"),
        "done":         done,
        "queued":       crawl.get("queued", 0),
        "seen":         total,
        "max_domains":  crawl.get("max_domains"),
        "pct":          pct,
        "eta_seconds":  eta,
        "results":      results,
        "results_from": since,
        "error":        crawl.get("error"),
    })
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@network_bp.route("/crawl/<crawl_id>/cancel", methods=["POST", "OPTIONS"])
def crawl_cancel(crawl_id):
    if request.method == "OPTIONS":
        return _corsify(""), 200
    with _crawls_lock:
        c = _crawls.get(crawl_id)
        if c: c["status"] = "cancelled"
    _save_crawl_meta(crawl_id)
    resp = jsonify({"crawl_id": crawl_id, "status": "cancelled"})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@network_bp.route("/crawl/<crawl_id>/clusters", methods=["GET"])
def crawl_clusters(crawl_id):
    """Aggregate crawl results by ASN for heatmap."""
    results_path = _crawl_results_path(crawl_id)
    if not os.path.exists(results_path):
        resp = jsonify({"error": "no results yet"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 404

    clusters = {}
    total    = 0
    errors   = 0

    try:
        with open(results_path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    r = json.loads(line)
                except: continue
                total += 1
                if r.get('error'):
                    errors += 1
                    continue
                asn = r.get('asn') or 'UNKNOWN'
                org = r.get('org') or asn
                cc  = r.get('country') or '?'
                if asn not in clusters:
                    clusters[asn] = {"asn":asn,"org":org,"country":cc,
                                     "sample_domains":[],"count":0}
                clusters[asn]['count'] += 1
                if len(clusters[asn]['sample_domains']) < 100:
                    clusters[asn]['sample_domains'].append(r['domain'])
    except Exception as e:
        resp = jsonify({"error": str(e)})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 500

    sorted_clusters = sorted(clusters.values(),
                             key=lambda x: x['count'], reverse=True)
    resp = jsonify({
        "crawl_id":        crawl_id,
        "total_processed": total,
        "clusters":        sorted_clusters[:200],
        "errors":          errors,
    })
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp
