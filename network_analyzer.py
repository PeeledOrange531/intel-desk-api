"""
network_analyzer_patch.py
=========================
Two independent patches for network_analyzer.py.

PATCH 1 — Crawl precision (fixes the "thousands of unrelated domains" problem)
PATCH 2 — Neutral opacity scoring (removes hosting-geography bias)

Apply either or both. Patch 1 replaces _discover_neighbors and the enqueue
block inside _run_crawl. Patch 2 replaces the scoring in compute_dimensions.

Requires: pip install tldextract   (falls back to a built-in suffix list if absent)
"""

import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — CRAWL PRECISION
# ══════════════════════════════════════════════════════════════════════════════

# ── 1a. Registrable-domain collapse ───────────────────────────────────────────
# en.cgtn.com, es.cgtn.com and cdn.cgtn.com are ONE site, not three network
# members. Collapse to eTLD+1 before anything reaches the queue.

try:
    import tldextract
    _TLD = tldextract.TLDExtract(suffix_list_urls=())  # offline snapshot
    def registrable(domain: str) -> str:
        if not domain:
            return ""
        ext = _TLD(domain.strip().lower())
        return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""
except ImportError:
    _MULTI_SUFFIX = {
        "co.uk","org.uk","gov.uk","ac.uk","me.uk","net.uk","sch.uk",
        "com.cn","net.cn","org.cn","gov.cn","edu.cn","ac.cn",
        "com.au","net.au","org.au","gov.au","edu.au",
        "co.jp","or.jp","ne.jp","ac.jp","go.jp",
        "com.br","com.mx","com.ar","com.tr","com.tw","com.hk","com.sg",
        "com.ua","com.pl","com.ru","org.ru","net.ru",
        "co.in","net.in","org.in","gov.in",
        "co.za","org.za","co.kr","or.kr","co.il","org.il","co.nz",
    }
    def registrable(domain: str) -> str:
        if not domain:
            return ""
        parts = domain.strip().lower().strip(".").split(".")
        if len(parts) < 2:
            return ""
        if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIX:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    logger.warning("tldextract not installed — using built-in suffix list. "
                   "pip install tldextract for correct .co.uk / .com.cn handling.")


# ── 1b. Cardinality gate ──────────────────────────────────────────────────────
# The count IS the signal quality. An IP with 12,000 domains on it is evidence
# of nothing; an IP with 6 is near-conclusive. This replaces is_cdn_or_shared_ip
# and is_promiscuous_nameserver as the primary decision — those hardcoded org
# lists miss every regional host you have not personally heard of.

IP_EXPAND_MAX   = 25    # domains on an IP: at or below this, following it is justified
IP_RECORD_MAX   = 5000  # above this, do not even record the edge
NS_EXPAND_MAX   = 50    # domains on a nameserver
NS_RECORD_MAX   = 5000
SAN_EXPAND_MAX  = 60    # SANs on one cert; above this it is a CDN/wildcard cert

_card_cache = {}
_card_lock  = threading.Lock()
CARD_TTL    = 3600


def _cached(key, fn):
    now = time.time()
    with _card_lock:
        hit = _card_cache.get(key)
        if hit and now - hit[1] < CARD_TTL:
            return hit[0]
    val = fn()
    with _card_lock:
        _card_cache[key] = (val, now)
    return val


def _reverse_ip_raw(ip: str) -> list:
    """Full reverse-IP list, NOT truncated. Truncating before counting is what
    made cardinality invisible in the original get_reverse_ip([:50])."""
    if not ip:
        return []
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                         timeout=10)
        if r.status_code != 200 or "error" in r.text.lower() or "API count" in r.text:
            return []
        return [d.strip().lower() for d in r.text.strip().split("\n") if "." in d]
    except Exception as e:
        logger.debug(f"_reverse_ip_raw({ip}): {e}")
        return []


def _nameserver_raw(ns: str) -> list:
    if not ns:
        return []
    try:
        r = requests.get(f"https://api.hackertarget.com/findsharednameserver/?q={ns}",
                         timeout=10)
        if r.status_code != 200 or "error" in r.text.lower() or "API count" in r.text:
            return []
        return [d.strip().lower() for d in r.text.strip().split("\n")
                if "." in d and len(d) > 3]
    except Exception as e:
        logger.debug(f"_nameserver_raw({ns}): {e}")
        return []


# HackerTarget's free tier truncates. If a response comes back at the cap we do
# NOT know the true count — only that it is at least the cap. Treat unknown as
# high cardinality: refusing to expand on incomplete evidence is the safe error.
HT_RESULT_CAP = 500


def cardinality_verdict(count: int, expand_max: int, record_max: int,
                        truncated: bool) -> str:
    """Returns 'expand', 'record', or 'discard'."""
    if truncated:
        return "record"
    if count <= expand_max:
        return "expand"
    if count <= record_max:
        return "record"
    return "discard"


# ── 1c. Evidence families and corroboration ───────────────────────────────────
# Original merge logic kept max(confidence) and threw the rest away, so a domain
# corroborated by three independent methods scored the same as one found by the
# single strongest. Independent corroboration is exactly what should promote a
# weak signal — so track families and reward crossing them.

METHOD_FAMILY = {
    "ssl_cert_direct":       "cert",
    "ssl_cert_crtsh":        "cert",
    "ssl_cert_certspotter":  "cert",
    "reverse_ip_dedicated":  "ip",
    "reverse_ip_shared":     "ip",
    "nameserver_dedicated":  "ns",
    "nameserver_public":     "ns",
    "tracking_id":           "id",
    "hackertarget_hostsearch": "dns",
    "otx_passive_dns":       "dns",
    "urlscan":               "coload",
    "threatminer":           "dns",
    "dns_brute":             "dns",
}

EXPAND_THRESHOLD = 0.70


def _merge_neighbors(raw: list, self_reg: str) -> list:
    """Collapse to registrable domains, keep every method that found each one,
    then compute a final confidence that rewards independent corroboration."""
    by_reg = {}
    for n in raw:
        d = registrable(n.get("domain", ""))
        if not d or d == self_reg:
            continue
        entry = by_reg.setdefault(d, {"domain": d, "evidence": []})
        entry["evidence"].append({
            "method":     n.get("method", "unknown"),
            "confidence": float(n.get("confidence", 0.5)),
            "detail":     n.get("detail", ""),
        })

    out = []
    for d, entry in by_reg.items():
        ev = entry["evidence"]
        best     = max(e["confidence"] for e in ev)
        families = {METHOD_FAMILY.get(e["method"], "other") for e in ev}

        # Tier-B promotion: two independent mid-confidence families together
        # clear the bar that neither clears alone.
        mid_families = {
            METHOD_FAMILY.get(e["method"], "other")
            for e in ev if e["confidence"] >= 0.45
        }
        conf = best
        if len(mid_families) >= 2:
            conf = max(conf, 0.72)
        conf = min(0.99, conf + 0.04 * (len(families) - 1))

        out.append({
            "domain":       d,
            "confidence":   round(conf, 3),
            "method":       max(ev, key=lambda e: e["confidence"])["method"],
            "families":     sorted(families),
            "evidence":     sorted(ev, key=lambda e: -e["confidence"])[:6],
            "corroborated": len(families) > 1,
        })

    out.sort(key=lambda x: -x["confidence"])
    return out


# ── 1d. REPLACEMENT for _discover_neighbors ───────────────────────────────────
# Changes from the original:
#   * OTX passive DNS, URLScan co-load and DNS brute-force are NOT called in the
#     crawl path. They belong on a single /analyze call as context. In a
#     recursive crawler they are a firehose — URLScan's q=domain:X returns any
#     scan where the domain appeared anywhere in a request chain, so any site
#     embedding a CGTN video player becomes a "neighbor".
#   * Reverse IP and nameserver expansion are gated on measured cardinality,
#     not on a hardcoded provider list.
#   * Oversized certs (CDN/wildcard) are recorded but not expanded.
#   * Every neighbor carries its evidence chain out.

def _discover_neighbors_v2(domain, triage_result, get_ssl_sans_tagged,
                           get_rdap_whois, clean_domain):
    """Dependencies are passed in so this file stays importable standalone.
    In network_analyzer.py just call the module-level functions directly."""
    ip       = triage_result.get("ip")
    self_reg = registrable(domain)
    raw      = []

    def _certs():
        try:
            tagged = get_ssl_sans_tagged(domain)
        except Exception as e:
            logger.debug(f"cert err {domain}: {e}")
            return []
        # Only cert-derived methods survive into the crawl path.
        cert_only = [t for t in tagged
                     if METHOD_FAMILY.get(t.get("method"), "") == "cert"]
        external = [t for t in cert_only
                    if registrable(t["domain"]) != self_reg]
        if len(external) > SAN_EXPAND_MAX:
            logger.info(f"{domain}: {len(external)} external SANs — "
                        f"wildcard/CDN cert, recording without expansion")
            for t in external:
                t["confidence"] = 0.35
                t["detail"] = f"one of {len(external)} SANs — cert too broad to follow"
        return external

    def _rip():
        if not ip:
            return []
        all_d = _cached(f"ip:{ip}", lambda: _reverse_ip_raw(ip))
        n = len(all_d)
        truncated = n >= HT_RESULT_CAP
        verdict = cardinality_verdict(n, IP_EXPAND_MAX, IP_RECORD_MAX, truncated)
        if verdict == "discard":
            logger.info(f"{domain}: IP {ip} has {n} domains — discarded")
            return []
        conf   = 0.80 if verdict == "expand" else 0.30
        method = "reverse_ip_dedicated" if verdict == "expand" else "reverse_ip_shared"
        detail = f"{'~' if truncated else ''}{n} domains on {ip}"
        return [{"domain": d, "method": method, "confidence": conf, "detail": detail}
                for d in all_d[:200]]

    def _ns():
        try:
            whois = get_rdap_whois(domain)
        except Exception as e:
            logger.debug(f"whois err {domain}: {e}")
            return []
        out = []
        for ns in (whois.get("nameservers") or [])[:2]:
            all_d = _cached(f"ns:{ns}", lambda ns=ns: _nameserver_raw(ns))
            n = len(all_d)
            truncated = n >= HT_RESULT_CAP
            verdict = cardinality_verdict(n, NS_EXPAND_MAX, NS_RECORD_MAX, truncated)
            if verdict == "discard":
                logger.info(f"{domain}: NS {ns} has {n} domains — discarded")
                continue
            conf   = 0.65 if verdict == "expand" else 0.20
            method = "nameserver_dedicated" if verdict == "expand" else "nameserver_public"
            detail = f"{'~' if truncated else ''}{n} domains on {ns}"
            out.extend({"domain": d, "method": method, "confidence": conf,
                        "detail": detail} for d in all_d[:200])
        return out

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = [ex.submit(_certs), ex.submit(_rip), ex.submit(_ns)]
        for f in futures:
            try:
                raw.extend(f.result(timeout=25))
            except Exception as e:
                logger.debug(f"discover future failed: {e}")

    merged = _merge_neighbors(raw, self_reg)
    expandable = sum(1 for m in merged if m["confidence"] >= EXPAND_THRESHOLD)
    logger.info(f"_discover_neighbors({domain}): {len(merged)} neighbors, "
                f"{expandable} above expand threshold")
    return merged[:200]


# ── 1e. REPLACEMENT for the enqueue block inside _run_crawl ───────────────────
# Drop this in place of the existing `for nb in neighbors:` loop.
# The original unpacked `confidence` and never tested it — every promiscuity
# check in _discover_neighbors was decorative. This is the actual fix.

ENQUEUE_BLOCK = '''
            depth_map = crawl.setdefault('depth_map', {})
            cur_depth = depth_map.get(domain, 0)
            max_depth = crawl.get('max_depth', 3)

            for nb in neighbors:
                if isinstance(nb, dict):
                    n          = nb.get('domain', '')
                    method     = nb.get('method', 'unknown')
                    confidence = float(nb.get('confidence', 0.5))
                    evidence   = nb.get('evidence', [])
                    families   = nb.get('families', [])
                else:
                    n, method, confidence, evidence, families = nb, 'unknown', 0.5, [], []

                reg = registrable(n)
                if not reg or reg == registrable(domain):
                    continue

                # Always record the edge — weak evidence is still evidence,
                # it just is not grounds for another hop.
                _append_crawl_edge(crawl_id, {
                    'parent':     domain,
                    'domain':     reg,
                    'method':     method,
                    'confidence': confidence,
                    'families':   families,
                    'evidence':   evidence,
                    'depth':      cur_depth + 1,
                    'expanded':   confidence >= EXPAND_THRESHOLD,
                })

                if confidence < EXPAND_THRESHOLD:
                    continue
                if cur_depth + 1 > max_depth:
                    continue
                if reg in seen or len(seen) >= max_doms:
                    continue

                seen.add(reg)
                queue.append(reg)
                depth_map[reg] = cur_depth + 1
                crawl.setdefault('discovery_info', {})[reg] = {
                    'parent': domain, 'method': method,
                    'confidence': confidence, 'families': families,
                }
'''


def _append_crawl_edge(crawl_id, edge, crawl_dir="/tmp"):
    """Edges go to their own JSONL so the results file stays one-row-per-analyzed
    domain. This is what lets the UI answer 'why is this node here?'."""
    try:
        with open(os.path.join(crawl_dir, f"crawl_{crawl_id}_edges.jsonl"), "a") as f:
            f.write(json.dumps(edge) + "\n")
    except Exception as e:
        logger.warning(f"Could not append edge {crawl_id}: {e}")


def evidence_chain(edges_by_domain, target, seed, max_hops=6):
    """Render the one-sentence justification for a node. If this cannot be
    produced, the node does not belong in the result set."""
    chain, cur, guard = [], target, 0
    while cur and cur != seed and guard < max_hops:
        e = edges_by_domain.get(cur)
        if not e:
            break
        chain.append(f"{e['domain']} ← {e['method']} ({e['confidence']:.2f}) ← {e['parent']}")
        cur = e["parent"]
        guard += 1
    return " ; ".join(reversed(chain)) if chain else f"{target} (seed)"


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — NEUTRAL OPACITY SCORING
# ══════════════════════════════════════════════════════════════════════════════
# The original added +2 opacity for a Chinese/Russian ASN and +1 for hosting in
# CN/RU/IR/KP/BY. Hosting geography is not opacity — a site with a full About
# page, named bylines, disclosed funding and unredacted WHOIS is transparent
# regardless of its IP. That conflation is a measurement-validity failure and it
# only fires against one set of countries.
#
# Opacity now measures ONLY country-agnostic disclosure evidence.
# State-carrier hosting, if you want it, moves to state_media_proximity and is
# driven by a symmetric table in network_database.json — not a hardcoded set.

def compute_opacity_v2(whois: dict, scrape: dict, db_match: dict) -> dict:
    """Infrastructure opacity — 0 = transparent, 10 = fully hidden.
    Every input here is available for every country's domains equally."""
    score, notes = 0, []

    if whois.get("privacy_protected"):
        score += 3
        notes.append("WHOIS privacy protection active")
    if not whois.get("registrant_org"):
        score += 2
        notes.append("No registrant organisation in WHOIS")
    if not whois.get("registrant_country"):
        score += 1
        notes.append("No registrant country in WHOIS")
    if not whois.get("created"):
        score += 1
        notes.append("No registration date available")

    if db_match.get("batch_flag"):
        score += 2
        notes.append("Registered in a batch with other flagged domains")

    # Template reuse is a real signal but weak alone and country-agnostic.
    cms_names = [c.get("signal") for c in scrape.get("cms", [])]
    if "wpbakery" in cms_names and not scrape.get("has_about_page"):
        score += 1
        notes.append("Template CMS with no About page")

    if not notes:
        notes.append("No opacity indicators — ownership chain is documented")

    return {"score": max(0, min(10, score)), "notes": notes}


def compute_state_proximity_v2(domain, db_match, scrape, asn_info,
                               ssl_san_overlap, reverse_ip_overlap,
                               net_db) -> dict:
    """State media proximity — neutral across all countries.

    Hosting on a state-owned carrier lives HERE, not in opacity, and is read
    from net_db['state_owned_carriers'], which you populate symmetrically:
      {"AS####": {"country": "XX", "operator": "...", "state_share": 0.51,
                  "source": "https://..."}}
    If that key is absent or empty, this signal fires for nobody — which is the
    correct default, and better than a list that only contains adversaries.
    """
    score, notes = 0, []

    links = scrape.get("state_media_links", [])
    if links:
        score += min(len(links) * 2, 4)
        notes.append("Outbound links to: " +
                     ", ".join(l["name"] for l in links[:4]))

    if ssl_san_overlap:
        score += min(len(ssl_san_overlap) * 2, 4)
        notes.append("Shares a certificate with: " + ", ".join(ssl_san_overlap[:3]))

    if reverse_ip_overlap:
        score += min(len(reverse_ip_overlap) * 2, 3)
        notes.append("Co-hosted with: " + ", ".join(reverse_ip_overlap[:3]))

    carriers = (net_db or {}).get("state_owned_carriers", {})
    asn = (asn_info or {}).get("asn", "")
    if asn and asn in carriers:
        c = carriers[asn]
        score += 2
        notes.append(f"Hosted on {c.get('operator', asn)} — "
                     f"{int(c.get('state_share', 0) * 100)}% state-owned "
                     f"({c.get('country', '?')})")

    if db_match.get("tier") == "tier1":
        return {"score": 10,
                "notes": [f"This IS a state media outlet ({db_match.get('name', '')})"]}
    if db_match.get("tier") == "tier2":
        score = max(score, 7)
        notes.insert(0, f"Confirmed affiliate — {(db_match.get('notes') or '')[:80]}")

    if not notes:
        notes.append("No state media connections detected")

    return {"score": max(0, min(10, score)), "notes": notes}


# ── 2b. Registry balance audit ────────────────────────────────────────────────
# Add as a route. If state_media_registry is 80% CN/RU, "nation-neutral" is true
# on paper only — the tool is structurally unable to surface a Western cluster.

def registry_balance(net_db: dict) -> dict:
    from collections import Counter
    reg = net_db.get("state_media_registry", {})
    aff = net_db.get("covert_affiliates", [])
    by_country = Counter(v.get("country", "?") for v in reg.values())
    aff_country = Counter(a.get("nation", "?") for a in aff)
    total = sum(by_country.values()) or 1
    top = by_country.most_common(15)
    return {
        "registry_total":      sum(by_country.values()),
        "affiliates_total":    len(aff),
        "countries_covered":   len(by_country),
        "by_country":          dict(top),
        "affiliates_by_country": dict(aff_country.most_common(15)),
        "top_two_share":       round(sum(c for _, c in top[:2]) / total, 3),
        "note": ("top_two_share above ~0.5 means findings are constrained by "
                 "coverage, not by what exists"),
    }


# ══════════════════════════════════════════════════════════════════════════════
# DELETE THESE FROM network_analyzer.py
# ══════════════════════════════════════════════════════════════════════════════
DELETIONS = """
1. The crawl-restore block pasted into check_database(), find_san_overlap() and
   find_rip_overlap(). All three glob /tmp on every domain analysis, all three
   set the same ping._initialized flag so only one ever runs, and they spawn
   _run_crawl threads that BYPASS the _crawl_threads double-start guard.
   Live duplicate-thread hazard. Keep the copy in ping() only.

2. compute_dimensions:  sans_count = len(scrape.get("ssl_sans_count", []))
   Always 0, never read.

3. _publicwww_search(): scrapes PublicWWW HTML with no key and accepts any <a>
   whose text matches a domain regex — pulls nav and footer links into the
   affiliate list. Needs the paid API or needs to go.

4. /ping hardcodes crt.sh/?q=%25.cgtn.com and /test-discovery defaults to
   cgtn.com. Cosmetic, but swap for example.com.

5. derive_attribution: ORG_MAP and TLD_MAP cover only CN/RU/IR/KP/BY/VE/SY/CU.
   Either make them comprehensive or delete both and rely on WHOIS registrant
   country plus ASN geolocation, which work for every country without a list.

6. scrape_page: WeChat and VK embeds are logged as analytics_ids. They are share
   widgets. Either log Facebook/X/LinkedIn equivalents too or drop all four.
"""
