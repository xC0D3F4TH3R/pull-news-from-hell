#!/usr/bin/env python3
"""
News & Threat-Intel Aggregator By ARY4N TOM4R
================================
Pulls from official RSS/JSON feeds across security, CVEs, malware/attack
research, breaches, developer news, general tech, and gaming — merges
duplicate stories reported by multiple sources, scores/flags anything
matching your keywords or CVE severity, and produces Markdown + HTML +
JSON reports. Can email you a digest, push to Slack/Discord, run itself
on a schedule (no cron required), check whether any feed has died, and
search everything it's ever collected.

QUICK START
-----------
    pip install -r requirements.txt
    python3 security_news_aggregator.py --selftest      # verify logic, no network needed
    python3 security_news_aggregator.py                 # one run, last 24h, all tiers
    python3 security_news_aggregator.py --daemon         # runs forever, fires daily at config time

See README.md for the full flag/config reference.
"""

import argparse
import concurrent.futures
import copy
import difflib
import html
import json
import os
import re
import smtplib
import sys
import time
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime

import feedparser
import requests

try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

# ==========================================================================
# SOURCES — every entry pulls from the publisher's own official feed.
# ==========================================================================
SOURCES = [
    # --- tier: daily — general breaking security news ---
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "tier": "daily", "kind": "rss"},
    {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/", "tier": "daily", "kind": "rss"},
    {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/", "tier": "daily", "kind": "rss"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "tier": "daily", "kind": "rss"},
    {"name": "The Record", "url": "https://therecord.media/feed", "tier": "daily", "kind": "rss"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "tier": "daily", "kind": "rss"},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/blog/atom.xml", "tier": "daily", "kind": "rss"},

    # --- tier: cve — new/exploited CVEs, official advisories ---
    {"name": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "tier": "cve", "kind": "kev_json"},
    {"name": "CISA Cybersecurity Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "tier": "cve", "kind": "rss"},
    {"name": "NVD Recently Published CVEs", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "tier": "cve", "kind": "nvd_recent"},

    # --- tier: malware — how attacks/payloads/malware/ransomware work ---
    {"name": "Cisco Talos Intelligence", "url": "https://blog.talosintelligence.com/rss/", "tier": "malware", "kind": "rss"},
    {"name": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "tier": "malware", "kind": "rss"},
    {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/", "tier": "malware", "kind": "rss"},
    {"name": "ESET WeLiveSecurity", "url": "https://www.welivesecurity.com/en/rss/feed/", "tier": "malware", "kind": "rss"},
    {"name": "Malwarebytes Labs", "url": "https://www.malwarebytes.com/blog/feed/index.xml", "tier": "malware", "kind": "rss"},
    {"name": "SANS Internet Storm Center", "url": "https://isc.sans.edu/rssfeed_full.xml", "tier": "malware", "kind": "rss"},

    # --- tier: breach — dedicated data-breach reporting ---
    {"name": "DataBreaches.net", "url": "https://databreaches.net/feed/", "tier": "breach", "kind": "rss"},

    # --- tier: dev — developer / programming news ---
    {"name": "GitHub Blog", "url": "https://github.blog/feed/", "tier": "dev", "kind": "rss"},
    {"name": "Stack Overflow Blog", "url": "https://stackoverflow.blog/feed/", "tier": "dev", "kind": "rss"},
    {"name": "DEV Community", "url": "https://dev.to/feed", "tier": "dev", "kind": "rss"},
    {"name": "InfoQ", "url": "https://feed.infoq.com", "tier": "dev", "kind": "rss"},
    {"name": "freeCodeCamp News", "url": "https://www.freecodecamp.org/news/rss/", "tier": "dev", "kind": "rss"},
    {"name": "Smashing Magazine", "url": "https://www.smashingmagazine.com/feed/", "tier": "dev", "kind": "rss"},
    {"name": "Hacker News (Y Combinator)", "url": "https://news.ycombinator.com/rss", "tier": "dev", "kind": "rss"},

    # --- tier: tech — general technology news ---
    {"name": "TechCrunch", "url": "https://techcrunch.com/feed/", "tier": "tech", "kind": "rss"},
    {"name": "The Verge", "url": "https://www.theverge.com/rss/index.xml", "tier": "tech", "kind": "rss"},
    {"name": "Ars Technica", "url": "https://feeds.arstechnica.com/arstechnica/index", "tier": "tech", "kind": "rss"},
    {"name": "Wired", "url": "https://www.wired.com/feed/rss", "tier": "tech", "kind": "rss"},
    {"name": "MIT Technology Review", "url": "https://www.technologyreview.com/feed/", "tier": "tech", "kind": "rss"},
    {"name": "IEEE Spectrum", "url": "https://spectrum.ieee.org/feeds/feed.rss", "tier": "tech", "kind": "rss"},

    # --- tier: gaming — video game news ---
    {"name": "IGN", "url": "https://www.ign.com/rss", "tier": "gaming", "kind": "rss"},
    {"name": "GameSpot", "url": "https://www.gamespot.com/feeds/news/", "tier": "gaming", "kind": "rss"},
    {"name": "Eurogamer", "url": "https://www.eurogamer.net/feed", "tier": "gaming", "kind": "rss"},
    {"name": "PC Gamer", "url": "https://www.pcgamer.com/rss/", "tier": "gaming", "kind": "rss"},
    {"name": "Rock Paper Shotgun", "url": "https://www.rockpapershotgun.com/feed", "tier": "gaming", "kind": "rss"},
    {"name": "Kotaku", "url": "https://kotaku.com/rss", "tier": "gaming", "kind": "rss"},
    {"name": "Polygon", "url": "https://www.polygon.com/rss/index.xml", "tier": "gaming", "kind": "rss"},
]
VALID_TIERS = sorted(set(s["tier"] for s in SOURCES))

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; NewsAggregator/2.0; personal research tool)"}
REQUEST_TIMEOUT = 15
MAX_RETRIES = 2

# ==========================================================================
# CONFIG
# ==========================================================================
DEFAULT_CONFIG = {
    "hours": 24,
    "tiers": VALID_TIERS,
    "keywords": [],                       # e.g. ["microsoft", "fortinet", "ransomware"]
    "output_dir": "reports",
    "state_file": "state/state.json",
    "log_file": "logs/aggregator.log",
    "formats": {"markdown": True, "html": True, "json": True},
    "dedup": {"enabled": True, "similarity_threshold": 0.82, "window_hours": 48},
    "top_count": 15,
    "no_repeat": True,                    # skip items already shown in a previous run
    "seen_retention_days": 21,
    "email": {
        "enabled": False, "smtp_host": "smtp.gmail.com", "smtp_port": 587,
        "smtp_user": "", "password_env": "SECNEWS_SMTP_PASSWORD",
        "from_addr": "", "to_addrs": [], "use_tls": True,
    },
    "webhook": {"enabled": False, "url_env": "SECNEWS_WEBHOOK_URL", "url": ""},
    "daemon": {"run_at": "07:00", "interval_hours": None},
}


def deep_update(base, override):
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_update(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if not path:
        return cfg
    if not os.path.exists(path):
        return cfg
    if not HAVE_YAML:
        print(f"NOTE: pyyaml not installed, ignoring {path}. Run: pip install pyyaml")
        return cfg
    try:
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        deep_update(cfg, user_cfg)
    except Exception as e:
        print(f"WARNING: could not parse config file {path} ({e}) — using defaults.")
    return cfg


# ==========================================================================
# TEXT / TIME HELPERS
# ==========================================================================
def clean_html(raw):
    if not raw:
        return ""
    text = re.sub(r"<[^>]+>", " ", raw)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def truncate(text, max_chars=280):
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + "…"


def parse_entry_time(entry):
    for key in ("published_parsed", "updated_parsed"):
        val = getattr(entry, key, None)
        if val:
            return datetime.fromtimestamp(time.mktime(val), tz=timezone.utc)
    for key in ("published", "updated"):
        val = getattr(entry, key, None)
        if val:
            try:
                return parsedate_to_datetime(val).astimezone(timezone.utc)
            except Exception:
                pass
    return None


def local_time_str(dt_utc):
    if dt_utc is None:
        return "date unknown"
    return dt_utc.astimezone().strftime("%Y-%m-%d %H:%M %Z")


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve(text):
    m = CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


def normalize_title(title):
    t = (title or "").lower()
    t = re.sub(r"[^a-z0-9\s]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


# ==========================================================================
# HTTP LAYER — retries + conditional GET (ETag / Last-Modified) caching
# ==========================================================================
def cached_get(url, state, params=None, is_json=False):
    """
    GET with retry/backoff. Sends If-None-Match / If-Modified-Since from
    state['feed_cache'] if we have them; a 304 means "nothing changed since
    last run" and is treated as a clean empty result, not an error.
    Returns (response_or_None, unchanged_bool, error_str_or_None).
    """
    cache = state.setdefault("feed_cache", {}).setdefault(url, {})
    req_headers = dict(HEADERS)
    if cache.get("etag"):
        req_headers["If-None-Match"] = cache["etag"]
    if cache.get("last_modified"):
        req_headers["If-Modified-Since"] = cache["last_modified"]

    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=req_headers, params=params, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 304:
                return None, True, None
            resp.raise_for_status()
            if resp.headers.get("ETag"):
                cache["etag"] = resp.headers["ETag"]
            if resp.headers.get("Last-Modified"):
                cache["last_modified"] = resp.headers["Last-Modified"]
            return resp, False, None
        except Exception as e:
            last_err = str(e)
            if attempt < MAX_RETRIES:
                time.sleep(1.5 * (attempt + 1))
    return None, False, last_err


# ==========================================================================
# FETCHERS
# ==========================================================================
def fetch_rss(source, cutoff_utc, state):
    resp, unchanged, err = cached_get(source["url"], state)
    if err:
        return [], f"{source['name']}: {err}"
    if unchanged or resp is None:
        return [], None
    items = []
    parsed = feedparser.parse(resp.content)
    for entry in parsed.entries:
        pub_dt = parse_entry_time(entry)
        if pub_dt and pub_dt < cutoff_utc:
            continue
        summary = clean_html(getattr(entry, "summary", "") or getattr(entry, "description", ""))
        items.append({
            "source": source["name"], "tier": source["tier"],
            "title": clean_html(getattr(entry, "title", "(no title)")),
            "link": getattr(entry, "link", ""),
            "published_utc": pub_dt, "summary": truncate(summary),
            "is_kev": False, "cvss": None,
        })
    return items, None


def fetch_kev(source, cutoff_utc, state):
    resp, unchanged, err = cached_get(source["url"], state)
    if err:
        return [], f"{source['name']}: {err}"
    if unchanged or resp is None:
        return [], None
    items = []
    data = resp.json()
    for vuln in data.get("vulnerabilities", []):
        date_added = vuln.get("dateAdded")
        try:
            added_dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if added_dt < cutoff_utc:
            continue
        cve = vuln.get("cveID", "")
        summary = clean_html(vuln.get("shortDescription", ""))
        if vuln.get("requiredAction"):
            summary += f" | Required action: {clean_html(vuln['requiredAction'])}"
        items.append({
            "source": source["name"], "tier": source["tier"],
            "title": f"{cve}: {vuln.get('vulnerabilityName', '')}",
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published_utc": added_dt, "summary": truncate(summary),
            "is_kev": True, "cvss": None,
        })
    return items, None


def fetch_nvd_recent(source, cutoff_utc, state):
    """NVD API 2.0 — CVEs published since cutoff (max 120-day window, no key required for light use)."""
    now_utc = datetime.now(timezone.utc)
    start = max(cutoff_utc, now_utc - timedelta(days=119))
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now_utc.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    # NVD's dynamic query isn't cacheable via ETag (window changes every run) — skip conditional GET.
    last_err = None
    resp = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = requests.get(source["url"], headers=HEADERS, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            break
        except Exception as e:
            last_err = str(e)
            resp = None
            if attempt < MAX_RETRIES:
                time.sleep(1.5 * (attempt + 1))
    if resp is None:
        return [], f"{source['name']}: {last_err}"

    items = []
    data = resp.json()
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        published = cve.get("published", "")
        try:
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            pub_dt = None
        if pub_dt and pub_dt < cutoff_utc:
            continue

        desc_text = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_score, severity = None, ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                base = metrics[key][0].get("cvssData", {})
                cvss_score = base.get("baseScore")
                severity = base.get("baseSeverity", metrics[key][0].get("baseSeverity", "?"))
                break

        title = cve_id + (f" — CVSS {cvss_score} ({severity})" if cvss_score is not None else "")
        items.append({
            "source": source["name"], "tier": source["tier"],
            "title": title,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://nvd.nist.gov/",
            "published_utc": pub_dt, "summary": truncate(clean_html(desc_text)),
            "is_kev": False, "cvss": cvss_score,
        })
    return items, None


def fetch_source(source, cutoff_utc, state):
    if source["kind"] == "kev_json":
        return fetch_kev(source, cutoff_utc, state)
    if source["kind"] == "nvd_recent":
        return fetch_nvd_recent(source, cutoff_utc, state)
    return fetch_rss(source, cutoff_utc, state)


def gather(sources, hours, state):
    cutoff_utc = datetime.now(timezone.utc) - timedelta(hours=hours)
    all_items, errors = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fetch_source, s, cutoff_utc, state): s for s in sources}
        for fut in concurrent.futures.as_completed(futures):
            items, err = fut.result()
            all_items.extend(items)
            if err:
                errors.append(err)
    return all_items, errors


# ==========================================================================
# DE-DUPLICATION — merges the same story reported by multiple sources
# ==========================================================================
def dedupe_items(items, threshold=0.82, window_hours=48):
    items_sorted = sorted(items, key=lambda x: x["published_utc"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    n = len(items_sorted)
    used = [False] * n
    merged = []
    for i in range(n):
        if used[i]:
            continue
        it = items_sorted[i]
        group = [it]
        used[i] = True
        cve_i = extract_cve(it["title"])
        norm_i = normalize_title(it["title"])
        for j in range(i + 1, n):
            if used[j]:
                continue
            jt = items_sorted[j]
            if it["published_utc"] and jt["published_utc"]:
                delta_h = abs((it["published_utc"] - jt["published_utc"]).total_seconds()) / 3600
                if delta_h > window_hours:
                    continue
            cve_j = extract_cve(jt["title"])
            is_dup = False
            if cve_i and cve_j:
                is_dup = cve_i == cve_j
            else:
                norm_j = normalize_title(jt["title"])
                if norm_i and norm_j:
                    is_dup = difflib.SequenceMatcher(None, norm_i, norm_j).ratio() >= threshold
            if is_dup:
                group.append(jt)
                used[j] = True
        merged.append(_merge_group(group))
    return merged


def _merge_group(group):
    primary = max(group, key=lambda x: len(x.get("summary") or ""))
    times = [g["published_utc"] for g in group if g["published_utc"]]
    earliest = min(times) if times else None
    sources, seen_names = [], set()
    for g in group:
        if g["source"] not in seen_names:
            sources.append({"name": g["source"], "link": g["link"]})
            seen_names.add(g["source"])
    cvss_vals = [g["cvss"] for g in group if g.get("cvss") is not None]
    return {
        "title": primary["title"],
        "summary": primary["summary"],
        "published_utc": earliest,
        "tier": primary["tier"],
        "link": primary["link"],
        "sources": sources,
        "is_kev": any(g.get("is_kev") for g in group),
        "cvss": max(cvss_vals) if cvss_vals else None,
    }


# ==========================================================================
# SCORING — keyword alerts + CVE severity + multi-source + recency
# ==========================================================================
def keyword_matches(item, keywords):
    text = f"{item['title']} {item.get('summary', '')}".lower()
    return [kw for kw in keywords if kw and kw.lower() in text]


def score_item(item, keywords):
    score = 0.0
    matches = keyword_matches(item, keywords)
    if matches:
        score += 50
    if item.get("is_kev"):
        score += 40
    cvss = item.get("cvss")
    if cvss is not None:
        if cvss >= 9:
            score += 40
        elif cvss >= 7:
            score += 20
        elif cvss >= 4:
            score += 8
    score += max(0, len(item.get("sources", [])) - 1) * 8
    if item.get("published_utc"):
        hours_old = (datetime.now(timezone.utc) - item["published_utc"]).total_seconds() / 3600
        score += max(0, 24 - hours_old) * 0.3
    return score, matches


def highlight(text, matches, style="md"):
    if not text or not matches:
        return text
    out = text
    for kw in sorted(set(matches), key=len, reverse=True):
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        repl = f"**{kw.upper()}**" if style == "md" else f"<mark>{kw}</mark>"
        out = pattern.sub(lambda m, r=repl: r if style == "md" else f"<mark>{m.group(0)}</mark>", out)
    return out


# ==========================================================================
# STATE (persisted across runs): dedupe-across-days + HTTP cache
# ==========================================================================
def load_state(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"last_run_utc": None, "seen_links": {}, "feed_cache": {}}


def save_state(path, state, retention_days=21):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    pruned = {}
    for link, ts in state.get("seen_links", {}).items():
        try:
            if datetime.fromisoformat(ts) >= cutoff:
                pruned[link] = ts
        except Exception:
            continue
    state["seen_links"] = pruned
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def filter_unseen(merged_items, state):
    now_iso = datetime.now(timezone.utc).isoformat()
    seen = state.setdefault("seen_links", {})
    fresh = []
    for it in merged_items:
        links = [s["link"] for s in it["sources"]] or [it["link"]]
        if all(l in seen for l in links):
            continue
        fresh.append(it)
    for it in merged_items:
        for l in ([s["link"] for s in it["sources"]] or [it["link"]]):
            seen.setdefault(l, now_iso)
    return fresh


# ==========================================================================
# REPORT BUILDERS
# ==========================================================================
def build_scored_list(items, keywords):
    scored = []
    for it in items:
        score, matches = score_item(it, keywords)
        scored.append({**it, "score": score, "matches": matches})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def build_markdown(scored_items, errors, meta, top_count):
    lines = [
        "# Daily Digest",
        f"**Generated:** {meta['run_time']}  ",
        f"**Window:** {meta['window_desc']}  ",
        f"**Items:** {len(scored_items)} unique stories ({meta['dedup_saved']} merged as duplicates)  ",
        "",
    ]
    top = [i for i in scored_items if i["score"] >= 40][:top_count]
    if top:
        lines.append("## 🔥 Priority & Trending")
        lines.append("")
        for it in top:
            lines.append(_md_item(it))
        lines.append("---")
        lines.append("")

    by_tier = {}
    for it in scored_items:
        by_tier.setdefault(it["tier"], []).append(it)
    for tier, its in by_tier.items():
        lines.append(f"## {tier.upper()} ({len(its)})")
        lines.append("")
        for it in its:
            lines.append(_md_item(it))
        lines.append("---")
        lines.append("")

    if errors:
        lines.append("## Fetch errors (sources skipped this run)")
        for e in errors:
            lines.append(f"- {e}")
        lines.append("")
    return "\n".join(lines)


def _md_item(it):
    out = [f"### {highlight(it['title'], it['matches'], 'md')}"]
    out.append(f"*{local_time_str(it['published_utc'])}*")
    if it["summary"]:
        out.append("")
        out.append(highlight(it["summary"], it["matches"], "md"))
    srcs = ", ".join(f"[{s['name']}]({s['link']})" for s in it["sources"])
    out.append("")
    out.append(f"Sources: {srcs}")
    out.append("")
    return "\n".join(out)


HTML_STYLE = """
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;
  background:#0f1115;color:#e6e6e6;line-height:1.5}
h1{font-size:1.6rem} h2{border-bottom:1px solid #333;padding-bottom:.3rem;margin-top:2rem;color:#8ab4f8}
.meta{color:#9aa0a6;font-size:.9rem}
.item{margin:1rem 0;padding:1rem;background:#1a1d23;border-radius:8px;border-left:3px solid #333}
.item.top{border-left-color:#f4b400}
.item h3{margin:0 0 .3rem 0;font-size:1.05rem}
.time{color:#9aa0a6;font-size:.85rem}
.sources a{color:#8ab4f8;text-decoration:none;margin-right:.6rem}
mark{background:#f4b400;color:#000;padding:0 2px;border-radius:2px}
.errors{color:#f28b82;font-size:.85rem}
"""


def build_html(scored_items, errors, meta, top_count):
    parts = [f"<html><head><meta charset='utf-8'><title>Digest {meta['run_time']}</title><style>{HTML_STYLE}</style></head><body>"]
    parts.append("<h1>Daily Digest</h1>")
    parts.append(f"<p class='meta'>Generated {meta['run_time']} &middot; {meta['window_desc']} &middot; "
                  f"{len(scored_items)} unique stories ({meta['dedup_saved']} merged)</p>")

    top = [i for i in scored_items if i["score"] >= 40][:top_count]
    if top:
        parts.append("<h2>🔥 Priority &amp; Trending</h2>")
        for it in top:
            parts.append(_html_item(it, is_top=True))

    by_tier = {}
    for it in scored_items:
        by_tier.setdefault(it["tier"], []).append(it)
    for tier, its in by_tier.items():
        parts.append(f"<h2>{html.escape(tier.upper())} ({len(its)})</h2>")
        for it in its:
            parts.append(_html_item(it))

    if errors:
        parts.append("<h2>Fetch errors</h2><ul class='errors'>")
        for e in errors:
            parts.append(f"<li>{html.escape(e)}</li>")
        parts.append("</ul>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _html_item(it, is_top=False):
    title = highlight(html.escape(it["title"]), it["matches"], "html")
    summary = highlight(html.escape(it["summary"]), it["matches"], "html") if it["summary"] else ""
    srcs = " ".join(f"<a href='{html.escape(s['link'])}' target='_blank'>{html.escape(s['name'])}</a>" for s in it["sources"])
    cls = "item top" if is_top else "item"
    return (f"<div class='{cls}'><h3>{title}</h3>"
            f"<div class='time'>{local_time_str(it['published_utc'])}</div>"
            f"<p>{summary}</p><div class='sources'>{srcs}</div></div>")


def build_json(scored_items, errors, meta):
    def ser(it):
        d = dict(it)
        d["published_utc"] = it["published_utc"].isoformat() if it["published_utc"] else None
        return d
    return json.dumps({"meta": meta, "items": [ser(i) for i in scored_items], "errors": errors}, indent=2)


def print_console(scored_items, errors, meta, top_count):
    print("=" * 72)
    print(f"DIGEST — {meta['run_time']} ({meta['window_desc']})")
    print(f"{len(scored_items)} unique stories, {meta['dedup_saved']} merged as duplicates")
    print("=" * 72)
    top = [i for i in scored_items if i["score"] >= 40][:top_count]
    if top:
        print("\n--- 🔥 PRIORITY & TRENDING ---")
        for it in top:
            _print_item(it)
    by_tier = {}
    for it in scored_items:
        by_tier.setdefault(it["tier"], []).append(it)
    for tier, its in by_tier.items():
        print(f"\n--- {tier.upper()} ({len(its)}) ---")
        for it in its:
            _print_item(it)
    if errors:
        print("\n--- Sources that failed this run ---")
        for e in errors:
            print(f"  ! {e}")
    print()


def _print_item(it):
    flag = " [MATCH]" if it["matches"] else ""
    print(f"\n[{local_time_str(it['published_utc'])}] {it['title']}{flag}")
    if it["summary"]:
        print(f"  {it['summary']}")
    for s in it["sources"]:
        print(f"  ({s['name']}) {s['link']}")


# ==========================================================================
# NOTIFY — email + Slack/Discord webhook
# ==========================================================================
def send_email(config, scored_items, meta, md_report, html_report):
    ecfg = config.get("email", {})
    if not ecfg.get("enabled"):
        print("Email not enabled in config (email.enabled: true) — skipping.")
        return False
    password = os.environ.get(ecfg.get("password_env", "SECNEWS_SMTP_PASSWORD"), "")
    if not password:
        print(f"WARNING: env var '{ecfg.get('password_env')}' not set — skipping email.")
        return False
    if not ecfg.get("to_addrs") or not ecfg.get("from_addr"):
        print("WARNING: email.from_addr / email.to_addrs not configured — skipping email.")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Daily Digest — {meta['run_time']} ({len(scored_items)} stories)"
    msg["From"] = ecfg["from_addr"]
    msg["To"] = ", ".join(ecfg["to_addrs"])
    msg.attach(MIMEText(md_report, "plain"))
    msg.attach(MIMEText(html_report, "html"))

    try:
        with smtplib.SMTP(ecfg["smtp_host"], ecfg.get("smtp_port", 587), timeout=20) as server:
            if ecfg.get("use_tls", True):
                server.starttls()
            server.login(ecfg["smtp_user"], password)
            server.sendmail(ecfg["from_addr"], ecfg["to_addrs"], msg.as_string())
        print(f"Email sent to {', '.join(ecfg['to_addrs'])}.")
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


def send_webhook(config, scored_items, meta):
    wcfg = config.get("webhook", {})
    if not wcfg.get("enabled"):
        print("Webhook not enabled in config (webhook.enabled: true) — skipping.")
        return False
    url = os.environ.get(wcfg.get("url_env", "SECNEWS_WEBHOOK_URL"), "") or wcfg.get("url", "")
    if not url:
        print(f"WARNING: webhook URL not set (env '{wcfg.get('url_env')}' empty, no url in config) — skipping.")
        return False

    top = [i for i in scored_items if i["score"] >= 40][:10]
    lines = [f"Daily Digest — {meta['run_time']}",
             f"{len(scored_items)} stories ({meta['dedup_saved']} merged)", ""]
    for it in top:
        lines.append(f"• {it['title']}")
        lines.append(f"  {it['sources'][0]['link']}")
    text = "\n".join(lines)

    is_discord = "discord.com" in url
    payload = {"content": text[:1900]} if is_discord else {"text": text[:35000]}
    try:
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()
        print("Webhook posted.")
        return True
    except Exception as e:
        print(f"Webhook send failed: {e}")
        return False


# ==========================================================================
# FEED HEALTH CHECK
# ==========================================================================
def check_one_feed(source):
    start = time.time()
    try:
        if source["kind"] == "nvd_recent":
            r = requests.get(source["url"], headers=HEADERS, params={"resultsPerPage": 1}, timeout=10)
        else:
            r = requests.head(source["url"], headers=HEADERS, timeout=10, allow_redirects=True)
            if r.status_code >= 400 or r.status_code == 405:
                r = requests.get(source["url"], headers=HEADERS, timeout=10, stream=True)
                r.close()
        elapsed = (time.time() - start) * 1000
        status = "OK" if r.status_code < 400 else f"HTTP {r.status_code}"
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        status = f"FAIL: {e}"
    return source["name"], source["tier"], status, elapsed


def check_feeds():
    print(f"{'SOURCE':<34}{'TIER':<10}{'STATUS':<28}{'LATENCY'}")
    print("-" * 84)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(check_one_feed, SOURCES))
    results.sort(key=lambda r: (r[2] != "OK", r[1], r[0]))
    dead = 0
    for name, tier, status, elapsed in results:
        if status != "OK":
            dead += 1
        print(f"{name:<34}{tier:<10}{status:<28}{elapsed:6.0f}ms")
    print("-" * 84)
    print(f"{len(results) - dead}/{len(results)} healthy.")


# ==========================================================================
# ARCHIVE SEARCH
# ==========================================================================
def search_archive(output_dir, term):
    term_l = term.lower()
    if not os.path.isdir(output_dir):
        print(f"No reports directory found at {output_dir}.")
        return
    json_files = sorted(f for f in os.listdir(output_dir) if f.startswith("digest_") and f.endswith(".json"))
    if not json_files:
        print("No archived JSON reports found yet — run the aggregator at least once first.")
        return
    hits = 0
    for fname in json_files:
        path = os.path.join(output_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        for it in data.get("items", []):
            hay = f"{it.get('title', '')} {it.get('summary', '')}".lower()
            if term_l in hay:
                hits += 1
                print(f"\n[{data['meta']['run_time']}] {it['title']}")
                if it.get("summary"):
                    print(f"  {it['summary']}")
                for s in it.get("sources", []):
                    print(f"  ({s['name']}) {s['link']}")
    print(f"\n{hits} match(es) for '{term}' across {len(json_files)} archived report(s).")


# ==========================================================================
# PIPELINE
# ==========================================================================
def run_once(args, config):
    sources = [s for s in SOURCES if s["tier"] in config["tiers"]]
    state = load_state(config["state_file"])

    if args.since_last and state.get("last_run_utc"):
        cutoff_dt = datetime.fromisoformat(state["last_run_utc"])
        hours = max(1, int((datetime.now(timezone.utc) - cutoff_dt).total_seconds() // 3600) + 1)
        window_desc = f"since last run ({local_time_str(cutoff_dt)})"
    else:
        hours = config["hours"]
        window_desc = f"last {hours}h"

    raw_items, errors = gather(sources, hours, state)

    if config["dedup"]["enabled"]:
        merged = dedupe_items(raw_items, config["dedup"]["similarity_threshold"], config["dedup"]["window_hours"])
    else:
        merged = [{**it, "sources": [{"name": it["source"], "link": it["link"]}]} for it in raw_items]
    dedup_saved = len(raw_items) - len(merged)

    if config["no_repeat"]:
        merged = filter_unseen(merged, state)

    scored = build_scored_list(merged, config["keywords"])

    run_time = datetime.now().astimezone()
    meta = {
        "run_time": run_time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "window_desc": window_desc,
        "dedup_saved": dedup_saved,
        "tiers": config["tiers"],
        "keywords": config["keywords"],
    }

    print_console(scored, errors, meta, config["top_count"])

    os.makedirs(config["output_dir"], exist_ok=True)
    stamp = run_time.strftime("%Y-%m-%d_%H%M%S")
    if os.path.exists(os.path.join(config["output_dir"], f"digest_{stamp}.json")):
        stamp += f"_{int(time.time() * 1000) % 1000:03d}"  # sub-second disambiguator, only if needed
    md_report = build_markdown(scored, errors, meta, config["top_count"])
    html_report = build_html(scored, errors, meta, config["top_count"])
    json_report = build_json(scored, errors, meta)

    if config["formats"].get("markdown", True):
        with open(os.path.join(config["output_dir"], f"digest_{stamp}.md"), "w", encoding="utf-8") as f:
            f.write(md_report)
    if config["formats"].get("html", True):
        with open(os.path.join(config["output_dir"], f"digest_{stamp}.html"), "w", encoding="utf-8") as f:
            f.write(html_report)
    if config["formats"].get("json", True):
        with open(os.path.join(config["output_dir"], f"digest_{stamp}.json"), "w", encoding="utf-8") as f:
            f.write(json_report)
    print(f"Saved: {config['output_dir']}/digest_{stamp}.{{md,html,json}}")

    if args.email:
        send_email(config, scored, meta, md_report, html_report)
    if args.webhook:
        send_webhook(config, scored, meta)

    state["last_run_utc"] = datetime.now(timezone.utc).isoformat()
    save_state(config["state_file"], state, config["seen_retention_days"])
    return scored, errors


def run_daemon(args, config):
    print("Daemon mode started. Ctrl+C to stop.")
    interval_hours = config["daemon"].get("interval_hours")
    while True:
        try:
            if interval_hours:
                run_once(args, config)
                sleep_s = interval_hours * 3600
            else:
                run_at = config["daemon"].get("run_at", "07:00")
                hh, mm = [int(x) for x in run_at.split(":")]
                now = datetime.now()
                target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if target <= now:
                    target += timedelta(days=1)
                sleep_s = (target - now).total_seconds()
                print(f"Next run at {target.strftime('%Y-%m-%d %H:%M')} (sleeping {sleep_s/3600:.1f}h)")
            # sleep in chunks so Ctrl+C is responsive
            while sleep_s > 0:
                chunk = min(sleep_s, 3600)
                time.sleep(chunk)
                sleep_s -= chunk
            if interval_hours:
                continue
            run_once(args, config)
        except KeyboardInterrupt:
            print("\nDaemon stopped.")
            break
        except Exception as e:
            print(f"Daemon run failed: {e} — retrying in 15 min.")
            time.sleep(900)


# ==========================================================================
# SELFTEST — validates dedup/scoring/report logic with fixture data, no network
# ==========================================================================
def selftest():
    print("Running selftest (no network calls)...")
    now = datetime.now(timezone.utc)
    fixture = [
        {"source": "The Hacker News", "tier": "cve", "title": "CVE-2026-1234: RCE in Example CMS",
         "link": "https://a.example/1", "published_utc": now, "summary": "Attackers exploit deserialization flaw.",
         "is_kev": True, "cvss": 9.8},
        {"source": "Bleeping Computer", "tier": "cve", "title": "CVE-2026-1234 exploited in the wild, CISA warns",
         "link": "https://b.example/1", "published_utc": now - timedelta(hours=1), "summary": "Second report of the same flaw.",
         "is_kev": False, "cvss": 9.8},
        {"source": "TechCrunch", "tier": "tech", "title": "Startup raises $50M for widget factory",
         "link": "https://c.example/1", "published_utc": now, "summary": "Unrelated funding news.",
         "is_kev": False, "cvss": None},
        {"source": "IGN", "tier": "gaming", "title": "New RPG announced at showcase",
         "link": "https://d.example/1", "published_utc": now, "summary": "A totally different unrelated title.",
         "is_kev": False, "cvss": None},
    ]

    merged = dedupe_items(fixture, threshold=0.82, window_hours=48)
    assert len(merged) == 3, f"expected 3 merged groups (2 CVE dupes -> 1), got {len(merged)}"
    cve_group = next(m for m in merged if extract_cve(m["title"]))
    assert len(cve_group["sources"]) == 2, "CVE duplicate across 2 sources should merge into 1 item with 2 sources"
    assert cve_group["is_kev"] is True, "merged group should inherit is_kev=True from either member"
    print("  [PASS] dedupe_items merges same-CVE stories across sources")

    scored = build_scored_list(merged, keywords=["widget"])
    tech_item = next(i for i in scored if "widget" in i["title"].lower())
    assert tech_item["matches"] == ["widget"], "keyword match should be detected"
    assert cve_group["cvss"] == 9.8
    top_scores = sorted(scored, key=lambda x: x["score"], reverse=True)
    assert top_scores[0]["cvss"] == 9.8 or top_scores[0]["matches"], "highest-scored item should be the critical CVE or keyword match"
    print("  [PASS] scoring: keyword matches and CVSS/KEV boosts applied correctly")

    meta = {"run_time": "TEST", "window_desc": "test window", "dedup_saved": len(fixture) - len(merged)}
    md = build_markdown(scored, [], meta, top_count=10)
    assert "CVE-2026-1234" in md and "🔥 Priority" in md
    h = build_html(scored, [], meta, top_count=10)
    assert "<html" in h and "CVE-2026-1234" in h
    j = build_json(scored, [], meta)
    parsed = json.loads(j)
    assert len(parsed["items"]) == 3
    print("  [PASS] markdown/html/json report builders produce valid output")

    state_path = "/tmp/_secnews_selftest_state.json"
    state = {"last_run_utc": None, "seen_links": {}, "feed_cache": {}}
    fresh1 = filter_unseen(merged, state)
    assert len(fresh1) == 3, "first pass: nothing seen yet, all items should pass through"
    fresh2 = filter_unseen(merged, state)
    assert len(fresh2) == 0, "second pass: everything already seen, should be filtered out"
    save_state(state_path, state, retention_days=21)
    reloaded = load_state(state_path)
    assert reloaded["seen_links"] == state["seen_links"]
    os.remove(state_path)
    print("  [PASS] state persistence: no-repeat filtering + save/load round-trip")

    cfg = load_config(None)
    assert cfg["hours"] == 24 and "daily" in cfg["tiers"]
    deep_update(cfg, {"email": {"enabled": True}, "hours": 6})
    assert cfg["email"]["enabled"] is True and cfg["hours"] == 6 and cfg["email"]["smtp_host"] == "smtp.gmail.com"
    print("  [PASS] config defaults + deep_update merge correctly")

    assert extract_cve("Something CVE-2025-9999 happened") == "CVE-2025-9999"
    assert normalize_title("Hello, World!!  2026") == "hello world 2026"
    print("  [PASS] text helpers (CVE extraction, title normalization)")

    print("\nAll selftest checks passed.")


# ==========================================================================
# CLI
# ==========================================================================
def main():
    parser = argparse.ArgumentParser(description="News & threat-intel aggregator with dedup, scoring, and automation.")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config (default: config.yaml if present)")
    parser.add_argument("--hours", type=int, default=None, help="Lookback window in hours (overrides config)")
    parser.add_argument("--tier", type=str, default=None, help=f"Comma-separated tiers. Available: {', '.join(VALID_TIERS)}")
    parser.add_argument("--keywords", type=str, default=None, help="Comma-separated keywords to add for this run")
    parser.add_argument("--output-dir", type=str, default=None)
    parser.add_argument("--top", type=int, default=None, help="Number of items in the Priority section")
    parser.add_argument("--no-dedup", action="store_true", help="Disable cross-source duplicate merging")
    parser.add_argument("--since-last", action="store_true", help="Use time since last successful run instead of --hours")
    parser.add_argument("--email", action="store_true", help="Send the digest by email (requires config)")
    parser.add_argument("--webhook", action="store_true", help="Post the digest to Slack/Discord (requires config)")
    parser.add_argument("--daemon", action="store_true", help="Run forever, firing on the schedule in config.daemon")
    parser.add_argument("--check-feeds", action="store_true", help="Health-check every configured feed and exit")
    parser.add_argument("--search", type=str, default=None, help="Search archived reports for a term and exit")
    parser.add_argument("--list-sources", action="store_true", help="List configured sources and exit")
    parser.add_argument("--selftest", action="store_true", help="Run internal logic tests with fixture data (no network) and exit")
    args = parser.parse_args()

    if args.selftest:
        selftest()
        return

    if args.list_sources:
        for s in SOURCES:
            print(f"[{s['tier']}] {s['name']} -> {s['url']}")
        return

    config = load_config(args.config)
    if args.hours is not None:
        config["hours"] = args.hours
    if args.tier:
        wanted = set(t.strip() for t in args.tier.split(","))
        unknown = wanted - set(VALID_TIERS)
        if unknown:
            print(f"Unknown tier(s): {', '.join(unknown)}. Available: {', '.join(VALID_TIERS)}")
            sys.exit(1)
        config["tiers"] = sorted(wanted)
    if args.keywords:
        config["keywords"] = list(config["keywords"]) + [k.strip() for k in args.keywords.split(",") if k.strip()]
    if args.output_dir:
        config["output_dir"] = args.output_dir
    if args.top is not None:
        config["top_count"] = args.top
    if args.no_dedup:
        config["dedup"]["enabled"] = False

    if args.check_feeds:
        check_feeds()
        return
    if args.search:
        search_archive(config["output_dir"], args.search)
        return
    if args.daemon:
        run_daemon(args, config)
        return

    run_once(args, config)


if __name__ == "__main__":
    main()