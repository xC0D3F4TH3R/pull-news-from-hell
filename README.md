# News & Threat-Intel Aggregator

Pulls from the **official RSS/JSON feeds** of trusted sources across
security news, CVEs, malware/attack research, breaches, developer news,
tech news, and gaming. Merges duplicate stories reported by multiple
outlets, flags anything matching your keywords or high-severity CVEs,
and produces a Markdown + HTML + JSON report — automatically, on a
schedule, with no manual step required once it's set up.

Every item includes: headline, publish date/time (your local timezone),
a short summary pulled straight from the publisher's own feed, and a
link back to the original so you can verify it yourself. Nothing is
generated or guessed — if a feed is unreachable it's reported as an
error, never silently faked.

## 1. Setup

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml   # optional but recommended — see below
python3 security_news_aggregator.py --selftest   # sanity-check the logic, no network needed
```

## 2. Run it

```bash
python3 security_news_aggregator.py
```

Default behavior: last 24 hours, all 7 tiers, duplicates merged, saved to
`reports/digest_<timestamp>.{md,html,json}`, plus a console summary.

## 3. Everything it can do

| What | How |
|---|---|
| Filter to specific topics | `--tier cve,malware` (or set `tiers:` in config) |
| Get alerted on specific terms | `--keywords fortinet,vmware` (or `keywords:` in config) — matches get flagged, bolded, and bumped into the Priority section |
| Change the lookback window | `--hours 6` |
| Run only since your last run (no gaps, no manual math) | `--since-last` |
| Skip duplicate merging | `--no-dedup` |
| Email yourself the digest | `--email` (needs `email:` configured, see below) |
| Post to Slack/Discord | `--webhook` (needs `webhook:` configured) |
| Run forever, fire itself daily | `--daemon` |
| Check which feeds are dead | `--check-feeds` |
| Search everything ever collected | `--search "log4j"` |
| See all configured sources | `--list-sources` |
| Verify the tool's logic works | `--selftest` (uses fixture data, makes zero network calls) |

## 4. How the "smart" parts work

**De-duplication.** The same story often breaks on 3+ outlets within an
hour. CVEs are matched by CVE ID; everything else is matched by title
similarity (only within a configurable time window, so it won't merge
unrelated old/new stories that happen to share generic wording). Merged
items show every source that reported it, with links to each.

**Priority scoring.** Every story gets a score from:
- +50 if it matches one of your keywords
- +40 if it's a CISA Known Exploited Vulnerability, or CVSS ≥ 9 (critical)
- +20 for CVSS 7–8.9 (high)
- +8 per additional source reporting the same story (bigger story = more outlets covering it)
- a small recency bonus (fresher stories rank slightly higher)

Anything scoring 40+ lands in the "🔥 Priority & Trending" section at
the top of the report, above the normal per-tier listing.

**No-repeat state.** A `state.json` file remembers every link you've
already been shown. Even if today's `--hours 24` window overlaps
yesterday's, you won't see the same story twice. It also stores each
feed's ETag/Last-Modified so repeat runs send conditional HTTP requests
(politer to the source servers, faster for you) instead of re-downloading
unchanged feeds every time.

## 5. Automating it (three options — pick one)

### Option A — cron (simplest, if you're fine with once/day)
```bash
crontab -e
```
```
0 7 * * * cd /full/path/to/secnews && /usr/bin/python3 security_news_aggregator.py --email >> logs/cron.log 2>&1
```

### Option B — daemon mode (the script schedules itself)
```bash
python3 security_news_aggregator.py --daemon
```
Reads `daemon.run_at` (e.g. `"07:00"`) from `config.yaml` and fires once
a day at that local time, forever, until you stop it. Set
`daemon.interval_hours` instead if you want "every N hours" rather than
a fixed daily time. Survives transient failures (retries in 15 min
rather than crashing).

### Option C — systemd service (daemon mode that survives reboots)
```bash
sudo cp systemd/secnews.service /etc/systemd/system/
sudo nano /etc/systemd/system/secnews.service   # edit the two path lines
sudo systemctl daemon-reload
sudo systemctl enable --now secnews
sudo systemctl status secnews
```

### Windows
Task Scheduler → Daily trigger → Action: `python.exe security_news_aggregator.py --email`,
same as before, or run `--daemon` in a background window / as a scheduled
task at logon.

## 6. Email digest setup

In `config.yaml`:
```yaml
email:
  enabled: true
  smtp_host: smtp.gmail.com
  smtp_port: 587
  smtp_user: you@gmail.com
  password_env: SECNEWS_SMTP_PASSWORD
  from_addr: you@gmail.com
  to_addrs: [you@gmail.com]
```
Then set the password as an environment variable — **never put it in the
config file itself**:
```bash
export SECNEWS_SMTP_PASSWORD="your-app-password"
```
For Gmail specifically, generate an **App Password** at
myaccount.google.com/apppasswords — Gmail rejects plain-password SMTP
login. Any SMTP provider works the same way (Outlook, a transactional
mail service, your own mail server).

## 7. Slack/Discord webhook setup

```yaml
webhook:
  enabled: true
  url_env: SECNEWS_WEBHOOK_URL
```
```bash
export SECNEWS_WEBHOOK_URL="https://hooks.slack.com/services/..."
# or a Discord webhook URL — both auto-detected from the URL
```
Posts the top priority items (score ≥ 40) each run, capped to each
platform's message-length limit.

## 8. Sources by tier

**`daily`** — The Hacker News, Bleeping Computer, KrebsOnSecurity, Dark
Reading, The Record, SecurityWeek, Schneier on Security

**`cve`** — CISA Known Exploited Vulnerabilities catalog, CISA
Cybersecurity Advisories, and NVD's live API (pulls CVEs published in
your window with description + CVSS score directly — no static feed
needed)

**`malware`** — Cisco Talos, Palo Alto Unit 42, Kaspersky Securelist,
ESET WeLiveSecurity, Malwarebytes Labs, SANS Internet Storm Center
(reporting-level technical writeups on how attacks/payloads/ransomware
work — never exploit code)

**`breach`** — DataBreaches.net (breach news also shows up naturally in
`daily` via Krebs/Bleeping/The Record)

**`dev`** — GitHub Blog, Stack Overflow Blog, DEV Community, InfoQ,
freeCodeCamp News, Smashing Magazine, Hacker News (Y Combinator)

**`tech`** — TechCrunch, The Verge, Ars Technica, Wired, MIT Technology
Review, IEEE Spectrum

**`gaming`** — IGN, GameSpot, Eurogamer, PC Gamer, Rock Paper Shotgun,
Kotaku, Polygon

**Deliberately left out:**
- A handful of unverifiable aggregator URLs from earlier drafts of this
  list (`cve.assurestart.co`, `cvefeed.io`, `cvealert.net`,
  `cvedatabase.com`) and social-media list links — couldn't confirm who
  runs them or how stable they are.
- **abuse.ch's URLhaus/MalwareBazaar** — legitimate, but they're raw
  indicator-of-compromise data (malicious URLs/hashes) for SIEMs and
  blocklists, not article-style content. Doesn't fit a "headline +
  summary" report; wire those into a SIEM/firewall separately if wanted.
- Email-only newsletters (tl;dr sec, Risky Business, SANS NewsBites,
  Unsupervised Learning, etc.) — no public RSS feed to pull from.

Two known quirks: Ars Technica/The Verge/IGN's free feeds return
excerpts rather than full text (source-side limit, not a bug), and
Kotaku/Polygon have had recent ownership turbulence — if either feed
goes quiet, `--check-feeds` will tell you.

## 9. Adding or removing sources

Edit the `SOURCES` list near the top of `security_news_aggregator.py`:
```python
{"name": "Some Site", "url": "https://example.com/feed/", "tier": "tech", "kind": "rss"},
```
`kind` is `"rss"` for normal feeds, `"kev_json"` for CISA's KEV-shaped
JSON, or `"nvd_recent"` for NVD's live CVE API pattern.

## 10. Files this creates

```
reports/            one digest_<timestamp>.{md,html,json} per run
state/state.json    seen-links history + per-feed HTTP cache (safe to delete to reset)
logs/                if you redirect cron/daemon output here yourself
```

## 11. Verifying it's actually correct

Run `python3 security_news_aggregator.py --selftest` any time. It
exercises the duplicate-merging, scoring, report generation, and
no-repeat state logic against fixture data — no network required — and
prints PASS/FAIL for each. Useful after editing `SOURCES` or the config,
or just to confirm nothing's silently broken.