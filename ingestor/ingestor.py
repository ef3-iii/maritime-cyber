"""
MTS Cyber Ops Center — Intelligence Ingestor
Polls all 12 sources every 10 minutes and writes to Supabase.
Runs via GitHub Actions on a scheduled workflow.

Environment variables required (set as GitHub Actions secrets):
  SUPABASE_URL      — https://yourproject.supabase.co
  SUPABASE_KEY      — service_role key (NOT anon key)
  NTFY_TOPIC        — mts-cyber-alerts (or your custom topic)
  OTX_API_KEY       — AlienVault OTX API key (free at otx.alienvault.com)
"""

import os
import hashlib
import logging
from datetime import datetime, timezone, timedelta

import feedparser
import httpx
from supabase import create_client, Client

# ── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
log = logging.getLogger("mts-ingestor")

# ── SUPABASE CLIENT ───────────────────────────────────────────────────────────
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
NTFY_TOPIC   = os.environ.get("NTFY_TOPIC", "mts-cyber-alerts")
OTX_API_KEY  = os.environ.get("OTX_API_KEY", "")

sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── KEYWORD FILTERS ───────────────────────────────────────────────────────────
IRAN_KEYWORDS = {
    "iran", "irgc", "cyberav3ngers", "pioneer kitten", "fox kitten",
    "oilrig", "apt34", "muddywater", "unc1549", "nimbus manticore",
    "roaring lion", "epic fury", "tehran", "isfahan", "khamenei",
    "ransomhub", "persian", "islamic revolutionary"
}

MARITIME_KEYWORDS = {
    "port", "terminal", "vessel", "maritime", "shipping", "coast guard",
    "mtsa", "offshore", "marine", "harbor", "harbour", "dock", "cargo",
    "tanker", "container ship", "ais", "vts", "mts", "seaport",
    "marinelink", "shipuniverse", "longshoremen", "uscg"
}

ICS_KEYWORDS = {
    "scada", "ics", "ot attack", "unitronics", "plc", "hmi", "dcs",
    "historian", "modbus", "dnp3", "industrial control", "operational technology"
}

CRITICAL_KEYWORDS = {
    "confirmed attack", "emergency directive", "wiper", "ransomware deployed",
    "cyberattack", "data encrypted", "systems offline", "breach confirmed",
    "missile strike", "ballistic missile", "kinetic"
}

HIGH_KEYWORDS = {
    "advisory", "irgc", "hacktivist", "ddos", "new vulnerability",
    "exploitation", "threat actor", "ics", "scada", "warning issued"
}

MTS_SECTORS = {
    "port", "terminal", "shipping", "maritime", "logistics", "vessel",
    "offshore", "transport", "harbor", "cargo", "tanker", "dock"
}

IRAN_NEXUS_GROUPS = {
    "ransomhub", "pioneer kitten", "fox kitten", "alphv", "blackcat",
    "cyberav3ngers", "homeland justice", "oilrig", "apt34", "muddywater"
}

# ── RSS FEED SOURCES ──────────────────────────────────────────────────────────
RSS_FEEDS = {
    "Al Jazeera":   "https://www.aljazeera.com/xml/rss/all.xml",
    "BBC":          "https://feeds.bbci.co.uk/news/world/rss.xml",
    "AP News":      "https://feeds.apnews.com/rss/apf-intlnews",
    "Sky News":     "https://feeds.skynews.com/feeds/rss/world.xml",
    "MarineLink":   "https://www.marinelink.com/rss/news",
    "ShipUniverse": "https://www.shipuniverse.com/feed",
    "CISA":         "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}

# ── HELPERS ───────────────────────────────────────────────────────────────────
def normalize(text: str) -> str:
    return text.lower().strip()

def keyword_hit(text: str, keywords: set) -> bool:
    t = normalize(text)
    return any(kw in t for kw in keywords)

def score_item(title: str, summary: str) -> dict:
    """
    Returns scoring dict:
      tier          — 1/2/3 or 0 (skip)
      iran_nexus    — bool
      mts_relevant  — bool
      country       — best guess
    """
    combined = f"{title} {summary}"
    iran_hit     = keyword_hit(combined, IRAN_KEYWORDS)
    maritime_hit = keyword_hit(combined, MARITIME_KEYWORDS)
    ics_hit      = keyword_hit(combined, ICS_KEYWORDS)
    critical_hit = keyword_hit(combined, CRITICAL_KEYWORDS)
    high_hit     = keyword_hit(combined, HIGH_KEYWORDS)

    # Must have at least one relevance signal
    if not any([iran_hit, maritime_hit, ics_hit]):
        return {"tier": 0}

    if critical_hit:
        tier = 1
    elif high_hit or ics_hit:
        tier = 2
    else:
        tier = 3

    # Escalate: maritime + iran = always tier 1
    if maritime_hit and iran_hit and tier > 1:
        tier = 1

    country = "IR" if iran_hit else None

    return {
        "tier":         tier,
        "iran_nexus":   iran_hit,
        "mts_relevant": maritime_hit or ics_hit,
        "country":      country,
    }

def url_hash(url: str) -> str:
    """Stable dedup key from URL."""
    return hashlib.sha256(url.encode()).hexdigest()[:16]

def send_ntfy(tier: int, title_str: str, message: str, source: str = "") -> bool:
    priority_map = {1: "urgent", 2: "high", 3: "default"}
    tags_map     = {1: "rotating_light,shield", 2: "warning,anchor", 3: "memo"}
    try:
        r = httpx.post(
            f"https://ntfy.sh/{NTFY_TOPIC}",
            content=f"{message[:220]}\nSource: {source}"[:300],
            headers={
                "Title":    title_str,
                "Priority": priority_map[tier],
                "Tags":     tags_map[tier],
            },
            timeout=10,
        )
        return r.status_code == 200
    except Exception as e:
        log.warning(f"ntfy send failed: {e}")
        return False

# ── INGEST: RSS FEEDS ─────────────────────────────────────────────────────────
def ingest_rss() -> int:
    inserted = 0
    cutoff   = datetime.now(timezone.utc) - timedelta(hours=2)

    for source_name, feed_url in RSS_FEEDS.items():
        log.info(f"Fetching RSS: {source_name}")
        try:
            feed = feedparser.parse(feed_url)
        except Exception as e:
            log.warning(f"RSS parse failed [{source_name}]: {e}")
            continue

        for entry in feed.entries[:20]:
            title   = entry.get("title",   "")[:500]
            summary = entry.get("summary", "")[:2000]
            url     = entry.get("link",    "")

            if not url or not title:
                continue

            # Skip stale items
            published = entry.get("published_parsed")
            if published:
                pub_dt = datetime(*published[:6], tzinfo=timezone.utc)
                if pub_dt < cutoff:
                    continue

            score = score_item(title, summary)
            if score["tier"] == 0:
                continue

            row = {
                "source":       source_name,
                "tier":         score["tier"],
                "headline":     title,
                "summary":      summary[:1000],
                "url":          url,
                "iran_nexus":   score["iran_nexus"],
                "mts_relevant": score["mts_relevant"],
                "country":      score.get("country"),
                "tlp":          "WHITE",
            }

            try:
                sb.table("threat_feed").upsert(
                    row, on_conflict="url", ignore_duplicates=True
                ).execute()
                inserted += 1
                log.info(f"  ✓ T{score['tier']} [{source_name}] {title[:60]}")

                # Alert on tier 1 or 2
                if score["tier"] <= 2:
                    title_map = {
                        1: "🔴 MTS CRITICAL ALERT",
                        2: "⚠️ MTS HIGH PRIORITY"
                    }
                    send_ntfy(score["tier"], title_map[score["tier"]], title, source_name)

            except Exception as e:
                log.warning(f"  DB upsert failed [{source_name}]: {e}")

    return inserted

# ── INGEST: RANSOMWARE.LIVE ───────────────────────────────────────────────────
def ingest_ransomware_live() -> int:
    inserted = 0
    log.info("Fetching ransomware.live")
    try:
        r = httpx.get(
            "https://api.ransomware.live/recentvictims",
            timeout=15,
            headers={"User-Agent": "MTS-OpsCenter-Ingestor/1.0"},
        )
        victims = r.json()
    except Exception as e:
        log.warning(f"ransomware.live fetch failed: {e}")
        return 0

    for v in victims:
        victim     = (v.get("victim") or "").strip()
        group      = (v.get("group")  or "").strip()
        sector     = (v.get("activity") or "").strip()

        if not victim or not group:
            continue

        g_lower = group.lower()
        s_lower = f"{sector} {victim}".lower()

        iran_hit = any(ig in g_lower for ig in IRAN_NEXUS_GROUPS)
        mts_hit  = any(ms in s_lower for ms in MTS_SECTORS)

        row = {
            "group_name":   group,
            "victim":       victim,
            "sector":       sector,
            "iran_nexus":   iran_hit,
            "mts_relevant": mts_hit,
            "source_name":  "ransomware.live",
            "source_url":   "https://www.ransomware.live",
        }

        try:
            sb.table("ransomware_victims").upsert(
                row, on_conflict="victim,group_name", ignore_duplicates=True
            ).execute()
            inserted += 1

            if mts_hit or iran_hit:
                tier = 1 if (mts_hit and iran_hit) else 2
                send_ntfy(
                    tier,
                    "🔴 MTS RANSOMWARE VICTIM" if tier == 1 else "⚠️ RANSOMWARE ALERT",
                    f"Victim: {victim} | Group: {group} | Sector: {sector}",
                    "ransomware.live"
                )
        except Exception as e:
            log.warning(f"  DB upsert failed [ransom.live {victim}]: {e}")

    log.info(f"  ransomware.live: {inserted} new victims")
    return inserted

# ── INGEST: RANSOM-DB.COM ─────────────────────────────────────────────────────
def ingest_ransom_db() -> int:
    """
    ransom-db.com does not have a public API — scrapes their recent victims page.
    Degrades gracefully if unavailable.
    """
    inserted = 0
    log.info("Fetching ransom-db.com")
    try:
        r = httpx.get(
            "https://ransom-db.com/recent",
            timeout=15,
            headers={"User-Agent": "MTS-OpsCenter-Ingestor/1.0"},
            follow_redirects=True,
        )
        # Parse HTML — look for victim table rows
        from html.parser import HTMLParser

        class VictimParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.victims = []
                self._in_row = False
                self._cells = []
                self._current_cell = ""

            def handle_starttag(self, tag, attrs):
                if tag == "tr":
                    self._in_row = True
                    self._cells = []
                elif tag == "td" and self._in_row:
                    self._current_cell = ""

            def handle_data(self, data):
                if self._in_row:
                    self._current_cell += data.strip()

            def handle_endtag(self, tag):
                if tag == "td":
                    self._cells.append(self._current_cell)
                    self._current_cell = ""
                elif tag == "tr" and len(self._cells) >= 2:
                    self.victims.append(self._cells[:])
                    self._in_row = False

        parser = VictimParser()
        parser.feed(r.text)

        for cells in parser.victims:
            if len(cells) < 2:
                continue
            group  = cells[0].strip()
            victim = cells[1].strip()
            sector = cells[2].strip() if len(cells) > 2 else ""

            if not victim or not group or victim.lower() in {"victim", "name", "company"}:
                continue

            g_lower = group.lower()
            s_lower = f"{sector} {victim}".lower()
            iran_hit = any(ig in g_lower for ig in IRAN_NEXUS_GROUPS)
            mts_hit  = any(ms in s_lower for ms in MTS_SECTORS)

            row = {
                "group_name":   group,
                "victim":       victim,
                "sector":       sector,
                "iran_nexus":   iran_hit,
                "mts_relevant": mts_hit,
                "source_name":  "ransom-db.com",
                "source_url":   "https://ransom-db.com",
            }

            try:
                sb.table("ransomware_victims").upsert(
                    row, on_conflict="victim,group_name", ignore_duplicates=True
                ).execute()
                inserted += 1
            except Exception:
                pass

    except Exception as e:
        log.warning(f"ransom-db.com fetch failed (non-critical): {e}")

    log.info(f"  ransom-db.com: {inserted} new entries")
    return inserted

# ── INGEST: OTX ALIENVAULT ────────────────────────────────────────────────────
def ingest_otx() -> int:
    if not OTX_API_KEY:
        log.info("OTX_API_KEY not set — skipping OTX ingest")
        return 0

    inserted = 0
    log.info("Fetching OTX AlienVault pulses")

    queries = ["iran", "irgc", "cyberav3ngers", "maritime ics", "pioneer kitten"]
    seen_ids = set()

    for q in queries:
        try:
            r = httpx.get(
                "https://otx.alienvault.com/api/v1/pulses/search",
                params={"q": q, "sort": "-modified", "limit": 10},
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=15,
            )
            data = r.json()
        except Exception as e:
            log.warning(f"OTX fetch failed [{q}]: {e}")
            continue

        for pulse in data.get("results", []):
            pulse_id = pulse.get("id", "")
            if not pulse_id or pulse_id in seen_ids:
                continue
            seen_ids.add(pulse_id)

            tags        = pulse.get("tags", [])
            description = (pulse.get("description") or "")[:500]
            name        = (pulse.get("name") or "")[:300]

            tag_str  = " ".join(t.lower() for t in tags)
            combined = f"{name} {description} {tag_str}"

            iran_rel = keyword_hit(combined, IRAN_KEYWORDS)
            ics_rel  = keyword_hit(combined, ICS_KEYWORDS)
            mts_rel  = keyword_hit(combined, MARITIME_KEYWORDS)

            if not any([iran_rel, ics_rel, mts_rel]):
                continue

            row = {
                "pulse_id":     pulse_id,
                "pulse_name":   name,
                "author":       pulse.get("author_name", ""),
                "tags":         tags,
                "ioc_count":    pulse.get("indicators_count", 0),
                "tlp":          pulse.get("tlp", "white").upper(),
                "modified":     pulse.get("modified"),
                "description":  description,
                "url":          f"https://otx.alienvault.com/pulse/{pulse_id}",
                "iran_related": iran_rel,
                "ics_related":  ics_rel,
                "mts_related":  mts_rel,
            }

            try:
                sb.table("otx_pulses").upsert(
                    row, on_conflict="pulse_id", ignore_duplicates=True
                ).execute()
                inserted += 1
                log.info(f"  ✓ OTX pulse: {name[:60]}")

                if iran_rel and ics_rel:
                    send_ntfy(2, "⚠️ OTX: Iran ICS Pulse",
                              f"{name[:180]} | IOCs: {row['ioc_count']}",
                              f"OTX AlienVault — otx.alienvault.com/pulse/{pulse_id}")
            except Exception as e:
                log.warning(f"  OTX DB upsert failed: {e}")

    log.info(f"  OTX: {inserted} new pulses")
    return inserted

# ── INGEST: PINGDOM OUTAGES ───────────────────────────────────────────────────
def ingest_pingdom() -> int:
    """
    Check Pingdom outages page for infrastructure correlation.
    Flags any outages in maritime, energy, Middle East, or known MTS platforms.
    """
    log.info("Checking Pingdom outages")
    PINGDOM_KEYWORDS = {
        "port", "maritime", "shipping", "energy", "pipeline", "terminal",
        "middle east", "iran", "israel", "gulf", "saudi", "cargo",
        "logistics", "transportation", "harbor"
    }
    try:
        r = httpx.get(
            "https://www.pingdom.com/outages/",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
            follow_redirects=True,
        )
        text = r.text.lower()
        hits = [kw for kw in PINGDOM_KEYWORDS if kw in text]

        if hits:
            log.info(f"  Pingdom: correlation keywords found: {hits}")
            send_ntfy(
                3,
                "ℹ️ Pingdom Outage Correlation",
                f"Infrastructure keywords detected on Pingdom outages page: {', '.join(hits)}. Manual review recommended.",
                "https://www.pingdom.com/outages/"
            )
            return len(hits)
    except Exception as e:
        log.warning(f"Pingdom fetch failed (non-critical): {e}")
    return 0

# ── WRITE METRICS SNAPSHOT ────────────────────────────────────────────────────
def write_metrics_snapshot(new_items: int, sources_ok: int):
    try:
        # Get current totals from DB
        total_res = sb.table("ransomware_victims").select("id", count="exact").execute()
        ytd_res   = sb.table("ransomware_victims").select("id", count="exact")\
                      .gte("created_at", "2026-01-01T00:00:00Z").execute()
        alert_res = sb.table("alert_log").select("id", count="exact")\
                      .gte("sent_at", (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()).execute()

        sb.table("metrics_snapshots").insert({
            "threat_level":       "CRITICAL",
            "iran_internet_pct":  4,
            "ransomware_total":   total_res.count or 0,
            "ransomware_ytd":     ytd_res.count or 0,
            "active_ops":         ["Op Roaring Lion", "Op Epic Fury"],
            "alert_count_24h":    alert_res.count or 0,
            "sources_checked":    sources_ok,
            "new_items_ingested": new_items,
        }).execute()
        log.info(f"Metrics snapshot written — {new_items} new items, {sources_ok} sources")
    except Exception as e:
        log.warning(f"Metrics snapshot failed: {e}")

# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 60)
    log.info("MTS Cyber Ops Ingestor — starting run")
    log.info(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    log.info("=" * 60)

    total_new    = 0
    sources_ok   = 0

    # RSS feeds (7 sources)
    rss_new = ingest_rss()
    total_new  += rss_new
    sources_ok += len(RSS_FEEDS)

    # Ransomware feeds (2 sources)
    rl_new  = ingest_ransomware_live()
    rdb_new = ingest_ransom_db()
    total_new  += rl_new + rdb_new
    sources_ok += 2

    # OTX (1 source)
    otx_new = ingest_otx()
    total_new  += otx_new
    sources_ok += 1 if OTX_API_KEY else 0

    # Pingdom (1 source)
    ingest_pingdom()
    sources_ok += 1

    # Metrics snapshot
    write_metrics_snapshot(total_new, sources_ok)

    log.info("=" * 60)
    log.info(f"Run complete — {total_new} new items ingested from {sources_ok} sources")
    log.info("=" * 60)

if __name__ == "__main__":
    main()
