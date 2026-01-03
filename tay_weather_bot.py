#!/usr/bin/env python3
"""
Tay Township Weather Bot

Flow (updated):
1) Fetch Environment Canada "battleboard" RSS/ATOM feed (ALERT_FEED_URL)
2) From that feed, find the related href for the warnings report page (e.g. report_e.html?onrm94)
3) Fetch that report page and parse:
   - Alert title/type (e.g. "Snow Squall")
   - Issue time text (e.g. "6:41 PM EST Friday 2 January 2026")
   - "What:" block (sentences)
   - "When:" block (sentences)
4) Build social text:
   - Headline MUST end with: "in Tay Township"
   - Twitter includes What + When + short care line
   - Facebook includes What + When + longer care line
5) Optionally post to X and Facebook (controlled by env toggles).
   - Failures SKIP posting but do NOT crash the whole run (exit 0).

Requirements: requests, beautifulsoup4, requests-oauthlib, Pillow (if you later add image processing)
"""

import base64
import datetime as dt
import email.utils
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from requests_oauthlib import OAuth1


# ----------------------------
# Config / environment
# ----------------------------
ALERT_FEED_URL = os.getenv("ALERT_FEED_URL", "https://weather.gc.ca/rss/battleboard/onrm94_e.xml")
TAY_ALERTS_URL = os.getenv("TAY_ALERTS_URL", "https://weatherpresenter.github.io/tay-weather-rss/tay/")
STATE_PATH = os.getenv("STATE_PATH", "state.json")

ENABLE_X_POSTING = os.getenv("ENABLE_X_POSTING", "false").lower() == "true"
ENABLE_FB_POSTING = os.getenv("ENABLE_FB_POSTING", "false").lower() == "true"
TEST_TWEET = os.getenv("TEST_TWEET", "true").lower() == "true"

# Camera images (optional)
CR29_NORTH_IMAGE_URL = os.getenv("CR29_NORTH_IMAGE_URL", "")
CR29_SOUTH_IMAGE_URL = os.getenv("CR29_SOUTH_IMAGE_URL", "")

# X OAuth2 (posting)
X_CLIENT_ID = os.getenv("X_CLIENT_ID", "")
X_CLIENT_SECRET = os.getenv("X_CLIENT_SECRET", "")
X_REFRESH_TOKEN = os.getenv("X_REFRESH_TOKEN", "")

# X OAuth1 (media upload)
X_API_KEY = os.getenv("X_API_KEY", "")
X_API_SECRET = os.getenv("X_API_SECRET", "")
X_ACCESS_TOKEN = os.getenv("X_ACCESS_TOKEN", "")
X_ACCESS_TOKEN_SECRET = os.getenv("X_ACCESS_TOKEN_SECRET", "")

# Facebook
FB_PAGE_ID = os.getenv("FB_PAGE_ID", "")
FB_PAGE_ACCESS_TOKEN = os.getenv("FB_PAGE_ACCESS_TOKEN", "")

# X endpoints
X_OAUTH2_TOKEN_URL = "https://api.x.com/2/oauth2/token"
X_CREATE_TWEET_URL = "https://api.x.com/2/tweets"
X_MEDIA_UPLOAD_URL = "https://upload.twitter.com/1.1/media/upload.json"

# Requests
UA = "tay-weather-bot/3.0 (+https://github.com/weatherpresenter/tay-weather-rss)"
TIMEOUT = 25


# ----------------------------
# Data models
# ----------------------------
@dataclass
class AlertInfo:
    emoji: str
    event_name: str               # e.g. "Snow Squall"
    issue_time_text: str          # raw from page, e.g. "6:41 PM EST Friday 2 January 2026"
    issue_short: str              # e.g. "Jan 2 6:41p"
    what_sentences: List[str]
    when_sentences: List[str]
    report_url: str


# ----------------------------
# Helpers: state
# ----------------------------
def load_state(path: str) -> dict:
    if not os.path.exists(path):
        return {"last_report_url": "", "last_issue_time_text": "", "last_event_name": ""}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"last_report_url": "", "last_issue_time_text": "", "last_event_name": ""}


def save_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ----------------------------
# Helpers: parsing
# ----------------------------
def fetch(url: str) -> str:
    r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT)
    r.raise_for_status()
    return r.text


def _xml_first(el: ET.Element, xpath: str, ns: dict) -> Optional[ET.Element]:
    found = el.find(xpath, ns)
    return found


def _xml_all(el: ET.Element, xpath: str, ns: dict) -> List[ET.Element]:
    return list(el.findall(xpath, ns))


def discover_report_url_from_feed(feed_xml: str) -> str:
    """
    Find the warnings report URL from battleboard feed.
    We look for <link rel="related" href="...report_e.html?..."> or any link containing report_e.html.
    """
    # Parse with common Atom namespace handling (feed may be Atom or RSS-ish)
    try:
        root = ET.fromstring(feed_xml)
    except Exception as e:
        raise RuntimeError(f"Could not parse feed XML: {e}")

    # Namespaces
    ns = {
        "atom": "http://www.w3.org/2005/Atom",
        "rss": "http://purl.org/rss/1.0/",
    }

    # Try Atom <feed><link ...>
    # Some feeds are <feed xmlns="http://www.w3.org/2005/Atom">
    # In that case tags are {atom}feed, {atom}link, etc.
    def iter_links() -> List[Tuple[str, str]]:
        links = []
        # 1) Atom namespace default
        for link in root.findall(".//{http://www.w3.org/2005/Atom}link"):
            rel = link.attrib.get("rel", "")
            href = link.attrib.get("href", "")
            if href:
                links.append((rel, href))
        # 2) Non-namespaced link tags (just in case)
        for link in root.findall(".//link"):
            rel = link.attrib.get("rel", "")
            href = link.attrib.get("href", "") or (link.text or "")
            href = href.strip()
            if href:
                links.append((rel, href))
        return links

    links = iter_links()

    # Prefer rel="related"
    for rel, href in links:
        if rel.lower() == "related" and "report_e.html" in href:
            return href

    # Any report link
    for rel, href in links:
        if "report_e.html" in href:
            return href

    # As fallback: maybe "warnings/report_e.html?XXXX" appears in text
    m = re.search(r"https?://weather\.gc\.ca/warnings/report_e\.html\?[a-z0-9]+", feed_xml, re.I)
    if m:
        return m.group(0)

    raise RuntimeError("Could not discover warnings report URL from feed.")


def normalize_event_name(raw: str) -> str:
    """
    raw examples from the report page:
      "Yellow Warning - Snow Squall"
      "Red Warning - Tornado"
    We want: "Snow Squall"
    """
    raw = raw.strip()
    raw = re.sub(r"^(Yellow|Red|Orange)\s+Warning\s*-\s*", "", raw, flags=re.I).strip()
    # Some pages might include extra words; keep it tidy
    return raw


def emoji_from_colour_word(colour_word: str) -> str:
    cw = colour_word.strip().lower()
    if cw == "red":
        return "🔴"
    if cw == "orange":
        return "🟠"
    # report page currently says "Yellow Warnings"
    return "🟡"


def parse_issue_short(issue_time_text: str) -> str:
    """
    Input like: "6:41 PM EST Friday 2 January 2026"
    Output like: "Jan 2 6:41p"
    """
    s = issue_time_text.strip()

    # Very forgiving parse:
    # Capture: time hh:mm, AM/PM, day number, month name, year
    m = re.search(
        r"(\d{1,2}:\d{2})\s*([AP]M)\s+\w+\s+\w+\s+(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})",
        s,
        re.I,
    )
    if not m:
        # fallback: keep something usable
        return s

    hhmm = m.group(1)
    ampm = m.group(2).lower()
    day = int(m.group(3))
    month_name = m.group(4)
    year = int(m.group(5))

    # Month short (Jan, Feb, ...)
    try:
        month_dt = dt.datetime.strptime(month_name[:3], "%b")
        mon_short = month_dt.strftime("%b")
    except Exception:
        mon_short = month_name[:3].title()

    # Convert "6:41" + "pm" to "6:41p"
    ampm_short = "a" if ampm.startswith("a") else "p"
    return f"{mon_short} {day} {hhmm}{ampm_short}"


def split_sentences(block: str) -> List[str]:
    """
    Turn a 'What:' or 'When:' block into clean sentences.
    Keep short-ish, trimmed, with trailing periods preserved.
    """
    b = re.sub(r"\s+", " ", block).strip()

    # Split on ". " but keep period
    parts = re.split(r"(?<=[.!?])\s+", b)
    out = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        # Ensure it ends with punctuation if it looks like a sentence fragment
        if not re.search(r"[.!?]$", p):
            p += "."
        out.append(p)
    return out


def parse_report_page(report_html: str, report_url: str) -> AlertInfo:
    """
    Extract:
      - colour + event name
      - issue time
      - What / When blocks
    The content on the report page is often rendered as plain text; we rely on regex over cleaned text.
    Example snippet (from the page):
      "yellow icon Yellow Warning - Snow Squall
       6:41 PM EST Friday 2 January 2026
       ...
       Snow squalls continue tonight. What: Additional... When: Continuing tonight. ..."
    """
    soup = BeautifulSoup(report_html, "html.parser")
    text = soup.get_text("\n")
    text = re.sub(r"[ \t]+", " ", text)

    # Find colour + raw title line: "Yellow Warning - Snow Squall"
    m_title = re.search(r"\b(Yellow|Red|Orange)\s+Warning\s*-\s*([^\n\r]+)", text, re.I)
    if not m_title:
        # fallback: maybe "Yellow Warnings" section then a title line
        m_title = re.search(r"\b(Yellow|Red|Orange)\s+Warnings\b.*?\b(Yellow|Red|Orange)\s+Warning\s*-\s*([^\n\r]+)", text, re.I | re.S)
        if not m_title:
            raise RuntimeError("Could not find alert title (e.g., 'Yellow Warning - ...') on report page.")

    colour_word = m_title.group(1)
    raw_title = f"{colour_word.title()} Warning - {m_title.group(2).strip()}"
    event_name = normalize_event_name(raw_title)
    emoji = emoji_from_colour_word(colour_word)

    # Find issue time line like: "6:41 PM EST Friday 2 January 2026"
    m_issue = re.search(r"\b(\d{1,2}:\d{2}\s*[AP]M\s+\w+\s+\w+\s+\d{1,2}\s+[A-Za-z]+\s+\d{4})\b", text, re.I)
    if not m_issue:
        raise RuntimeError("Could not find issue time text on report page.")
    issue_time_text = m_issue.group(1).strip()
    issue_short = parse_issue_short(issue_time_text)

    # Find What / When blocks
    # We capture:
    #   What: ... When: ... Where:
    # or if Where isn't present, stop at "Additional information:" or "In effect for:"
    m_blocks = re.search(
        r"\bWhat:\s*(.+?)\s*\bWhen:\s*(.+?)(?:\s*\bWhere:\s*|\s*\bAdditional information:\s*|\s*\bIn effect for:\s*)",
        text,
        re.I | re.S,
    )
    if not m_blocks:
        # fallback: try stopping at "For road conditions"
        m_blocks = re.search(
            r"\bWhat:\s*(.+?)\s*\bWhen:\s*(.+?)(?:\s*For road conditions|\s*Please continue to monitor|\s*\bIn effect for:\s*)",
            text,
            re.I | re.S,
        )
    if not m_blocks:
        raise RuntimeError("Could not extract What/When blocks from report page.")

    what_block = m_blocks.group(1).strip()
    when_block = m_blocks.group(2).strip()

    what_sentences = split_sentences(what_block)
    when_sentences = split_sentences(when_block)

    return AlertInfo(
        emoji=emoji,
        event_name=event_name,
        issue_time_text=issue_time_text,
        issue_short=issue_short,
        what_sentences=what_sentences,
        when_sentences=when_sentences,
        report_url=report_url,
    )


# ----------------------------
# Post building
# ----------------------------
CARE_TWITTER = "Please take care, travel only if needed and check on neighbours who may need support."
CARE_FACEBOOK = "If you can, please stay off the roads and give crews room to work. If you must go out, slow down, leave extra space and keep your lights on. Please check on neighbours who may need help staying warm or getting supplies."
HASHTAGS = "#TayTownship #ONStorm"


def build_headline(alert: AlertInfo) -> str:
    # Must end with "in Tay Township"
    return f"{alert.emoji} - {alert.event_name} in Tay Township"


def build_twitter_text(alert: AlertInfo) -> str:
    headline = build_headline(alert)

    # Prefer exactly the look you showed:
    # headline blank line then lines then blank line then More + Issued + hashtags
    lines = [headline, ""]
    for s in alert.what_sentences[:2]:
        lines.append(s)
    for s in alert.when_sentences[:2]:
        lines.append(s)

    lines.append(CARE_TWITTER)
    lines.append("")
    lines.append(f"More: {TAY_ALERTS_URL}")
    lines.append(f"Issued {alert.issue_short} {HASHTAGS}")

    text = "\n".join(lines).strip()

    # Enforce 280 chars: drop extra What/When sentences first, then shorten care.
    if len(text) <= 280:
        return text

    # Rebuild progressively smaller
    def assemble(what_n: int, when_n: int, care: str) -> str:
        ll = [headline, ""]
        for s2 in alert.what_sentences[:what_n]:
            ll.append(s2)
        for s2 in alert.when_sentences[:when_n]:
            ll.append(s2)
        ll.append(care)
        ll.append("")
        ll.append(f"More: {TAY_ALERTS_URL}")
        ll.append(f"Issued {alert.issue_short} {HASHTAGS}")
        return "\n".join(ll).strip()

    # Try fewer lines
    candidates = [
        assemble(2, 1, CARE_TWITTER),
        assemble(1, 1, CARE_TWITTER),
        assemble(1, 1, "Please take care and travel only if needed."),
        assemble(1, 0, "Please take care and travel only if needed."),
        assemble(0, 0, "Please take care and travel only if needed."),
    ]
    for c in candidates:
        if len(c) <= 280:
            return c

    # Last resort hard trim (still keep headline + More + Issued)
    trimmed = assemble(0, 0, "Please take care.").strip()
    if len(trimmed) > 280:
        trimmed = trimmed[:277] + "…"
    return trimmed


def build_facebook_text(alert: AlertInfo) -> str:
    headline = build_headline(alert)
    lines = [headline, ""]
    for s in alert.what_sentences[:3]:
        lines.append(s)
    for s in alert.when_sentences[:2]:
        lines.append(s)
    lines.append(CARE_FACEBOOK)
    lines.append("")
    lines.append(f"More: {TAY_ALERTS_URL}")
    lines.append(f"Issued {alert.issue_short} {HASHTAGS}")
    return "\n".join(lines).strip()


# ----------------------------
# X posting (OAuth2 create tweet + OAuth1 media upload)
# ----------------------------
def get_oauth2_access_token() -> Optional[str]:
    """
    Refresh OAuth2 access token using refresh_token.
    Writes rotated refresh token to x_refresh_token_rotated.txt if present.
    """
    if not (X_CLIENT_ID and X_CLIENT_SECRET and X_REFRESH_TOKEN):
        print("⚠️ X skipped: missing OAuth2 env (X_CLIENT_ID/X_CLIENT_SECRET/X_REFRESH_TOKEN)")
        return None

    basic = base64.b64encode(f"{X_CLIENT_ID}:{X_CLIENT_SECRET}".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": UA,
    }
    data = {
        "grant_type": "refresh_token",
        "refresh_token": X_REFRESH_TOKEN,
    }

    r = requests.post(X_OAUTH2_TOKEN_URL, headers=headers, data=data, timeout=TIMEOUT)
    print(f"X token refresh status: {r.status_code}")
    if r.status_code != 200:
        try:
            print(f"X token refresh error body: {r.text}")
        except Exception:
            pass
        return None

    payload = r.json()
    access_token = payload.get("access_token")
    new_refresh = payload.get("refresh_token")
    if new_refresh and new_refresh != X_REFRESH_TOKEN:
        # let the workflow update the repo secret
        with open("x_refresh_token_rotated.txt", "w", encoding="utf-8") as f:
            f.write(new_refresh)
        print("⚠️ X refresh token rotated. Workflow will update the repo secret.")

    return access_token


def x_upload_media_from_url(image_url: str) -> Optional[str]:
    """
    Uploads media to X using OAuth1. Returns media_id_string.
    """
    if not image_url:
        return None

    if not (X_API_KEY and X_API_SECRET and X_ACCESS_TOKEN and X_ACCESS_TOKEN_SECRET):
        print("⚠️ X media upload skipped: missing OAuth1 env (X_API_KEY/.../X_ACCESS_TOKEN_SECRET)")
        return None

    try:
        img = requests.get(image_url, headers={"User-Agent": UA}, timeout=TIMEOUT)
        img.raise_for_status()
    except Exception as e:
        print(f"⚠️ X media fetch failed ({image_url}): {e}")
        return None

    oauth = OAuth1(X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET)
    files = {"media": img.content}

    r = requests.post(X_MEDIA_UPLOAD_URL, auth=oauth, files=files, timeout=TIMEOUT)
    print(f"X media upload status: {r.status_code}")
    if r.status_code != 200:
        print(f"X media upload error: {r.text}")
        return None

    j = r.json()
    return j.get("media_id_string")


def post_to_x(text: str, image_urls: List[str]) -> bool:
    access_token = get_oauth2_access_token()
    if not access_token:
        print("⚠️ X skipped: X_TOKEN_REFRESH_FAILED")
        return False

    media_ids = []
    for u in image_urls:
        mid = x_upload_media_from_url(u)
        if mid:
            media_ids.append(mid)

    payload = {"text": text}
    if media_ids:
        payload["media"] = {"media_ids": media_ids[:4]}

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "User-Agent": UA,
    }

    r = requests.post(X_CREATE_TWEET_URL, headers=headers, json=payload, timeout=TIMEOUT)
    print(f"X POST /2/tweets status: {r.status_code}")
    if r.status_code not in (200, 201):
        print(f"⚠️ X post error: {r.text}")
        return False

    return True


# ----------------------------
# Facebook posting
# ----------------------------
def fb_post_text(message: str) -> bool:
    if not (FB_PAGE_ID and FB_PAGE_ACCESS_TOKEN):
        print("⚠️ Facebook skipped: missing FB_PAGE_ID/FB_PAGE_ACCESS_TOKEN")
        return False

    url = f"https://graph.facebook.com/v24.0/{FB_PAGE_ID}/feed"
    data = {"message": message, "access_token": FB_PAGE_ACCESS_TOKEN}

    r = requests.post(url, data=data, timeout=TIMEOUT)
    print(f"FB POST /feed status: {r.status_code}")
    if r.status_code not in (200, 201):
        print(f"⚠️ Facebook post error: {r.text}")
        return False
    return True


# ----------------------------
# Main
# ----------------------------
def main() -> int:
    state = load_state(STATE_PATH)

    # 1) Fetch feed
    try:
        feed_xml = fetch(ALERT_FEED_URL)
    except Exception as e:
        print(f"❌ Failed to fetch battleboard feed: {e}")
        return 0  # don't hard-fail workflow

    # 2) Discover report URL from feed
    try:
        report_url = discover_report_url_from_feed(feed_xml)
    except Exception as e:
        print(f"❌ Failed to find report URL from feed: {e}")
        return 0

    # 3) Fetch report page
    try:
        report_html = fetch(report_url)
    except Exception as e:
        print(f"❌ Failed to fetch report page: {e}")
        return 0

    # 4) Parse report page
    try:
        alert = parse_report_page(report_html, report_url)
    except Exception as e:
        print(f"❌ Failed to parse report page: {e}")
        return 0

    # De-dupe: if it's exactly the same as last run (same report URL + same issue time + same event)
    if (
        state.get("last_report_url") == alert.report_url
        and state.get("last_issue_time_text") == alert.issue_time_text
        and state.get("last_event_name") == alert.event_name
    ):
        print("No new alert content (same report + issue time + event). Nothing to do.")
        return 0

    # 5) Build messages
    x_text = build_twitter_text(alert)
    fb_text = build_facebook_text(alert)

    print("X preview:")
    print(x_text)
    print("\nFB preview:")
    print(fb_text)

    # 6) Post (optional)
    image_urls = [u for u in [CR29_NORTH_IMAGE_URL, CR29_SOUTH_IMAGE_URL] if u]

    social_posted = 0
    if ENABLE_X_POSTING and not TEST_TWEET:
        ok = post_to_x(x_text, image_urls=image_urls)
        social_posted += 1 if ok else 0
    elif ENABLE_X_POSTING and TEST_TWEET:
        print("🧪 TEST_TWEET=true: X posting disabled (preview only).")
    else:
        print("X posting disabled.")

    if ENABLE_FB_POSTING and not TEST_TWEET:
        ok = fb_post_text(fb_text)
        social_posted += 1 if ok else 0
    elif ENABLE_FB_POSTING and TEST_TWEET:
        print("🧪 TEST_TWEET=true: Facebook posting disabled (preview only).")
    else:
        print("Facebook posting disabled.")

    # 7) Update state even if social posting failed — this prevents infinite spam retries.
    state["last_report_url"] = alert.report_url
    state["last_issue_time_text"] = alert.issue_time_text
    state["last_event_name"] = alert.event_name
    state["last_run_utc"] = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    save_state(STATE_PATH, state)

    if social_posted == 0:
        print("No social posts sent (skipped/failed), but state updated.")
    else:
        print(f"Social posts sent: {social_posted}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
