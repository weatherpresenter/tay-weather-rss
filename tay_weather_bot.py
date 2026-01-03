#!/usr/bin/env python3
"""
Tay Township Weather Bot
- Source of truth: Environment Canada Battleboard RSS (ALERT_FEED_URL)
- From RSS, use related report link (e.g., https://weather.gc.ca/warnings/report_e.html?onrm94)
- Parse report page SOURCE for alert JSON-ish payload and extract:
    * headline sentence
    * What (first N lines)
    * When (single line)
- Build X + Facebook messages to match exact formatting requested
- Post:
    * X: OAuth2 for /2/tweets, OAuth1 for media upload
    * Facebook: Graph API /{page_id}/feed
- Safety:
    * global cooldown to avoid spam / FB 368
    * per-platform hash so unchanged text isn't reposted
- Images:
    * pull 511on camera images, overlay logo, upload to X
"""

import datetime as dt
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from io import BytesIO
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from PIL import Image
from requests_oauthlib import OAuth1
import xml.etree.ElementTree as ET

# ----------------------------
# Env / Config
# ----------------------------
UA = os.getenv("UA", "tay-weather-bot/3.0 (+https://weatherpresenter.github.io/tay-weather-rss/tay/)")
TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "25"))

ALERT_FEED_URL = os.getenv("ALERT_FEED_URL", "https://weather.gc.ca/rss/battleboard/onrm94_e.xml")
TAY_ALERTS_URL = os.getenv("TAY_ALERTS_URL", "https://weatherpresenter.github.io/tay-weather-rss/tay/")

ENABLE_X_POSTING = os.getenv("ENABLE_X_POSTING", "false").lower() == "true"
ENABLE_FB_POSTING = os.getenv("ENABLE_FB_POSTING", "false").lower() == "true"
TEST_TWEET = os.getenv("TEST_TWEET", "false").lower() == "true"

# Posting frequency protection
MIN_POST_INTERVAL_MINUTES = int(os.getenv("MIN_POST_INTERVAL_MINUTES", "60"))

# X OAuth2 (posting)
X_CLIENT_ID = os.getenv("X_CLIENT_ID", "")
X_CLIENT_SECRET = os.getenv("X_CLIENT_SECRET", "")
X_REFRESH_TOKEN = os.getenv("X_REFRESH_TOKEN", "")

# X OAuth1 (media)
X_API_KEY = os.getenv("X_API_KEY", "")
X_API_SECRET = os.getenv("X_API_SECRET", "")
X_ACCESS_TOKEN = os.getenv("X_ACCESS_TOKEN", "")
X_ACCESS_TOKEN_SECRET = os.getenv("X_ACCESS_TOKEN_SECRET", "")

# Facebook
FB_PAGE_ID = os.getenv("FB_PAGE_ID", "")
FB_PAGE_ACCESS_TOKEN = os.getenv("FB_PAGE_ACCESS_TOKEN", "")

# Camera images (511on)
CR29_NORTH_IMAGE_URL = os.getenv("CR29_NORTH_IMAGE_URL", "https://511on.ca/map/Cctv/400")
CR29_SOUTH_IMAGE_URL = os.getenv("CR29_SOUTH_IMAGE_URL", "https://511on.ca/map/Cctv/402")

# Logo overlay
LOGO_PATH = os.getenv("LOGO_PATH", "assets/logo.png")
LOGO_SCALE = float(os.getenv("LOGO_SCALE", "0.18"))   # fraction of image width
LOGO_MARGIN = int(os.getenv("LOGO_MARGIN", "18"))     # px
LOGO_POSITION = os.getenv("LOGO_POSITION", "bottom-right").lower()

STATE_PATH = os.getenv("STATE_PATH", "state.json")

# X endpoints
X_TOKEN_URL = "https://api.x.com/2/oauth2/token"
X_POST_TWEET_URL = "https://api.x.com/2/tweets"
X_MEDIA_UPLOAD_URL = "https://upload.twitter.com/1.1/media/upload.json"

# Facebook endpoint
FB_FEED_URL_TMPL = "https://graph.facebook.com/v24.0/{page_id}/feed"

# Tay local timezone (America/Toronto)
try:
    from zoneinfo import ZoneInfo
    TZ_TORONTO = ZoneInfo("America/Toronto")
except Exception:
    TZ_TORONTO = None  # fallback; will still run using UTC formatting


# ----------------------------
# Data Structures
# ----------------------------
@dataclass
class ParsedAlert:
    headline: str            # e.g. "Snow Squall Warning"
    location: str            # "Tay Township"
    what_lines: List[str]    # lines under What:
    when_line: str           # single line When:
    issued_dt_local: Optional[dt.datetime]  # for "Issued Jan 2 6:41p"


# ----------------------------
# State helpers
# ----------------------------
def utc_now() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)

def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")

def iso_to_dt(s: str) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return dt.datetime.fromisoformat(s)
    except Exception:
        return None

def load_state(path: str) -> Dict:
    if not os.path.exists(path):
        return {
            "last_social_post_utc": "",
            "last_x_text_hash": "",
            "last_fb_text_hash": "",
        }
    try:
        with open(path, "r", encoding="utf-8") as f:
            st = json.load(f)
        # ensure keys exist
        st.setdefault("last_social_post_utc", "")
        st.setdefault("last_x_text_hash", "")
        st.setdefault("last_fb_text_hash", "")
        return st
    except Exception:
        return {
            "last_social_post_utc": "",
            "last_x_text_hash": "",
            "last_fb_text_hash": "",
        }

def save_state(path: str, state: Dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)

def text_hash(s: str) -> str:
    return hashlib.sha256(s.strip().encode("utf-8")).hexdigest()


# ----------------------------
# Network helpers
# ----------------------------
def http_get(url: str) -> requests.Response:
    return requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT)

def http_get_text(url: str) -> str:
    r = http_get(url)
    r.raise_for_status()
    r.encoding = r.apparent_encoding or "utf-8"
    return r.text


# ----------------------------
# Battleboard RSS → report link
# ----------------------------
def parse_battleboard_report_link(feed_xml: str) -> Optional[str]:
    """
    Find a report link like https://weather.gc.ca/warnings/report_e.html?onrm94
    Strategy:
      - Look for <link> elements or <id> or HTML in content containing 'report_e.html?onrm94'
      - Otherwise fall back to hard-coded pattern based on feed name
    """
    # quick regex first (works even if XML namespaces are annoying)
    m = re.search(r"https?://weather\.gc\.ca/warnings/report_e\.html\?onrm94", feed_xml)
    if m:
        return m.group(0)

    # XML parse for link elements
    try:
        root = ET.fromstring(feed_xml)
        # RSS2 has channel/link; Atom has entry/link href
        # try Atom link rel=alternate
        for el in root.iter():
            tag = el.tag.lower()
            if tag.endswith("link"):
                href = el.attrib.get("href", "") or (el.text or "")
                if "report_e.html?onrm94" in href:
                    return href.strip()
    except Exception:
        pass

    # fallback
    return "https://weather.gc.ca/warnings/report_e.html?onrm94"


# ----------------------------
# Parse report page source for Tay block text
# ----------------------------
def extract_tay_alert_text_from_report_source(html: str) -> Optional[str]:
    """
    The report page includes a big JS/JSON blob containing entries with "text":"...".
    We look for the loc block for Tay area and grab its "text":"...".
    We accept either:
      - name":"Tay Township"
      - or the Midland - Coldwater - Orr Lake region the user showed earlier
    """
    # Prefer Tay Township if present
    patterns = [
        r'"name"\s*:\s*"Tay Township".{0,2500}?"text"\s*:\s*"([^"]+)"',
        r'"name"\s*:\s*"Midland\s*-\s*Coldwater\s*-\s*Orr Lake".{0,4000}?"text"\s*:\s*"([^"]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, html, flags=re.DOTALL)
        if m:
            raw = m.group(1)
            return decode_json_escaped_text(raw)

    # If no name block matched, grab the first "text":"..." that contains "What:" and "When:"
    m2 = re.search(r'"text"\s*:\s*"([^"]*What:\\n[^"]*When:\\n[^"]*)"', html, flags=re.DOTALL)
    if m2:
        return decode_json_escaped_text(m2.group(1))

    return None

def decode_json_escaped_text(s: str) -> str:
    """
    Convert JSON-escaped string fragment into normal text.
    Example contains sequences like '\\n' and maybe unicode escapes.
    """
    try:
        # wrap as JSON string and decode
        return json.loads(f'"{s}"')
    except Exception:
        # fallback minimal
        return s.replace("\\n", "\n").replace('\\"', '"')


def extract_headline_from_report_source(html: str) -> Optional[str]:
    """
    Pull the headline like "Snow squalls continue tonight." or similar.
    We find the first sentence in the alert text before "What:".
    We'll ultimately use the "event type + Warning" from RSS/metadata,
    but this helps when RSS is vague.
    """
    alert_text = extract_tay_alert_text_from_report_source(html)
    if not alert_text:
        return None
    # Take first non-empty line(s) before "What:"
    pre = alert_text.split("What:", 1)[0].strip()
    # First sentence/line
    line = pre.splitlines()[0].strip() if pre else ""
    return line.rstrip(".")


def parse_what_when_from_alert_text(alert_text: str) -> Tuple[List[str], str]:
    """
    From the 'text' block:
        What:
        ...
        When:
        ...
    Return what_lines (list) and when_line (single line)
    """
    # normalize
    t = alert_text.replace("\r\n", "\n").replace("\r", "\n")

    what_lines: List[str] = []
    when_lines: List[str] = []

    # Find section ranges
    m_what = re.search(r"\bWhat:\s*\n", t)
    m_when = re.search(r"\bWhen:\s*\n", t)

    if m_what:
        start = m_what.end()
        end = m_when.start() if m_when else len(t)
        what_block = t[start:end].strip()
        what_lines = [ln.strip() for ln in what_block.splitlines() if ln.strip()]

    if m_when:
        start = m_when.end()
        # "Where:" or end
        m_where = re.search(r"\bWhere:\s*\n", t[m_when.end():])
        end = m_when.end() + (m_where.start() if m_where else len(t[m_when.end():]))
        when_block = t[start:end].strip()
        when_lines = [ln.strip() for ln in when_block.splitlines() if ln.strip()]

    # Collapse when into one line like: "Continuing tonight. Weakening on Saturday morning."
    when_line = " ".join([ln.rstrip(".") + "." for ln in when_lines]).replace("..", ".").strip()
    return what_lines, when_line


# ----------------------------
# Issued time formatting
# ----------------------------
def format_issued_short(local_dt: Optional[dt.datetime]) -> str:
    """
    "Issued Jan 2 6:41p" (matches user examples)
    """
    if not local_dt:
        # fallback to now in Toronto
        dtn = dt.datetime.now(TZ_TORONTO) if TZ_TORONTO else dt.datetime.now()
    else:
        dtn = local_dt

    mon = dtn.strftime("%b")
    day = str(int(dtn.strftime("%d")))
    hour = int(dtn.strftime("%I"))
    minute = dtn.strftime("%M")
    ampm = dtn.strftime("%p").lower()
    ampm_short = "a" if ampm.startswith("a") else "p"
    return f"Issued {mon} {day} {hour}:{minute}{ampm_short}"


# ----------------------------
# Headline rule (add "Warning" if missing)
# ----------------------------
def headline_event_with_level(event_name: str) -> str:
    """
    Ensure we output like "Snow Squall Warning" not just "Snow Squall"
    """
    s = event_name.strip()
    if not s:
        return "Weather information"
    # If already contains Warning/Watch/Advisory/Statement
    if re.search(r"\b(Warning|Watch|Advisory|Statement)\b", s, flags=re.IGNORECASE):
        # title case-ish: keep as-is but normalize spacing
        return re.sub(r"\s+", " ", s).strip()
    # default to Warning
    return f"{s} Warning"


# ----------------------------
# Build post text (matches your exact formatting)
# ----------------------------
HASHTAGS = "#TayTownship #ONStorm"

def build_x_post(alert: ParsedAlert) -> str:
    # X: what first 2 lines, when_line, shorter care sentence
    what = alert.what_lines[:2]
    parts = []
    parts.append(f"🟡 - {alert.headline} in {alert.location}")
    parts.append("")  # blank line
    parts.extend(what)
    if alert.when_line:
        parts.append(alert.when_line)
    parts.append("Please take care, travel only if needed and check on neighbours who may need support.")
    parts.append("")
    parts.append(f"More: {TAY_ALERTS_URL}")
    parts.append(f"{format_issued_short(alert.issued_dt_local)} {HASHTAGS}")
    text = "\n".join(parts).strip()

    # Hard limit 280 (X). If over, trim what lines down to 1, then drop care line.
    if len(text) > 280:
        parts2 = []
        parts2.append(f"🟡 - {alert.headline} in {alert.location}")
        parts2.append("")
        if alert.what_lines:
            parts2.append(alert.what_lines[0])
        if alert.when_line:
            parts2.append(alert.when_line)
        parts2.append("Please take care, travel only if needed.")
        parts2.append("")
        parts2.append(f"More: {TAY_ALERTS_URL}")
        parts2.append(f"{format_issued_short(alert.issued_dt_local)} {HASHTAGS}")
        text = "\n".join(parts2).strip()

    if len(text) > 280:
        # last resort: remove care sentence
        parts3 = []
        parts3.append(f"🟡 - {alert.headline} in {alert.location}")
        parts3.append("")
        if alert.what_lines:
            parts3.append(alert.what_lines[0])
        if alert.when_line:
            parts3.append(alert.when_line)
        parts3.append("")
        parts3.append(f"More: {TAY_ALERTS_URL}")
        parts3.append(f"{format_issued_short(alert.issued_dt_local)} {HASHTAGS}")
        text = "\n".join(parts3).strip()

    return text


def build_fb_post(alert: ParsedAlert) -> str:
    # FB: what first 3 lines, when_line, longer care statement
    what = alert.what_lines[:3]
    parts = []
    parts.append(f"🟡 - {alert.headline} in {alert.location}")
    parts.append("")
    parts.extend(what)
    if alert.when_line:
        parts.append(alert.when_line)
    parts.append("If you can, please stay off the roads and give crews room to work. If you must go out, slow down, leave extra space and keep your lights on. Please check on neighbours who may need help staying warm or getting supplies.")
    parts.append("")
    parts.append(f"More: {TAY_ALERTS_URL}")
    parts.append(f"{format_issued_short(alert.issued_dt_local)} {HASHTAGS}")
    return "\n".join(parts).strip()


# ----------------------------
# Logo overlay on camera images
# ----------------------------
def add_logo_overlay(jpg_bytes: bytes) -> bytes:
    if not os.path.exists(LOGO_PATH):
        print(f"⚠️ Logo file not found at {LOGO_PATH} — uploading original image.")
        return jpg_bytes

    base = Image.open(BytesIO(jpg_bytes)).convert("RGBA")
    logo = Image.open(LOGO_PATH).convert("RGBA")

    target_w = max(1, int(base.size[0] * LOGO_SCALE))
    ratio = target_w / max(1, logo.size[0])
    target_h = max(1, int(logo.size[1] * ratio))
    logo = logo.resize((target_w, target_h), Image.LANCZOS)

    if "left" in LOGO_POSITION:
        x = LOGO_MARGIN
    else:
        x = base.size[0] - logo.size[0] - LOGO_MARGIN

    if "top" in LOGO_POSITION:
        y = LOGO_MARGIN
    else:
        y = base.size[1] - logo.size[1] - LOGO_MARGIN

    base.alpha_composite(logo, (x, y))

    out = BytesIO()
    base.convert("RGB").save(out, format="JPEG", quality=90, optimize=True)
    return out.getvalue()


def fetch_camera_jpeg(url: str) -> bytes:
    r = http_get(url)
    r.raise_for_status()
    return r.content


# ----------------------------
# X OAuth2 token refresh
# ----------------------------
def get_oauth2_access_token() -> str:
    """
    Use refresh token to get an OAuth2 access token for posting.
    If refresh token rotates, write new refresh token to file so workflow can update secret.
    """
    if not (X_CLIENT_ID and X_CLIENT_SECRET and X_REFRESH_TOKEN):
        raise RuntimeError("Missing X OAuth2 env vars (X_CLIENT_ID, X_CLIENT_SECRET, X_REFRESH_TOKEN)")

    auth = (X_CLIENT_ID, X_CLIENT_SECRET)
    data = {
        "grant_type": "refresh_token",
        "refresh_token": X_REFRESH_TOKEN,
    }
    r = requests.post(X_TOKEN_URL, auth=auth, data=data, headers={"User-Agent": UA}, timeout=TIMEOUT)
    print(f"X token refresh status: {r.status_code}")

    if r.status_code != 200:
        try:
            print("X token refresh error body:", r.text)
        except Exception:
            pass
        raise requests.HTTPError(f"{r.status_code} Client Error: token refresh failed", response=r)

    payload = r.json()
    access_token = payload.get("access_token", "")
    if not access_token:
        raise RuntimeError("No access_token returned from X token refresh")

    new_refresh = payload.get("refresh_token")
    if new_refresh and new_refresh != X_REFRESH_TOKEN:
        print("⚠️ X refresh token rotated. Workflow will update the repo secret.")
        with open("x_refresh_token_rotated.txt", "w", encoding="utf-8") as f:
            f.write(new_refresh)

    return access_token


def x_upload_media(jpg_bytes: bytes) -> str:
    """
    Upload media to X using OAuth1 (upload.twitter.com)
    """
    if not (X_API_KEY and X_API_SECRET and X_ACCESS_TOKEN and X_ACCESS_TOKEN_SECRET):
        raise RuntimeError("Missing X OAuth1 env vars for media upload")

    oauth = OAuth1(X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET)
    r = requests.post(
        X_MEDIA_UPLOAD_URL,
        auth=oauth,
        files={"media": jpg_bytes},
        headers={"User-Agent": UA},
        timeout=TIMEOUT,
    )
    print(f"X media upload status: {r.status_code}")
    r.raise_for_status()
    media_id = r.json().get("media_id_string") or str(r.json().get("media_id"))
    if not media_id:
        raise RuntimeError("No media_id returned from X media upload")
    return media_id


def x_post_tweet(text: str, media_ids: Optional[List[str]] = None) -> bool:
    token = get_oauth2_access_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": UA}
    payload: Dict = {"text": text}
    if media_ids:
        payload["media"] = {"media_ids": media_ids}

    if TEST_TWEET:
        print("TEST_TWEET=true; skipping actual X post.")
        return False

    r = requests.post(X_POST_TWEET_URL, headers=headers, json=payload, timeout=TIMEOUT)
    print(f"X POST /2/tweets status: {r.status_code}")
    r.raise_for_status()
    return True


# ----------------------------
# Facebook posting
# ----------------------------
def fb_post_message(message: str) -> bool:
    if not (FB_PAGE_ID and FB_PAGE_ACCESS_TOKEN):
        raise RuntimeError("Missing FB_PAGE_ID / FB_PAGE_ACCESS_TOKEN")

    if TEST_TWEET:
        print("TEST_TWEET=true; skipping actual Facebook post.")
        return False

    url = FB_FEED_URL_TMPL.format(page_id=FB_PAGE_ID)
    data = {"message": message, "access_token": FB_PAGE_ACCESS_TOKEN}
    r = requests.post(url, data=data, headers={"User-Agent": UA}, timeout=TIMEOUT)
    print(f"FB POST /feed status: {r.status_code}")

    if r.status_code != 200:
        # Show error body to logs but don't crash the whole run (FB can rate limit)
        try:
            print("⚠️ Facebook post error:", r.text)
        except Exception:
            pass
        return False

    return True


# ----------------------------
# Build alert from live sources
# ----------------------------
def parse_alert() -> ParsedAlert:
    # 1) Get battleboard feed
    feed_xml = http_get_text(ALERT_FEED_URL)

    # 2) Find report link
    report_url = parse_battleboard_report_link(feed_xml)
    if not report_url:
        raise RuntimeError("Could not find report URL from battleboard feed")

    # 3) Fetch report source
    report_html = http_get_text(report_url)

    # 4) Extract the key alert text blob for Tay area
    alert_text = extract_tay_alert_text_from_report_source(report_html)
    if not alert_text:
        raise RuntimeError("Could not extract Tay alert text from report page source")

    # 5) Parse What/When
    what_lines, when_line = parse_what_when_from_alert_text(alert_text)

    # 6) Determine headline event type
    #    Prefer the event name from report headline; then normalize to "Warning"
    report_headline = extract_headline_from_report_source(report_html) or ""
    # Try to infer event type from the headline sentence
    # Example headline sentence: "Snow squalls continue tonight."
    inferred_event = ""
    if report_headline:
        if "snow squall" in report_headline.lower():
            inferred_event = "Snow Squall"
        elif "winter storm" in report_headline.lower():
            inferred_event = "Winter Storm"
        elif "rain" in report_headline.lower():
            inferred_event = "Rain"
        elif "freezing" in report_headline.lower():
            inferred_event = "Freezing Rain"

    headline = headline_event_with_level(inferred_event or "Weather")

    # 7) issued time: try from battleboard feed <pubDate> (first item)
    issued_local = None
    try:
        # RSS2 pubDate example; try regex rather than namespaces
        m = re.search(r"<pubDate>([^<]+)</pubDate>", feed_xml)
        if m:
            import email.utils
            issued_dt = email.utils.parsedate_to_datetime(m.group(1).strip())
            if issued_dt.tzinfo is None:
                issued_dt = issued_dt.replace(tzinfo=dt.timezone.utc)
            if TZ_TORONTO:
                issued_local = issued_dt.astimezone(TZ_TORONTO)
            else:
                issued_local = issued_dt
    except Exception:
        issued_local = None

    return ParsedAlert(
        headline=headline,
        location="Tay Township",
        what_lines=what_lines,
        when_line=when_line,
        issued_dt_local=issued_local,
    )


# ----------------------------
# Main
# ----------------------------
def main() -> None:
    state = load_state(STATE_PATH)

    alert = parse_alert()

    x_text = build_x_post(alert)
    fb_text = build_fb_post(alert)

    print("X preview:\n" + x_text + "\n")
    print("FB preview:\n" + fb_text + "\n")

    # Cooldown + unchanged protection
    x_hash = text_hash(x_text)
    fb_hash = text_hash(fb_text)

    last_post_dt = iso_to_dt(state.get("last_social_post_utc", ""))
    too_soon = False
    if last_post_dt:
        mins = (utc_now() - last_post_dt).total_seconds() / 60.0
        too_soon = mins < MIN_POST_INTERVAL_MINUTES

    same_x = state.get("last_x_text_hash", "") == x_hash
    same_fb = state.get("last_fb_text_hash", "") == fb_hash

    posted_x = False
    posted_fb = False

    if too_soon:
        print(f"⚠️ Global cooldown: last post was < {MIN_POST_INTERVAL_MINUTES} minutes ago. Skipping X/FB.")
        save_state(STATE_PATH, state)
        return

    # Post to X (with images)
    if ENABLE_X_POSTING and not same_x and not TEST_TWEET:
        try:
            # Fetch camera images and overlay logo
            cam_urls = [CR29_NORTH_IMAGE_URL, CR29_SOUTH_IMAGE_URL]
            media_ids: List[str] = []
            for u in cam_urls:
                jpg = fetch_camera_jpeg(u)
                jpg2 = add_logo_overlay(jpg)
                media_ids.append(x_upload_media(jpg2))

            posted_x = x_post_tweet(x_text, media_ids=media_ids)
            if posted_x:
                state["last_x_text_hash"] = x_hash
        except Exception as e:
            print(f"⚠️ X skipped: {type(e).__name__}: {e}")
    else:
        if not ENABLE_X_POSTING:
            print("X skipped: ENABLE_X_POSTING=false")
        elif TEST_TWEET:
            print("X skipped: TEST_TWEET=true")
        elif same_x:
            print("X skipped: post text unchanged.")

    # Post to Facebook
    if ENABLE_FB_POSTING and not same_fb and not TEST_TWEET:
        try:
            posted_fb = fb_post_message(fb_text)
            if posted_fb:
                state["last_fb_text_hash"] = fb_hash
        except Exception as e:
            print(f"⚠️ Facebook skipped: {type(e).__name__}: {e}")
    else:
        if not ENABLE_FB_POSTING:
            print("Facebook skipped: ENABLE_FB_POSTING=false")
        elif TEST_TWEET:
            print("Facebook skipped: TEST_TWEET=true")
        elif same_fb:
            print("Facebook skipped: post text unchanged.")

    # Update last post time if anything posted
    if posted_x or posted_fb:
        state["last_social_post_utc"] = utc_now_iso()

    save_state(STATE_PATH, state)

    sent_count = int(bool(posted_x)) + int(bool(posted_fb))
    print(f"Social posts sent: {sent_count}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Fail loud so GH Actions shows red when parsing is broken
        print(f"ERROR: {type(e).__name__}: {e}")
        raise
