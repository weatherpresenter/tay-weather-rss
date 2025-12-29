# tay_weather_bot.py
#
# Tay Township Weather Bot
# - Pulls Environment Canada CAP alerts from Datamart
# - Filters to Tay-area regions (strict allow-list match on CAP <areaDesc>)
# - Writes RSS feed: tay-weather.xml
# - Posts to X (OAuth 2.0 refresh token) and Facebook Page
# - Cooldowns + dedupe + "all clear" support
#
# REQUIRED GitHub Secrets:
#   X_CLIENT_ID
#   X_CLIENT_SECRET
#   X_REFRESH_TOKEN
#
# For Facebook Page posting (Secrets):
#   FB_PAGE_ID
#   FB_PAGE_ACCESS_TOKEN
#
# OPTIONAL (recommended) for auto-updating X_REFRESH_TOKEN when X rotates it:
#   GH_PAT_ACTIONS_SECRETS   -> GitHub Personal Access Token with repo Actions Secrets write
#
# Optional env vars:
#   ENABLE_X_POSTING=true/false
#   ENABLE_FB_POSTING=true/false
#   TEST_TWEET=true   -> posts a test message and exits
#
import base64
import json
import os
import re
import time
import hashlib
import datetime as dt
import email.utils
import xml.etree.ElementTree as ET
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


# ----------------------------
# Feature toggles (via env)
# ----------------------------
ENABLE_X_POSTING = os.getenv("ENABLE_X_POSTING", "true").lower() == "true"
ENABLE_FB_POSTING = os.getenv("ENABLE_FB_POSTING", "false").lower() == "true"
TEST_TWEET = os.getenv("TEST_TWEET", "false").lower() == "true"

INCLUDE_SPECIAL_WEATHER_STATEMENTS = True
INCLUDE_ALERTS = True
STRICT_AREA_MATCH = True  # require CAP <areaDesc> match

# ----------------------------
# Tay / target areas
# ----------------------------
# Exact strings as they appear in CAP <areaDesc>
AREA_ALLOWLIST = [
    # Land (Tay region)
    "Midland - Coldwater - Orr Lake",

    # Marine (include if you want marine alerts)
    "Southern Georgian Bay",
]

# CAP Datamart offices (CWTO = Ontario Storm Prediction Centre)
OFFICES = ["CWTO"]

# Look-back window (hours)
HOURS_BACK_TO_SCAN = 12

# RSS retention
MAX_RSS_ITEMS = 25

# Paths
STATE_PATH = "state.json"
RSS_PATH = "tay-weather.xml"

USER_AGENT = "tay-weather-rss-bot/1.0"

# Stable “More info” URL (avoid CAP file URLs that 404 later)
MORE_INFO_URL = "https://weather.gc.ca/?zoom=11&center=44.80743105,-79.69598152"

# ----------------------------
# Cooldown policy
# ----------------------------
COOLDOWN_MINUTES = {
    "warning": 60,
    "watch": 120,
    "advisory": 180,
    "statement": 240,
    "alert": 180,
    "allclear": 60,
    "default": 180,
}

GLOBAL_COOLDOWN_MINUTES = 5

# ----------------------------
# Message templates
# ----------------------------
SOCIAL_TEMPLATES = {
    "alert": (
        "⚠️ {event_label} for {areas_short}\n"
        "{headline}\n"
        "{advice}\n"
        "More: {more_info}\n"
        "#TayTownship #ONStorm"
    ),
    "statement": (
        "🌦️ Special Weather Statement for {areas_short}\n"
        "{headline}\n"
        "{advice}\n"
        "More: {more_info}\n"
        "#TayTownship"
    ),
    "allclear": (
        "✅ All clear: {event_label} ended for {areas_short}\n"
        "Continue to use caution as conditions may still be hazardous.\n"
        "Details: {more_info}\n"
        "#TayTownship"
    ),
}


# ----------------------------
# Generic helpers
# ----------------------------
def normalize(s: str) -> str:
    if not s:
        return ""
    s = s.lower()
    s = s.replace("–", "-").replace("—", "-")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def safe_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def load_state() -> dict:
    """
    state.json structure:
    {
      "seen_ids": [],
      "posted_guids_x": [],
      "posted_guids_fb": [],
      "cooldowns": { "group_key": 1735390000 },
      "global_last_post_ts": 0
    }
    """
    default = {
        "seen_ids": [],
        "posted_guids_x": [],
        "posted_guids_fb": [],
        "cooldowns": {},
        "global_last_post_ts": 0,
    }

    if not os.path.exists(STATE_PATH):
        return default

    try:
        raw = open(STATE_PATH, "r", encoding="utf-8").read().strip()
        if not raw:
            return default
        data = json.loads(raw)
        if not isinstance(data, dict):
            return default
    except Exception:
        return default

    data.setdefault("seen_ids", [])
    data.setdefault("posted_guids_x", [])
    data.setdefault("posted_guids_fb", [])
    data.setdefault("cooldowns", {})
    data.setdefault("global_last_post_ts", 0)
    return data


def save_state(state: dict) -> None:
    state["seen_ids"] = state.get("seen_ids", [])[-5000:]
    state["posted_guids_x"] = state.get("posted_guids_x", [])[-5000:]
    state["posted_guids_fb"] = state.get("posted_guids_fb", [])[-5000:]

    cds = state.get("cooldowns", {})
    if isinstance(cds, dict) and len(cds) > 5000:
        items = sorted(cds.items(), key=lambda kv: kv[1], reverse=True)[:4000]
        state["cooldowns"] = dict(items)

    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def utc_dirs_to_check(hours_back: int):
    n = now_utc()
    for h in range(hours_back, -1, -1):
        t = n - dt.timedelta(hours=h)
        yield t.strftime("%Y%m%d"), t.strftime("%H")


def list_cap_files(directory_url: str) -> List[str]:
    r = requests.get(directory_url, headers={"User-Agent": USER_AGENT}, timeout=20)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.endswith(".cap"):
            out.append(urljoin(directory_url.rstrip("/") + "/", href))
    return sorted(set(out))


def find_text(elem: Optional[ET.Element], tag_name: str) -> str:
    if elem is None:
        return ""
    found = elem.find(f".//{{*}}{tag_name}")
    return found.text.strip() if (found is not None and found.text) else ""


def pick_info_block(root: ET.Element) -> Optional[ET.Element]:
    infos = root.findall(".//{*}info")
    if not infos:
        return None
    for info in infos:
        lang = find_text(info, "language")
        if normalize(lang).startswith("en"):
            return info
    return infos[0]


def parse_cap(xml_text: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_text)

    identifier = find_text(root, "identifier")
    sent = find_text(root, "sent")

    info = pick_info_block(root)
    event = find_text(info, "event")
    headline = find_text(info, "headline")
    description = find_text(info, "description")
    instruction = find_text(info, "instruction")

    msg_type = find_text(info, "msgType")  # Alert | Update | Cancel
    severity = find_text(info, "severity")
    urgency = find_text(info, "urgency")
    certainty = find_text(info, "certainty")

    areas = []
    if info is not None:
        for area in info.findall(".//{*}area"):
            ad = find_text(area, "areaDesc")
            if ad:
                areas.append(ad)

    return {
        "identifier": identifier,
        "sent": sent,
        "event": event,
        "headline": headline,
        "description": description,
        "instruction": instruction,
        "areas": areas,
        "msg_type": msg_type,
        "severity": severity,
        "urgency": urgency,
        "certainty": certainty,
    }


def should_include_event(cap: Dict[str, Any]) -> bool:
    event = normalize(cap.get("event", ""))
    headline = normalize(cap.get("headline", ""))

    if not event and not headline:
        return False

    excluded = {"test", "alert ready test", "broadcast intrusion"}
    if any(b in event for b in excluded) or any(b in headline for b in excluded):
        return False

    is_sws = (event == "special weather statement")
    if is_sws and INCLUDE_SPECIAL_WEATHER_STATEMENTS:
        return True

    if (not is_sws) and INCLUDE_ALERTS:
        return True

    return False


def matched_allowlisted_area(cap: Dict[str, Any]) -> Optional[str]:
    """
    Returns the FIRST areaDesc in this CAP that matches our allowlist (exact match, case-insensitive).
    This prevents "Uxbridge" showing up in the text if Midland is also present in the same CAP.
    """
    areas = cap.get("areas", []) or []
    if not areas:
        return None

    allow_norm = {normalize(a) for a in AREA_ALLOWLIST}
    for a in areas:
        if normalize(a) in allow_norm:
            return a
    return None


def area_matches(cap: Dict[str, Any]) -> bool:
    if STRICT_AREA_MATCH and not (cap.get("areas") or []):
        return False
    return matched_allowlisted_area(cap) is not None


def rfc2822_date_from_sent(sent: str) -> str:
    if sent:
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
            try:
                if fmt.endswith("%z"):
                    d = dt.datetime.strptime(sent, fmt)
                else:
                    d = dt.datetime.strptime(sent, fmt).replace(tzinfo=dt.timezone.utc)
                return email.utils.format_datetime(d)
            except Exception:
                pass
    return email.utils.format_datetime(now_utc())


# ----------------------------
# RSS helpers
# ----------------------------
def ensure_rss_exists() -> None:
    if os.path.exists(RSS_PATH):
        return

    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")

    ET.SubElement(channel, "title").text = "Tay Township Weather Alerts"
    ET.SubElement(channel, "link").text = "https://weatherpresenter.github.io/tay-weather-rss/"
    ET.SubElement(channel, "description").text = "Automated Environment Canada alerts for Tay Township area."
    ET.SubElement(channel, "language").text = "en-ca"

    ET.ElementTree(rss).write(RSS_PATH, encoding="utf-8", xml_declaration=True)


def load_rss_tree() -> Tuple[ET.ElementTree, ET.Element]:
    ensure_rss_exists()
    tree = ET.parse(RSS_PATH)
    root = tree.getroot()
    channel = root.find("channel")
    if channel is None:
        raise RuntimeError("RSS file missing <channel>")
    return tree, channel


def rss_item_exists(channel: ET.Element, guid_text: str) -> bool:
    for item in channel.findall("item"):
        guid = item.find("guid")
        if guid is not None and (guid.text or "").strip() == guid_text:
            return True
    return False


def add_rss_item(channel: ET.Element, title: str, link: str, guid: str, pub_date: str, description: str) -> None:
    item = ET.Element("item")
    ET.SubElement(item, "title").text = title
    ET.SubElement(item, "link").text = link
    g = ET.SubElement(item, "guid")
    g.text = guid
    g.set("isPermaLink", "false")
    ET.SubElement(item, "pubDate").text = pub_date
    ET.SubElement(item, "description").text = description

    insert_index = 0
    for i, child in enumerate(list(channel)):
        if child.tag in {"title", "link", "description", "language", "lastBuildDate"}:
            insert_index = i + 1
    channel.insert(insert_index, item)


def trim_rss_items(channel: ET.Element, max_items: int) -> None:
    items = channel.findall("item")
    if len(items) <= max_items:
        return
    for item in items[max_items:]:
        channel.remove(item)


def build_rss_description(cap: Dict[str, Any]) -> str:
    bits = []
    a = matched_allowlisted_area(cap)
    if a:
        bits.append(f"Area: {a}")

    if cap.get("event"):
        bits.append(f"Event: {cap['event'].strip()}")

    if cap.get("headline"):
        bits.append(cap["headline"].strip())

    if cap.get("description"):
        bits.append(cap["description"].strip())

    if cap.get("instruction"):
        bits.append("Advice: " + cap["instruction"].strip())

    bits.append(f"More info: {MORE_INFO_URL}")

    text = "\n\n".join(bits).strip()
    if len(text) > 2000:
        text = text[:2000].rstrip() + "…"
    return text


# ----------------------------
# Cooldown logic
# ----------------------------
def classify_event_kind(cap: Dict[str, Any]) -> str:
    event = normalize(cap.get("event", ""))
    headline = normalize(cap.get("headline", ""))

    if event == "special weather statement" or "special weather statement" in headline:
        return "statement"

    if "warning" in headline or "warning" in event:
        return "warning"
    if "watch" in headline or "watch" in event:
        return "watch"
    if "advisory" in headline or "advisory" in event:
        return "advisory"

    return "alert"


def is_all_clear(cap: Dict[str, Any]) -> bool:
    msg_type = normalize(cap.get("msg_type", ""))
    headline = normalize(cap.get("headline", ""))
    desc = normalize(cap.get("description", ""))

    if msg_type == "cancel":
        return True
    if "has ended" in headline or headline.endswith(" ended"):
        return True
    if "has ended" in desc:
        return True
    return False


def group_key_for_cooldown(cap: Dict[str, Any]) -> str:
    area_primary = matched_allowlisted_area(cap) or ""
    kind = "allclear" if is_all_clear(cap) else classify_event_kind(cap)
    raw = f"{normalize(area_primary)}|{kind}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def get_cooldown_minutes_for(cap: Dict[str, Any]) -> int:
    if is_all_clear(cap):
        return COOLDOWN_MINUTES["allclear"]
    kind = classify_event_kind(cap)
    return COOLDOWN_MINUTES.get(kind, COOLDOWN_MINUTES["default"])


def cooldown_allows_post(state: Dict[str, Any], cap: Dict[str, Any]) -> Tuple[bool, str]:
    now_ts = int(time.time())

    last_global = safe_int(state.get("global_last_post_ts", 0), 0)
    if last_global and (now_ts - last_global) < (GLOBAL_COOLDOWN_MINUTES * 60):
        return False, f"Global cooldown active ({GLOBAL_COOLDOWN_MINUTES}m)."

    key = group_key_for_cooldown(cap)
    cooldowns = state.get("cooldowns", {}) if isinstance(state.get("cooldowns"), dict) else {}
    last_ts = safe_int(cooldowns.get(key, 0), 0)

    mins = get_cooldown_minutes_for(cap)
    if last_ts and (now_ts - last_ts) < (mins * 60):
        return False, f"Cooldown active for group ({mins}m)."

    return True, "OK"


def mark_posted(state: Dict[str, Any], cap: Dict[str, Any]) -> None:
    now_ts = int(time.time())
    key = group_key_for_cooldown(cap)
    state.setdefault("cooldowns", {})
    state["cooldowns"][key] = now_ts
    state["global_last_post_ts"] = now_ts


# ----------------------------
# X (OAuth 2.0 refresh) + auto-secret-update
# ----------------------------
def _github_repo() -> str:
    # Actions provides GITHUB_REPOSITORY like "owner/repo"
    return os.getenv("GITHUB_REPOSITORY", "").strip()


def _github_pat() -> str:
    return os.getenv("GH_PAT_ACTIONS_SECRETS", "").strip()


def _update_github_actions_secret(secret_name: str, secret_value: str) -> None:
    """
    Updates a GitHub Actions secret in THIS repo.
    Requires GH_PAT_ACTIONS_SECRETS with permission to write repo secrets.
    """
    pat = _github_pat()
    repo = _github_repo()
    if not pat or not repo:
        # Not configured; just skip silently
        return

    # Lazy import so you only need PyNaCl if you enable this feature
    try:
        from nacl import encoding, public  # type: ignore
    except Exception:
        raise RuntimeError(
            "PyNaCl not installed. Add 'pip install pynacl' in your workflow "
            "if you want auto-updating of X_REFRESH_TOKEN."
        )

    headers = {"Authorization": f"token {pat}", "Accept": "application/vnd.github+json"}

    # 1) Get repo public key
    r = requests.get(f"https://api.github.com/repos/{repo}/actions/secrets/public-key", headers=headers, timeout=20)
    r.raise_for_status()
    key_info = r.json()
    key_id = key_info["key_id"]
    key = key_info["key"]

    # 2) Encrypt secret_value with the public key (sealed box)
    pk = public.PublicKey(key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(pk)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

    # 3) PUT secret
    payload = {"encrypted_value": encrypted_b64, "key_id": key_id}
    r2 = requests.put(
        f"https://api.github.com/repos/{repo}/actions/secrets/{secret_name}",
        headers=headers,
        json=payload,
        timeout=20,
    )
    r2.raise_for_status()
    print(f"GitHub secret updated: {secret_name}")


def get_oauth2_access_token() -> str:
    """
    Uses refresh token to mint a short-lived access token.
    IMPORTANT: X may rotate refresh tokens. If it does, we update the GitHub Secret automatically
    (if GH_PAT_ACTIONS_SECRETS is configured).
    """
    client_id = os.getenv("X_CLIENT_ID", "").strip()
    client_secret = os.getenv("X_CLIENT_SECRET", "").strip()
    refresh_token = os.getenv("X_REFRESH_TOKEN", "").strip()

    missing = [k for k, v in [
        ("X_CLIENT_ID", client_id),
        ("X_CLIENT_SECRET", client_secret),
        ("X_REFRESH_TOKEN", refresh_token),
    ] if not v]
    if missing:
        raise RuntimeError(f"Missing required X env vars: {', '.join(missing)}")

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT,
    }
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}

    r = requests.post("https://api.x.com/2/oauth2/token", headers=headers, data=data, timeout=30)
    print("X token refresh status:", r.status_code)
    r.raise_for_status()

    payload = r.json()
    access = payload.get("access_token")
    if not access:
        raise RuntimeError("No access_token returned during refresh.")

    new_refresh = payload.get("refresh_token")
    if new_refresh and new_refresh != refresh_token:
        # Do NOT print tokens in logs. Just rotate the secret if configured.
        _update_github_actions_secret("X_REFRESH_TOKEN", new_refresh)

    return access


def post_to_x(text: str) -> Dict[str, Any]:
    url = "https://api.x.com/2/tweets"
    access_token = get_oauth2_access_token()
    r = requests.post(
        url,
        json={"text": text},
        headers={
            "Authorization": f"Bearer {access_token}",
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        },
        timeout=20,
    )
    print("X POST /2/tweets:", r.status_code, r.text[:300])
    if r.status_code >= 400:
        raise RuntimeError(f"X post failed {r.status_code}: {r.text}")
    return r.json()


# ----------------------------
# Facebook (Pages) posting
# ----------------------------
def fb_creds_from_env() -> Tuple[str, str]:
    page_id = os.getenv("FB_PAGE_ID", "").strip()
    page_token = os.getenv("FB_PAGE_ACCESS_TOKEN", "").strip()

    missing = [k for k, v in [
        ("FB_PAGE_ID", page_id),
        ("FB_PAGE_ACCESS_TOKEN", page_token),
    ] if not v]
    if missing:
        raise RuntimeError(f"Missing required Facebook env vars: {', '.join(missing)}")

    return page_id, page_token


def post_to_facebook(message: str) -> Dict[str, Any]:
    page_id, page_token = fb_creds_from_env()
    url = f"https://graph.facebook.com/v24.0/{page_id}/feed"
    r = requests.post(
        url,
        data={"message": message, "access_token": page_token},
        headers={"User-Agent": USER_AGENT},
        timeout=20,
    )
    print("FB POST /feed:", r.status_code, r.text[:300])
    if r.status_code >= 400:
        raise RuntimeError(f"Facebook post failed {r.status_code}: {r.text}")
    return r.json()


# ----------------------------
# Social message building
# ----------------------------
def areas_short_for(cap: Dict[str, Any]) -> str:
    matched = matched_allowlisted_area(cap)
    if matched:
        s = matched.strip()
    else:
        s = "Tay Township area"
    return s if len(s) <= 70 else (s[:67].rstrip() + "…")


def extract_advice_short(cap: Dict[str, Any]) -> str:
    inst = (cap.get("instruction") or "").strip()
    if inst:
        return inst if len(inst) <= 160 else (inst[:157].rstrip() + "…")

    desc = (cap.get("description") or "").strip()
    if not desc:
        return "Take precautions and monitor conditions."

    parts = re.split(r"(?<=[.!?])\s+", desc)
    first = (parts[0] if parts else desc).strip()
    return first if len(first) <= 160 else (first[:157].rstrip() + "…")


def build_social_text(cap: Dict[str, Any]) -> str:
    areas_short = areas_short_for(cap)
    headline = (cap.get("headline") or "").strip() or (cap.get("event") or "Weather alert").strip()
    advice = extract_advice_short(cap)
    event_label = (cap.get("event") or "Weather alert").strip()

    if is_all_clear(cap):
        template = SOCIAL_TEMPLATES["allclear"]
        text = template.format(event_label=event_label, areas_short=areas_short, more_info=MORE_INFO_URL)
    else:
        kind = classify_event_kind(cap)
        template = SOCIAL_TEMPLATES["statement"] if kind == "statement" else SOCIAL_TEMPLATES["alert"]
        text = template.format(
            event_label=event_label,
            areas_short=areas_short,
            headline=headline,
            advice=advice,
            more_info=MORE_INFO_URL,
        )

    # keep consistent across platforms
    return text if len(text) <= 280 else (text[:277].rstrip() + "…")


# ----------------------------
# Main
# ----------------------------
def main() -> None:
    if TEST_TWEET:
        msg = "Test post from Tay weather bot ✅"
        print("TEST_TWEET=true. Posting to enabled platforms and exiting.")
        if ENABLE_X_POSTING:
            post_to_x(msg)
        if ENABLE_FB_POSTING:
            post_to_facebook(msg)
        return

    state = load_state()
    seen = set(state.get("seen_ids", []))
    posted_x = set(state.get("posted_guids_x", []))
    posted_fb = set(state.get("posted_guids_fb", []))

    tree, channel = load_rss_tree()

    new_rss_items = 0
    x_posts = 0
    fb_posts = 0
    skipped_cooldown = 0

    for yyyymmdd, hh in utc_dirs_to_check(HOURS_BACK_TO_SCAN):
        for office in OFFICES:
            directory_url = f"https://dd.weather.gc.ca/today/alerts/cap/{yyyymmdd}/{office}/{hh}/"

            try:
                cap_urls = list_cap_files(directory_url)
            except Exception as e:
                # 404s happen for some hours; not fatal.
                print("Directory fetch failed:", directory_url, str(e))
                continue

            for cap_url in cap_urls:
                try:
                    resp = requests.get(cap_url, headers={"User-Agent": USER_AGENT}, timeout=20)
                    resp.raise_for_status()
                    cap = parse_cap(resp.text)
                except Exception as e:
                    print("CAP fetch/parse failed:", cap_url, str(e))
                    continue

                cap_id = (cap.get("identifier") or "").strip()
                if not cap_id:
                    continue

                if cap_id in seen:
                    continue
                seen.add(cap_id)

                if not should_include_event(cap):
                    continue
                if not area_matches(cap):
                    continue

                title = (cap.get("headline") or cap.get("event") or "Weather alert").strip()
                pub_date = rfc2822_date_from_sent(cap.get("sent", ""))
                guid = cap_id

                # Always use stable link
                link = MORE_INFO_URL
                description = build_rss_description(cap)

                if not rss_item_exists(channel, guid):
                    add_rss_item(channel, title=title, link=link, guid=guid, pub_date=pub_date, description=description)
                    new_rss_items += 1

                allowed, reason = cooldown_allows_post(state, cap)
                if not allowed:
                    skipped_cooldown += 1
                    print("Social skipped:", reason, "| matched:", matched_allowlisted_area(cap), "| first_area:", (cap.get("areas") or [""])[0])
                    continue

                social_text = build_social_text(cap)
                print("Social preview:", social_text.replace("\n", " | ")[:260])
                print("Matched allowlist area:", matched_allowlisted_area(cap))

                any_posted = False

                if ENABLE_X_POSTING and guid not in posted_x:
                    post_to_x(social_text)
                    posted_x.add(guid)
                    x_posts += 1
                    any_posted = True

                if ENABLE_FB_POSTING and guid not in posted_fb:
                    post_to_facebook(social_text)
                    posted_fb.add(guid)
                    fb_posts += 1
                    any_posted = True

                if any_posted:
                    mark_posted(state, cap)

    lbd = channel.find("lastBuildDate")
    if lbd is None:
        lbd = ET.SubElement(channel, "lastBuildDate")
    lbd.text = email.utils.format_datetime(now_utc())

    trim_rss_items(channel, MAX_RSS_ITEMS)

    tree.write(RSS_PATH, encoding="utf-8", xml_declaration=True)
    state["seen_ids"] = list(seen)
    state["posted_guids_x"] = list(posted_x)
    state["posted_guids_fb"] = list(posted_fb)
    save_state(state)

    print(
        "Run summary:",
        f"new_rss_items_added={new_rss_items}",
        f"x_posts={x_posts}",
        f"fb_posts={fb_posts}",
        f"skipped_cooldown={skipped_cooldown}",
    )


if __name__ == "__main__":
    main()
