import json
import os
import re
import datetime as dt
import email.utils
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests_oauthlib import OAuth1

# ---------------------------------
# Behaviour switches
# ---------------------------------
INCLUDE_SPECIAL_WEATHER_STATEMENTS = True
INCLUDE_ALERTS = True  # warnings/watches/advisories etc. (and Cancel/Update messages)

# If True, only match on CAP areaDesc (recommended to avoid unrelated alerts).
# Note: this means your AREA_KEYWORDS must match Environment Canada region names,
# not just hamlet names.
STRICT_AREA_MATCH = True

EXCLUDED_EVENTS = {
    "test",
    "alert ready test",
    "broadcast intrusion",
}

# ---------------------------------
# Settings (Tay hamlets + common region name)
# ---------------------------------
AREA_KEYWORDS = [
    # These hamlets often do NOT appear in CAP areaDesc, so keep these only if you set STRICT_AREA_MATCH = False.
    "Victoria Harbour",
    "Port McNicoll",
    "Waubaushene",
    "Waverley",
    # This is closer to how EC regions are named and is more likely to match areaDesc
    "Midland - Coldwater - Orr Lake",
]

OFFICES = ["CWTO"]  # Ontario Storm Prediction Centre
HOURS_BACK_TO_SCAN = 6           # look back to avoid missing items
MAX_RSS_ITEMS = 25               # keep RSS tidy
STATE_PATH = "state.json"
RSS_PATH = "tay-weather.xml"
USER_AGENT = "tay-weather-rss-bot/1.0"

MORE_INFO_URL = "https://weather.gc.ca/warnings/index_e.html?prov=on"

# ---------------------------------
# X (Twitter) posting
# ---------------------------------
POST_TO_X = True  # Set False if you want RSS-only

# Put these in GitHub repo secrets:
# X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET
X_API_KEY = os.getenv("X_API_KEY", "")
X_API_SECRET = os.getenv("X_API_SECRET", "")
X_ACCESS_TOKEN = os.getenv("X_ACCESS_TOKEN", "")
X_ACCESS_TOKEN_SECRET = os.getenv("X_ACCESS_TOKEN_SECRET", "")

# Optional: force a test tweet from Actions by setting TEST_TWEET="true" in workflow env
TEST_TWEET = os.getenv("TEST_TWEET", "false").lower() == "true"

# ---------------------------------
# Cooldowns (recommended defaults)
# ---------------------------------
# Cooldowns prevent repeated posts for the same region and event.
# Use more aggressive cooldowns for lower-severity items.
COOLDOWN_SECONDS_BY_CLASS = {
    "warning": 30 * 60,   # 30 minutes
    "watch": 60 * 60,     # 60 minutes
    "advisory": 90 * 60,  # 90 minutes
    "sws": 3 * 60 * 60,   # 3 hours for Special Weather Statement
    "other": 2 * 60 * 60, # 2 hours
    "cancel": 0,          # no cooldown for cancellations (all-clear)
}

# ---------------------------------
# Helpers
# ---------------------------------
def normalize(s: str) -> str:
    if not s:
        return ""
    s = s.lower()
    s = s.replace("–", "-").replace("—", "-")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def parse_iso(s: str) -> dt.datetime | None:
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def load_state() -> dict:
    """
    Load state.json safely.
    If the file is missing, empty, or invalid JSON, reset to defaults.
    """
    default = {"seen_ids": [], "cooldowns": {}}
    if not os.path.exists(STATE_PATH):
        return default

    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return default
            data.setdefault("seen_ids", [])
            data.setdefault("cooldowns", {})
            return data
    except Exception:
        return default


def save_state(state: dict) -> None:
    state["seen_ids"] = state.get("seen_ids", [])[-5000:]
    # keep cooldowns from growing endlessly
    if isinstance(state.get("cooldowns"), dict) and len(state["cooldowns"]) > 5000:
        # keep most recent 5000 by timestamp if possible
        items = list(state["cooldowns"].items())
        items.sort(key=lambda kv: (kv[1] or ""), reverse=True)
        state["cooldowns"] = dict(items[:5000])

    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def utc_dirs_to_check(hours_back: int):
    now = dt.datetime.utcnow()
    for h in range(hours_back, -1, -1):
        t = now - dt.timedelta(hours=h)
        yield t.strftime("%Y%m%d"), t.strftime("%H")


def list_cap_files(directory_url: str) -> list[str]:
    r = requests.get(directory_url, headers={"User-Agent": USER_AGENT}, timeout=20)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.endswith(".cap"):
            out.append(urljoin(directory_url.rstrip("/") + "/", href))
    return sorted(set(out))


def find_text(elem, tag_name: str) -> str:
    if elem is None:
        return ""
    found = elem.find(f".//{{*}}{tag_name}")
    return found.text.strip() if (found is not None and found.text) else ""


def pick_info_block(root: ET.Element) -> ET.Element | None:
    infos = root.findall(".//{*}info")
    if not infos:
        return None
    for info in infos:
        lang = find_text(info, "language")
        if normalize(lang).startswith("en"):
            return info
    return infos[0]


def parse_cap(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)

    identifier = find_text(root, "identifier")
    sent = find_text(root, "sent")

    info = pick_info_block(root)
    event = find_text(info, "event")
    headline = find_text(info, "headline")
    description = find_text(info, "description")
    instruction = find_text(info, "instruction")

    msg_type = find_text(info, "msgType")  # Alert, Update, Cancel (common in EC CAP)
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


def should_include_event(cap: dict) -> bool:
    event = normalize(cap.get("event", ""))
    headline = normalize(cap.get("headline", ""))

    if not event and not headline:
        return False

    # Skip tests
    if any(bad in event for bad in EXCLUDED_EVENTS) or any(bad in headline for bad in EXCLUDED_EVENTS):
        return False

    is_sws = (event == "special weather statement")

    if is_sws and INCLUDE_SPECIAL_WEATHER_STATEMENTS:
        return True

    # “Alerts” = everything else (warnings/watches/advisories etc.), including Cancel/Update
    if (not is_sws) and INCLUDE_ALERTS:
        return True

    return False


def area_matches(cap: dict) -> bool:
    """
    Recommended: match only on CAP areaDesc to avoid pulling unrelated alerts.
    If STRICT_AREA_MATCH is False, we also fall back to headline/description text.
    """
    areas_norm = [normalize(a) for a in cap.get("areas", []) if a]
    hay = " | ".join(areas_norm)

    fallback = ""
    if not STRICT_AREA_MATCH:
        fallback = normalize((cap.get("headline") or "") + " " + (cap.get("description") or ""))

    if not areas_norm and STRICT_AREA_MATCH:
        return False

    for kw in AREA_KEYWORDS:
        nkw = normalize(kw)
        if not nkw:
            continue
        if nkw in hay:
            return True
        if fallback and nkw in fallback:
            return True

    return False


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


def ensure_rss_exists() -> None:
    if os.path.exists(RSS_PATH):
        return

    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")

    ET.SubElement(channel, "title").text = "Tay Township Weather Statements"
    ET.SubElement(channel, "link").text = "https://weatherpresenter.github.io/tay-weather-rss/"
    ET.SubElement(channel, "description").text = (
        "Automated weather statements and alerts for Tay-area communities."
    )
    ET.SubElement(channel, "language").text = "en-ca"

    tree = ET.ElementTree(rss)
    tree.write(RSS_PATH, encoding="utf-8", xml_declaration=True)


def load_rss_tree() -> tuple[ET.ElementTree, ET.Element]:
    ensure_rss_exists()
    tree = ET.parse(RSS_PATH)
    root = tree.getroot()
    channel = root.find("channel")
    if channel is None:
        raise RuntimeError("RSS file missing <channel> element")
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


def build_description(cap: dict) -> str:
    bits = []

    areas = cap.get("areas", [])
    if areas:
        bits.append(f"Area: {areas[0]}")

    ev = cap.get("event")
    if ev:
        bits.append(f"Event: {ev.strip()}")

    if cap.get("headline"):
        bits.append(cap["headline"].strip())

    if cap.get("description"):
        bits.append(cap["description"].strip())

    if cap.get("instruction"):
        bits.append("Advice: " + cap["instruction"].strip())

    bits.append(f"More info: {MORE_INFO_URL}")

    text = "\n\n".join(bits).strip()
    if len(text) > 1200:
        text = text[:1200].rstrip() + "…"
    return text


# ---------------------------------
# X (Twitter) helpers
# ---------------------------------
def x_oauth1() -> OAuth1:
    return OAuth1(X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET)


def x_enabled() -> bool:
    if not POST_TO_X:
        return False
    needed = [X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET]
    return all(v.strip() for v in needed)


def x_post(text: str) -> None:
    """
    Posts a tweet (X API v2). Raises on failure so the workflow goes red.
    """
    url = "https://api.twitter.com/2/tweets"
    r = requests.post(url, auth=x_oauth1(), json={"text": text}, timeout=30)
    print("X POST /2/tweets:", r.status_code, r.text[:500])
    if r.status_code not in (200, 201):
        raise RuntimeError(f"X post failed: {r.status_code} {r.text}")


def classify_alert(cap: dict) -> str:
    """
    Return a rough class for cooldown decisions.
    """
    event = normalize(cap.get("event", ""))
    headline = normalize(cap.get("headline", ""))
    msg_type = normalize(cap.get("msg_type", ""))

    if msg_type == "cancel":
        return "cancel"
    if event == "special weather statement":
        return "sws"

    text = f"{event} {headline}"
    if "warning" in text:
        return "warning"
    if "watch" in text:
        return "watch"
    if "advisory" in text:
        return "advisory"
    return "other"


def cooldown_key(cap: dict) -> str:
    """
    Cooldown per region + event class, so you do not spam updates.
    """
    area = (cap.get("areas") or [""])[0]
    cls = classify_alert(cap)
    # include msg_type so Cancel is not blocked by an Alert cooldown
    msg_type = (cap.get("msg_type") or "").strip().lower() or "alert"
    return f"{normalize(area)}|{cls}|{msg_type}"


def cooldown_seconds_for(cap: dict) -> int:
    cls = classify_alert(cap)
    return int(COOLDOWN_SECONDS_BY_CLASS.get(cls, COOLDOWN_SECONDS_BY_CLASS["other"]))


def is_in_cooldown(state: dict, cap: dict) -> bool:
    cd = state.get("cooldowns", {}) or {}
    key = cooldown_key(cap)
    last = parse_iso(cd.get(key, ""))
    if last is None:
        return False
    seconds = (now_utc() - last).total_seconds()
    return seconds < cooldown_seconds_for(cap)


def mark_cooldown(state: dict, cap: dict) -> None:
    state.setdefault("cooldowns", {})
    state["cooldowns"][cooldown_key(cap)] = iso_now()


def shorten(s: str, limit: int) -> str:
    s = (s or "").strip()
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 1)].rstrip() + "…"


def extract_primary_area(cap: dict) -> str:
    areas = cap.get("areas") or []
    return areas[0].strip() if areas else "Tay Township area"


def tweet_text_for(cap: dict) -> str:
    """
    Tweet templates:
    - Alert/Update: headline + area + short action line + link
    - Cancel: All clear follow-up
    """
    msg_type = normalize(cap.get("msg_type", "")) or "alert"
    headline = cap.get("headline") or cap.get("event") or "Weather update"
    area = extract_primary_area(cap)
    link = MORE_INFO_URL  # stable link

    # If you prefer to link the CAP file, swap this:
    # link = cap.get("cap_url") or MORE_INFO_URL

    if msg_type == "cancel":
        # all clear template
        return (
            f"All clear: {shorten(headline, 140)}\n"
            f"Area: {shorten(area, 120)}\n"
            f"Continue to monitor official updates: {link}"
        )

    # Alert or Update
    prefix = "Weather alert" if msg_type == "alert" else "Weather update"
    return (
        f"{prefix}: {shorten(headline, 160)}\n"
        f"Area: {shorten(area, 120)}\n"
        f"Details: {link}"
    )


# ---------------------------------
# Main
# ---------------------------------
def main():
    # Optional test tweet path
    if TEST_TWEET:
        print("TEST_TWEET is true")
        if not x_enabled():
            raise RuntimeError("TEST_TWEET requested but X credentials are missing in environment.")
        x_post("Test tweet from Tay weather bot ✅")
        print("Test tweet sent.")
        return

    state = load_state()
    seen = set(state.get("seen_ids", []))

    tree, channel = load_rss_tree()

    new_rss_items = 0
    tweets_attempted = 0
    tweets_sent = 0
    tweets_skipped_cooldown = 0

    for yyyymmdd, hh in utc_dirs_to_check(HOURS_BACK_TO_SCAN):
        for office in OFFICES:
            directory_url = f"https://dd.weather.gc.ca/today/alerts/cap/{yyyymmdd}/{office}/{hh}/"

            try:
                cap_urls = list_cap_files(directory_url)
            except Exception as e:
                print("Directory fetch failed:", directory_url, str(e))
                continue

            for cap_url in cap_urls:
                try:
                    xml_text = requests.get(cap_url, headers={"User-Agent": USER_AGENT}, timeout=20).text
                    cap = parse_cap(xml_text)
                    cap["cap_url"] = cap_url
                except Exception as e:
                    print("CAP parse failed:", cap_url, str(e))
                    continue

                cap_id = (cap.get("identifier") or "").strip()
                if not cap_id:
                    continue

                if cap_id in seen:
                    continue

                # Mark as seen so we do not reprocess forever
                seen.add(cap_id)

                if not should_include_event(cap):
                    continue
                if not area_matches(cap):
                    continue

                # RSS fields
                title = cap.get("headline") or cap.get("event") or "Weather update"
                pub_date = rfc2822_date_from_sent(cap.get("sent", ""))
                guid = cap_id
                link = cap_url  # CAP link for RSS
                description = build_description(cap)

                if not rss_item_exists(channel, guid):
                    add_rss_item(channel, title=title, link=link, guid=guid, pub_date=pub_date, description=description)
                    new_rss_items += 1

                # Tweeting logic: tweet only for newly seen CAP items that match Tay filter
                if x_enabled():
                    tweets_attempted += 1

                    if is_in_cooldown(state, cap):
                        tweets_skipped_cooldown += 1
                        print("Tweet skipped due to cooldown:", cooldown_key(cap))
                        continue

                    text = tweet_text_for(cap)
                    print("Tweet text preview:", text.replace("\n", " | ")[:240])

                    x_post(text)
                    tweets_sent += 1
                    mark_cooldown(state, cap)
                else:
                    if POST_TO_X:
                        print("X posting is enabled but credentials are missing. Skipping tweets.")

    # Update lastBuildDate
    now_rfc = email.utils.format_datetime(now_utc())
    lbd = channel.find("lastBuildDate")
    if lbd is None:
        lbd = ET.SubElement(channel, "lastBuildDate")
    lbd.text = now_rfc

    trim_rss_items(channel, MAX_RSS_ITEMS)

    # Save RSS + state
    tree.write(RSS_PATH, encoding="utf-8", xml_declaration=True)
    state["seen_ids"] = list(seen)
    save_state(state)

    print(
        "Run summary:",
        f"new_rss_items_added={new_rss_items}",
        f"tweets_attempted={tweets_attempted}",
        f"tweets_sent={tweets_sent}",
        f"tweets_skipped_cooldown={tweets_skipped_cooldown}",
    )


if __name__ == "__main__":
    main()
