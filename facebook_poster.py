# facebook_poster.py
from __future__ import annotations

import json
import os
import random
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests


# ----------------------------
# Settings (tune these safely)
# ----------------------------
DEFAULT_FB_COOLDOWN_SECONDS = int(os.getenv("FB_COOLDOWN_SECONDS", "3600"))  # 60 minutes
DEFAULT_FB_BLOCK_SECONDS = int(os.getenv("FB_BLOCK_SECONDS", "21600"))       # 6 hours
DEFAULT_FB_TIMEOUT_SECONDS = int(os.getenv("FB_TIMEOUT_SECONDS", "30"))
DEFAULT_FB_JITTER_SECONDS = int(os.getenv("FB_JITTER_SECONDS", "10"))        # small randomness


# ----------------------------
# State helpers
# ----------------------------
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        # expects "2026-01-03T17:08:00Z" or "...+00:00"
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_state(path: str = "state.json") -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        # If state is corrupt, don't crash the run
        return {}


def save_state(state: Dict[str, Any], path: str = "state.json") -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
    except Exception as e:
        print("⚠️ Failed to save state.json:", e)


# ----------------------------
# Facebook error parsing
# ----------------------------
def _fb_error_info(resp: requests.Response) -> Dict[str, Any]:
    try:
        j = resp.json()
        return (j or {}).get("error", {}) or {}
    except Exception:
        return {}


def is_fb_rate_limit(resp: requests.Response) -> bool:
    """
    Facebook "action blocked / rate limited" commonly shows as:
      HTTP 400
      error.code = 368
      error.error_subcode = 1390008
    """
    err = _fb_error_info(resp)
    return (
        resp.status_code >= 400
        and err.get("code") == 368
        and str(err.get("error_subcode")) == "1390008"
    )


def is_fb_permission_or_token_issue(resp: requests.Response) -> bool:
    """
    Useful for logging; not used to crash the job.
    """
    err = _fb_error_info(resp)
    code = err.get("code")
    # 190 = invalid OAuth access token
    # 10 / 200-series can be permission issues (varies)
    return resp.status_code >= 400 and code in (10, 190, 200, 250)


# ----------------------------
# Image loader hook
# ----------------------------
def load_image_bytes(image_ref: str) -> Tuple[bytes, str]:
    """
    You already have this in tay_weather_bot.py.
    Keep this stub so this file is self-contained; you should import your existing
    load_image_bytes and replace this function or monkey-patch it.

    Return: (bytes, mime_type)
    """
    raise NotImplementedError("Wire this to your existing load_image_bytes(image_ref).")


# ----------------------------
# Posting logic
# ----------------------------
@dataclass
class FBDecision:
    ok_to_post: bool
    reason: str


def should_post_to_facebook(
    state: Dict[str, Any],
    *,
    has_new_social_event: bool,
    now: Optional[datetime] = None,
    cooldown_seconds: int = DEFAULT_FB_COOLDOWN_SECONDS,
) -> FBDecision:
    """
    Prevent overwhelming Facebook:
    - Only post when there's something new (your bot already knows this)
    - Respect a cooldown between successful posts
    - Respect a block window if FB rate-limited you recently
    """
    now = now or utc_now()

    if not has_new_social_event:
        return FBDecision(False, "no_new_event")

    fb_blocked_until = _parse_iso(str(state.get("fb_blocked_until", ""))) if state.get("fb_blocked_until") else None
    if fb_blocked_until and now < fb_blocked_until:
        return FBDecision(False, f"blocked_until_{_iso(fb_blocked_until)}")

    last_ok = _parse_iso(str(state.get("fb_last_posted_at", ""))) if state.get("fb_last_posted_at") else None
    if last_ok and (now - last_ok).total_seconds() < cooldown_seconds:
        return FBDecision(False, f"cooldown_{cooldown_seconds}s")

    return FBDecision(True, "allowed")


def _fb_env() -> Tuple[str, str, str]:
    page_id = os.getenv("FB_PAGE_ID", "").strip()
    page_token = os.getenv("FB_PAGE_ACCESS_TOKEN", "").strip()
    api_ver = os.getenv("FB_API_VERSION", "v24.0").strip()
    if not page_id or not page_token:
        raise RuntimeError("Missing FB_PAGE_ID or FB_PAGE_ACCESS_TOKEN")
    return page_id, page_token, api_ver


def _post(url: str, *, data: Dict[str, Any], files: Optional[Dict[str, Any]] = None) -> requests.Response:
    # Small jitter so every run doesn't hammer the same second (helps with spam heuristics)
    jitter = max(0, DEFAULT_FB_JITTER_SECONDS)
    if jitter:
        time.sleep(random.uniform(0.0, float(jitter)))

    return requests.post(url, data=data, files=files, timeout=DEFAULT_FB_TIMEOUT_SECONDS)


def post_to_facebook_page(message: str) -> Dict[str, Any]:
    page_id, page_token, api_ver = _fb_env()
    url = f"https://graph.facebook.com/{api_ver}/{page_id}/feed"
    r = _post(url, data={"message": message, "access_token": page_token})
    print("FB POST /feed status:", r.status_code)

    if r.status_code >= 400:
        print("FB error body:", r.text)
        # Don't crash here; let caller decide fallback / skip
        raise requests.HTTPError(f"FB /feed failed {r.status_code}", response=r)

    return r.json()


def post_photo_to_facebook_page(caption: str, image_ref: str) -> Dict[str, Any]:
    page_id, page_token, api_ver = _fb_env()
    if not image_ref:
        raise RuntimeError("Missing image_ref for FB photo post")

    url = f"https://graph.facebook.com/{api_ver}/{page_id}/photos"

    if re.match(r"^https?://", image_ref, flags=re.IGNORECASE):
        r = _post(
            url,
            data={"url": image_ref, "caption": caption, "access_token": page_token},
        )
    else:
        img_bytes, mime_type = load_image_bytes(image_ref)
        r = _post(
            url,
            data={"caption": caption, "access_token": page_token},
            files={"source": ("image", img_bytes, mime_type)},
        )

    print("FB POST /photos status:", r.status_code)
    if r.status_code >= 400:
        print("FB error body:", r.text)
        raise requests.HTTPError(f"FB /photos failed {r.status_code}", response=r)

    return r.json()


def post_carousel_to_facebook_page(caption: str, image_urls: List[str]) -> Dict[str, Any]:
    """
    Posts up to 10 images as a single feed post with attached_media.
    """
    image_urls = [u for u in (image_urls or []) if (u or "").strip()]

    if not image_urls:
        # No images -> text-only
        return post_to_facebook_page(caption)

    if len(image_urls) == 1:
        return post_photo_to_facebook_page(caption, image_urls[0])

    page_id, page_token, api_ver = _fb_env()

    media_fbids: List[str] = []
    photos_url = f"https://graph.facebook.com/{api_ver}/{page_id}/photos"

    # Step 1: upload unpublished photos
    for u in image_urls[:10]:
        try:
            if re.match(r"^https?://", u, flags=re.IGNORECASE):
                r = _post(
                    photos_url,
                    data={"url": u, "published": "false", "access_token": page_token},
                )
            else:
                img_bytes, mime_type = load_image_bytes(u)
                r = _post(
                    photos_url,
                    data={"published": "false", "access_token": page_token},
                    files={"source": ("image", img_bytes, mime_type)},
                )

            if r.status_code >= 400:
                print("⚠️ FB carousel upload failed for one image:", r.status_code, r.text)
                continue

            j = r.json()
            fbid = j.get("id")
            if fbid:
                media_fbids.append(str(fbid))
        except Exception as e:
            print("⚠️ FB carousel upload skipped for one image:", e)

    if not media_fbids:
        return post_to_facebook_page(caption)

    if len(media_fbids) == 1:
        return post_photo_to_facebook_page(caption, image_urls[0])

    # Step 2: attach photos to a single feed post
    data: Dict[str, Any] = {"message": caption, "access_token": page_token}
    for i, fbid in enumerate(media_fbids):
        data[f"attached_media[{i}]"] = json.dumps({"media_fbid": fbid})

    feed_url = f"https://graph.facebook.com/{api_ver}/{page_id}/feed"
    r = _post(feed_url, data=data)
    print("FB POST /feed (carousel) status:", r.status_code)

    if r.status_code >= 400:
        print("FB error body:", r.text)
        raise requests.HTTPError(f"FB /feed (carousel) failed {r.status_code}", response=r)

    return r.json()


# ----------------------------
# High-level "safe post" wrapper
# ----------------------------
def safe_post_facebook(
    state: Dict[str, Any],
    *,
    caption: str,
    image_urls: List[str],
    has_new_social_event: bool,
    state_path: str = "state.json",
    cooldown_seconds: int = DEFAULT_FB_COOLDOWN_SECONDS,
    block_seconds: int = DEFAULT_FB_BLOCK_SECONDS,
) -> Dict[str, Any]:
    """
    One attempt per run, with controlled fallback:
    - If FB rate-limits you (368), set fb_blocked_until and SKIP without failing the job.
    - Otherwise try: carousel -> single photo -> text
    - Record fb_last_posted_at on success
    """
    now = utc_now()
    decision = should_post_to_facebook(
        state,
        has_new_social_event=has_new_social_event,
        now=now,
        cooldown_seconds=cooldown_seconds,
    )

    if not decision.ok_to_post:
        print(f"FB: skipping ({decision.reason})")
        return {"skipped": True, "reason": decision.reason}

    def _handle_error(e: requests.HTTPError) -> Dict[str, Any]:
        resp = getattr(e, "response", None)
        if resp is not None and is_fb_rate_limit(resp):
            blocked_until = now + (block_seconds and __import__("datetime").timedelta(seconds=block_seconds))
            state["fb_blocked_until"] = _iso(blocked_until)
            save_state(state, state_path)
            print(f"⚠️ FB rate-limited (368). Blocking FB until {state['fb_blocked_until']}.")
            return {"skipped": True, "reason": "fb_rate_limit", "blocked_until": state["fb_blocked_until"]}

        # Non-368: surface useful logging but don't necessarily crash the whole workflow
        if resp is not None:
            err = _fb_error_info(resp)
            print("FB error parsed:", {
                "status": resp.status_code,
                "code": err.get("code"),
                "error_subcode": err.get("error_subcode"),
                "type": err.get("type"),
                "message": err.get("message"),
                "fbtrace_id": err.get("fbtrace_id"),
            })
        return {"error": True, "reason": "fb_http_error"}

    # Try carousel first (best experience)
    try:
        result = post_carousel_to_facebook_page(caption, image_urls)
        state["fb_last_posted_at"] = _iso(now)
        state.pop("fb_blocked_until", None)
        save_state(state, state_path)
        return {"ok": True, "mode": "carousel", "result": result}
    except requests.HTTPError as e:
        handled = _handle_error(e)
        if handled.get("skipped"):
            return handled
        print("⚠️ FB carousel failed (non-368). Trying single photo...")

    # Fallback to single photo
    try:
        if image_urls:
            result = post_photo_to_facebook_page(caption, image_urls[0])
            state["fb_last_posted_at"] = _iso(now)
            state.pop("fb_blocked_until", None)
            save_state(state, state_path)
            return {"ok": True, "mode": "single_photo", "result": result}
    except requests.HTTPError as e:
        handled = _handle_error(e)
        if handled.get("skipped"):
            return handled
        print("⚠️ FB single photo failed (non-368). Trying text-only...")

    # Final fallback to text-only
    try:
        result = post_to_facebook_page(caption)
        state["fb_last_posted_at"] = _iso(now)
        state.pop("fb_blocked_until", None)
        save_state(state, state_path)
        return {"ok": True, "mode": "text", "result": result}
    except requests.HTTPError as e:
        handled = _handle_error(e)
        if handled.get("skipped"):
            return handled

        # At this point it's some persistent permission/config problem.
        # We will NOT crash your run; we just log and move on.
        print("⚠️ FB text-only failed too. Skipping FB for this run.")
        return {"skipped": True, "reason": "fb_failed_all_modes"}
