# Tay Township Weather Alerts (Automation)

This repository monitors Weather Canada CAP alerts and Special Weather Statements for the Tay Township area and:
- Updates an RSS feed (`tay-weather.xml`)
- Posts updates to X, when enabled
- Posts updates to a Facebook Page, when enabled

## Coverage
Matches alerts that reference:
- Victoria Harbour
- Port McNicoll
- Waubaushene
- Waverley
- Midland - Coldwater - Orr Lake (common regional coverage)

## How it runs
GitHub Actions runs every 5 minutes (and can be run manually).

## Safety features
- Deduplication: prevents repeat posting of the same alert (by CAP identifier)
- Text-hash dedupe: prevents X failures when two different alerts generate identical post text (X blocks duplicate tweet bodies)
- Cooldowns by severity:
  - Warnings: 60 minutes
  - Watches: 90 minutes
  - Advisories: 120 minutes
  - Special Weather Statements: 180 minutes
  - Cancels (all clear): 15 minutes
- Daily cap: 15 posts per day (Free X API safety)
- Kill switch: `ENABLE_X_POSTING` environment variable
- Optional: `ENABLE_FB_POSTING` environment variable

## Security note
If you previously ran the workflow when token payloads were printed in logs, rotate your X refresh token / client secret immediately.

## Kill switch
In `.github/workflows/weather.yml`, set:
- `ENABLE_X_POSTING: "false"` to stop posting
- `ENABLE_X_POSTING: "true"` to resume posting

Similarly:
- `ENABLE_FB_POSTING: "false"` to stop Facebook posting

## All clear behaviour
When Weather Canada issues a Cancel message for an alert that was previously posted as active, the bot posts an “All clear” follow-up tweet.

To avoid confusion, cancellation tweets are not posted unless the bot previously posted the alert as active.

## Files
- `tay_weather_bot.py`: main bot
- `tay-weather.xml`: RSS output
- `state.json`: bot state (seen alerts, cooldowns, posted IDs)
