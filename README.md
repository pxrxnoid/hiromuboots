# mercaribot

Polls Mercari JP for new footwear listings matching configured queries and posts them to a Telegram chat/channel.

## Setup

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN=...        # from @BotFather
export TELEGRAM_CHAT_ID=...          # your chat/channel id (bot must be a member/admin)
python bot.py
```

On first run the bot seeds the SQLite `seen.db` with all current results **without notifying**, so you won't get spammed by pre-existing listings. Subsequent cycles only notify on genuinely new items.

## Config

`config.json` (any key can be overridden by env var of the same name):

- `POLL_INTERVAL_SECONDS` — how often to scan (default 300)
- `SEARCH_QUERIES` — list of keyword strings run each cycle
- `MERCARI_CATEGORY_ID` — array of Mercari category IDs. Defaults to `[5, 1243]` (women's + men's shoes). Set to `[]` to disable filtering.
- `JPY_USD_RATE` — multiplier used to show approx USD in captions
- `FAILURE_ALERT_MINUTES` — after this many minutes of continuous failures, the bot pings the chat once
- `PAGE_SIZE` — items fetched per query per cycle

Env vars `SEARCH_QUERIES` and `MERCARI_CATEGORY_ID` accept comma-separated values.

## Telegram commands

- `/status` — last scan time, tracked count, active queries
- `/add <query>` — add a search term (persisted to `config.json`)
- `/remove <query>` — remove a search term
- `/search <query>` — one-off inline search

## Fetching strategy

POST `https://api.mercari.jp/v2/entities:search` with:

- **DPoP header** — per-request JWT signed with an ephemeral ECDSA P-256 key. Mercari's web client does the same thing; without it the API returns 401. Implemented in `DPoPSigner`.
- **X-Platform: web**, realistic User-Agent, Origin/Referer set to `https://jp.mercari.com`.
- **Nested `searchCondition`** body — Mercari's current v2 schema wraps keyword/status/sort/categoryId inside a `searchCondition` object (the flat form returns 400).

429 / 5xx / transport errors retry with exponential backoff (2s → 60s cap, 5 attempts).

The old HTML/`__NEXT_DATA__` fallback was dropped: Mercari's search page is now a Next.js app-router SPA with no server-rendered JSON. If the API ever breaks, a headless browser would be the only fallback — out of scope.

## Deploy to Render (free tier)

1. Create a Telegram bot via [@BotFather](https://t.me/BotFather) and copy the token.
2. Get your chat/channel ID (DM [@userinfobot](https://t.me/userinfobot), or for a channel add the bot as admin and forward a message to [@getidsbot](https://t.me/getidsbot)).
3. On Render: **New → Blueprint → connect this repo**. `render.yaml` is auto-detected.
4. Set the two secret env vars when prompted: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`.
5. Deploy.

**Free-tier caveat**: Render free web services spin down after ~15 min of HTTP inactivity, which pauses the poller. Fix: set up a free [UptimeRobot](https://uptimerobot.com) monitor to GET your service URL every 5 minutes — that keeps the bot awake 24/7. For a fully persistent setup, upgrade to Render's "Starter" background worker ($7/mo) or run on a cheap VPS.

The bot exposes a tiny `GET /` health endpoint (returns `OK`) on `$PORT` only when that env var is set — exactly what Render's health check + UptimeRobot need.
