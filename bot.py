"""Mercari JP footwear scanner — Telegram bot."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from telegram import Update
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import Application, CommandHandler, ContextTypes

ROOT = Path(__file__).parent
CONFIG_PATH = ROOT / "config.json"
DB_PATH = Path(os.environ.get("DB_PATH") or ROOT / "seen.db")

MERCARI_SEARCH_API = "https://api.mercari.jp/v2/entities:search"
MERCARI_ITEM_URL = "https://jp.mercari.com/item/{id}"
THUMB_BASE = "https://static.mercdn.net/c!/w=240/thumb/photos/{id}_1.jpg"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

log = logging.getLogger("mercaribot")


# ---------- config ----------

DEFAULTS: dict[str, Any] = {
    "TELEGRAM_BOT_TOKEN": "",
    "TELEGRAM_CHAT_ID": "",
    "POLL_INTERVAL_SECONDS": 300,
    "SEARCH_QUERIES": [
        "hiromu takahara",
        "ヒロム タカハラ",
        "ヒロムタカハラ",
        "hiromu takahara shoes",
        "takahara hiromu",
    ],
    # Empty = no category filter (keyword alone is specific enough).
    # Known footwear category id: 8744 (boots/shoes seen in Mercari responses).
    "MERCARI_CATEGORY_ID": [],
    "JPY_USD_RATE": 0.0064,
    "FAILURE_ALERT_MINUTES": 30,
    "PAGE_SIZE": 40,
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception as e:
            log.warning("config.json unreadable: %s", e)
    for key in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        if os.environ.get(key):
            cfg[key] = os.environ[key]
    if os.environ.get("POLL_INTERVAL_SECONDS"):
        cfg["POLL_INTERVAL_SECONDS"] = int(os.environ["POLL_INTERVAL_SECONDS"])
    if os.environ.get("SEARCH_QUERIES"):
        cfg["SEARCH_QUERIES"] = [
            q.strip() for q in os.environ["SEARCH_QUERIES"].split(",") if q.strip()
        ]
    if os.environ.get("MERCARI_CATEGORY_ID") is not None:
        raw = os.environ["MERCARI_CATEGORY_ID"].strip()
        cfg["MERCARI_CATEGORY_ID"] = (
            [int(x) for x in raw.split(",") if x.strip().isdigit()] if raw else []
        )
    return cfg


def save_config(cfg: dict) -> None:
    public = {k: v for k, v in cfg.items() if k not in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")}
    CONFIG_PATH.write_text(json.dumps(public, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------- db ----------

def db_init() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.execute("CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, first_seen INTEGER)")
    con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    con.commit()
    return con


def db_has(con: sqlite3.Connection, item_id: str) -> bool:
    return con.execute("SELECT 1 FROM seen WHERE id=?", (item_id,)).fetchone() is not None


def db_add(con: sqlite3.Connection, item_id: str) -> None:
    con.execute(
        "INSERT OR IGNORE INTO seen (id, first_seen) VALUES (?, ?)",
        (item_id, int(time.time())),
    )
    con.commit()


def db_count(con: sqlite3.Connection) -> int:
    return con.execute("SELECT COUNT(*) FROM seen").fetchone()[0]


def db_meta_get(con: sqlite3.Connection, key: str) -> str | None:
    row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def db_meta_set(con: sqlite3.Connection, key: str, value: str) -> None:
    con.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
    con.commit()


# ---------- DPoP ----------

def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class DPoPSigner:
    """Generates per-request DPoP JWTs. Mercari's public web client uses the
    same shape: ES256 over an ephemeral P-256 key, with jwk in header and
    iat/jti/htu/htm/uuid in claims."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        pub = self._key.public_key().public_numbers()
        self._jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u(pub.x.to_bytes(32, "big")),
            "y": _b64u(pub.y.to_bytes(32, "big")),
        }
        self._device_uuid = str(uuid.uuid4())

    def sign(self, method: str, url: str) -> str:
        claims = {
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
            "htu": url,
            "htm": method,
            "uuid": self._device_uuid,
        }
        return jwt.encode(
            claims,
            self._key,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self._jwk},
        )


# ---------- Mercari search ----------

def _cat_ids(category_id: Any) -> list[str]:
    if not category_id:
        return []
    if isinstance(category_id, (list, tuple)):
        return [str(c) for c in category_id if str(c).strip()]
    return [str(category_id)]


def _build_body(keyword: str, category_ids: list[str], page_size: int) -> dict:
    return {
        "userId": "",
        "pageSize": page_size,
        "pageToken": "",
        "searchSessionId": str(uuid.uuid4()),
        "indexRouting": "INDEX_ROUTING_UNSPECIFIED",
        "thumbnailTypes": [],
        "searchCondition": {
            "keyword": keyword,
            "excludeKeyword": "",
            "sort": "SORT_CREATED_TIME",
            "order": "ORDER_DESC",
            "status": ["STATUS_ON_SALE"],
            "sizeId": [],
            "categoryId": category_ids,
            "brandId": [],
            "sellerId": [],
            "priceMin": 0,
            "priceMax": 0,
            "itemConditionId": [],
            "shippingPayerId": [],
            "shippingFromArea": [],
            "shippingMethod": [],
            "colorId": [],
            "hasCoupon": False,
            "attributes": [],
            "itemTypes": [],
            "skuIds": [],
        },
        "defaultDatasets": [],
        "serviceFrom": "suruga",
        "withItemBrand": True,
        "withItemSize": False,
        "withItemPromotions": True,
        "withItemSizes": True,
        "withShopname": False,
    }


async def fetch_query(
    client: httpx.AsyncClient,
    signer: DPoPSigner,
    keyword: str,
    category_id: Any,
    page_size: int,
) -> list[dict]:
    body = _build_body(keyword, _cat_ids(category_id), page_size)
    delay = 2.0
    last_err: Exception | None = None
    for attempt in range(5):
        headers = {
            "DPoP": signer.sign("POST", MERCARI_SEARCH_API),
            "X-Platform": "web",
            "Accept": "*/*",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "Origin": "https://jp.mercari.com",
            "Referer": "https://jp.mercari.com/",
        }
        try:
            resp = await client.post(MERCARI_SEARCH_API, json=body, headers=headers, timeout=20)
        except httpx.RequestError as e:
            last_err = e
            log.warning("transport error %r (attempt %d); backoff %.0fs", e, attempt + 1, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)
            continue

        if resp.status_code == 200:
            try:
                return resp.json().get("items") or []
            except json.JSONDecodeError as e:
                last_err = e
                log.warning("200 but json decode failed: %s", e)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)
                continue

        if resp.status_code == 429 or 500 <= resp.status_code < 600:
            log.warning(
                "api %s on %r (attempt %d); backoff %.0fs",
                resp.status_code, keyword, attempt + 1, delay,
            )
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)
            continue

        raise RuntimeError(f"mercari api {resp.status_code}: {resp.text[:200]}")

    if last_err:
        raise last_err
    raise RuntimeError("mercari api retries exhausted")


def normalize(raw: dict) -> dict:
    item_id = str(raw.get("id") or "")
    title = str(raw.get("name") or raw.get("title") or "")
    price = raw.get("price")
    try:
        price_int = int(price) if price is not None else None
    except (TypeError, ValueError):
        price_int = None

    thumb = ""
    thumbs = raw.get("thumbnails")
    if isinstance(thumbs, list) and thumbs:
        first = thumbs[0]
        if isinstance(first, str):
            thumb = first
        elif isinstance(first, dict):
            thumb = first.get("url") or first.get("uri") or ""
    if not thumb:
        thumb = raw.get("thumbnail") or ""
    if not thumb and item_id:
        thumb = THUMB_BASE.format(id=item_id)

    return {
        "id": item_id,
        "title": title,
        "price": price_int,
        "thumbnail": thumb,
        "url": MERCARI_ITEM_URL.format(id=item_id),
    }


# ---------- notifications ----------

def html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_caption(item: dict, query: str, usd_rate: float) -> str:
    lines = [f"<b>{html_escape(item['title'] or '(untitled)')}</b>"]
    if item["price"] is not None:
        usd = item["price"] * usd_rate
        lines.append(f"¥{item['price']:,}  (~${usd:,.2f})")
    lines.append(f"<a href=\"{item['url']}\">open on Mercari</a>")
    lines.append(f"match: <i>{html_escape(query)}</i>")
    lines.append(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    return "\n".join(lines)


async def send_notifications(
    app: Application,
    chat_id: str,
    new_items: list[tuple[dict, str]],
    usd_rate: float,
) -> None:
    if not new_items:
        return
    if len(new_items) > 1:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        try:
            await app.bot.send_message(
                chat_id,
                f"<b>{len(new_items)} new Mercari listing(s)</b> — {ts}",
                parse_mode=ParseMode.HTML,
            )
        except TelegramError as e:
            log.warning("header send failed: %s", e)

    for item, query in new_items:
        caption = format_caption(item, query, usd_rate)
        sent = False
        if item["thumbnail"]:
            try:
                await app.bot.send_photo(
                    chat_id,
                    photo=item["thumbnail"],
                    caption=caption,
                    parse_mode=ParseMode.HTML,
                )
                sent = True
            except TelegramError as e:
                log.warning("send_photo failed (%s); falling back to text", e)
        if not sent:
            try:
                await app.bot.send_message(
                    chat_id,
                    caption,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=False,
                )
            except TelegramError as e:
                log.error("send_message failed: %s", e)
        await asyncio.sleep(0.3)


# ---------- poller ----------

class Poller:
    def __init__(self, app: Application, cfg: dict, con: sqlite3.Connection) -> None:
        self.app = app
        self.cfg = cfg
        self.con = con
        self.signer = DPoPSigner()
        self.last_scan_at: datetime | None = None
        self.last_success_at: datetime = datetime.now(timezone.utc)
        self.alert_sent = False
        self.initialized = db_meta_get(con, "initialized") == "1"
        self.stop_event = asyncio.Event()
        self.task: asyncio.Task | None = None

    async def run(self) -> None:
        async with httpx.AsyncClient() as client:
            while not self.stop_event.is_set():
                try:
                    await self.scan_once(client)
                    self.last_success_at = datetime.now(timezone.utc)
                    self.alert_sent = False
                except Exception as e:
                    log.exception("scan cycle failed: %s", e)
                    await self._maybe_alert()
                try:
                    await asyncio.wait_for(
                        self.stop_event.wait(), timeout=self.cfg["POLL_INTERVAL_SECONDS"]
                    )
                except asyncio.TimeoutError:
                    pass

    async def scan_once(self, client: httpx.AsyncClient) -> None:
        self.last_scan_at = datetime.now(timezone.utc)
        new_items: list[tuple[dict, str]] = []
        any_success = False
        for q in list(self.cfg["SEARCH_QUERIES"]):
            try:
                raw_list = await fetch_query(
                    client, self.signer, q,
                    self.cfg.get("MERCARI_CATEGORY_ID"), self.cfg["PAGE_SIZE"],
                )
                any_success = True
            except Exception as e:
                log.error("query %r failed: %s", q, e)
                continue
            for raw in raw_list:
                item = normalize(raw)
                if not item["id"]:
                    continue
                if db_has(self.con, item["id"]):
                    continue
                db_add(self.con, item["id"])
                if self.initialized:
                    new_items.append((item, q))
            await asyncio.sleep(0.5)

        if not self.initialized:
            if any_success:
                db_meta_set(self.con, "initialized", "1")
                self.initialized = True
                log.info("initial scan complete; %d items seeded", db_count(self.con))
            else:
                log.warning("initial scan had no successful queries; will retry")
            return

        if not any_success:
            raise RuntimeError("all queries failed this cycle")

        if new_items:
            await send_notifications(
                self.app,
                self.cfg["TELEGRAM_CHAT_ID"],
                new_items,
                self.cfg["JPY_USD_RATE"],
            )
            log.info("sent %d new listing(s)", len(new_items))

    async def _maybe_alert(self) -> None:
        if self.alert_sent:
            return
        elapsed = (datetime.now(timezone.utc) - self.last_success_at).total_seconds()
        if elapsed >= self.cfg["FAILURE_ALERT_MINUTES"] * 60:
            try:
                await self.app.bot.send_message(
                    self.cfg["TELEGRAM_CHAT_ID"],
                    f"⚠️ Bot has been unable to reach Mercari for {int(elapsed // 60)} minutes.",
                )
                self.alert_sent = True
            except TelegramError as e:
                log.error("failure-alert send failed: %s", e)


# ---------- commands ----------

async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    cfg = ctx.application.bot_data["cfg"]
    poller: Poller = ctx.application.bot_data["poller"]
    con: sqlite3.Connection = ctx.application.bot_data["con"]
    last = poller.last_scan_at.isoformat(timespec="seconds") if poller.last_scan_at else "never"
    queries = "\n".join(f"• {q}" for q in cfg["SEARCH_QUERIES"]) or "(none)"
    await update.message.reply_text(
        f"Last scan: {last}\n"
        f"Tracked items: {db_count(con)}\n"
        f"Poll interval: {cfg['POLL_INTERVAL_SECONDS']}s\n"
        f"Queries:\n{queries}"
    )


async def cmd_add(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    cfg = ctx.application.bot_data["cfg"]
    if not ctx.args:
        await update.message.reply_text("Usage: /add <query>")
        return
    q = " ".join(ctx.args).strip()
    if q in cfg["SEARCH_QUERIES"]:
        await update.message.reply_text("Already in list.")
        return
    cfg["SEARCH_QUERIES"].append(q)
    save_config(cfg)
    await update.message.reply_text(f"Added: {q}")


async def cmd_remove(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    cfg = ctx.application.bot_data["cfg"]
    if not ctx.args:
        await update.message.reply_text("Usage: /remove <query>")
        return
    q = " ".join(ctx.args).strip()
    if q not in cfg["SEARCH_QUERIES"]:
        await update.message.reply_text("Not found.")
        return
    cfg["SEARCH_QUERIES"].remove(q)
    save_config(cfg)
    await update.message.reply_text(f"Removed: {q}")


async def cmd_search(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    cfg = ctx.application.bot_data["cfg"]
    poller: Poller = ctx.application.bot_data["poller"]
    if not ctx.args:
        await update.message.reply_text("Usage: /search <query>")
        return
    q = " ".join(ctx.args).strip()
    await update.message.reply_text(f"Searching: {q} ...")
    async with httpx.AsyncClient() as client:
        try:
            raw_list = await fetch_query(client, poller.signer, q, cfg.get("MERCARI_CATEGORY_ID"), 5)
        except Exception as e:
            await update.message.reply_text(f"Error: {e}")
            return
    if not raw_list:
        await update.message.reply_text("No results.")
        return
    chat_id = str(update.effective_chat.id)
    for raw in raw_list[:5]:
        item = normalize(raw)
        caption = format_caption(item, q, cfg["JPY_USD_RATE"])
        sent = False
        if item["thumbnail"]:
            try:
                await ctx.application.bot.send_photo(
                    chat_id, photo=item["thumbnail"], caption=caption, parse_mode=ParseMode.HTML
                )
                sent = True
            except TelegramError as e:
                log.warning("/search send_photo failed (%s); falling back to text", e)
        if not sent:
            await ctx.application.bot.send_message(
                chat_id, caption, parse_mode=ParseMode.HTML, disable_web_page_preview=False
            )
        await asyncio.sleep(0.3)


# ---------- lifecycle ----------

async def _handle_health(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.read(2048)
        body = b"OK"
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def post_init(app: Application) -> None:
    cfg = app.bot_data["cfg"]
    con = app.bot_data["con"]
    poller = Poller(app, cfg, con)
    app.bot_data["poller"] = poller
    poller.task = asyncio.create_task(poller.run())
    log.info(
        "poller started (interval=%ss, queries=%d)",
        cfg["POLL_INTERVAL_SECONDS"],
        len(cfg["SEARCH_QUERIES"]),
    )

    port = os.environ.get("PORT")
    if port and port.isdigit():
        server = await asyncio.start_server(_handle_health, "0.0.0.0", int(port))
        app.bot_data["health_server"] = server
        log.info("health server listening on :%s", port)


async def post_shutdown(app: Application) -> None:
    poller: Poller | None = app.bot_data.get("poller")
    if poller:
        poller.stop_event.set()
        if poller.task:
            try:
                await asyncio.wait_for(poller.task, timeout=10)
            except asyncio.TimeoutError:
                poller.task.cancel()
    server: asyncio.AbstractServer | None = app.bot_data.get("health_server")
    if server:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = load_config()
    if not cfg["TELEGRAM_BOT_TOKEN"]:
        log.error("TELEGRAM_BOT_TOKEN is required (env var or config.json)")
        sys.exit(1)
    if not cfg["TELEGRAM_CHAT_ID"]:
        log.error("TELEGRAM_CHAT_ID is required (env var or config.json)")
        sys.exit(1)

    con = db_init()
    app = (
        Application.builder()
        .token(cfg["TELEGRAM_BOT_TOKEN"])
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )
    app.bot_data["cfg"] = cfg
    app.bot_data["con"] = con
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("add", cmd_add))
    app.add_handler(CommandHandler("remove", cmd_remove))
    app.add_handler(CommandHandler("search", cmd_search))

    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
