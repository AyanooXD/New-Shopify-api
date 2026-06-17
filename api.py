# 𝐓𝐞𝐥𝐞𝐠𝐫𝐚𝐦: https://t.me/scriptdung
# 𝐁𝐚𝐜𝐤𝐮𝐩: https://t.me/scriptdungbackup
# 𝐃𝐞𝐯: @Xoarch
# Converted from Flask → Robyn (Railway Hobby Plan optimized)
# Tweaks applied: #1 Global Connection Pool | #6 LRU Cache for fetch_products

import os
import json
import time
import asyncio
import aiohttp
from functools import lru_cache
from urllib.parse import unquote
from robyn import Robyn, Request, Response, Headers

import core
from core import (
    process_card_async,
    parse_cc_string,
    extract_clean_response,
    fetch_products as _original_fetch_products,
    _get_ssl_connector,
)

# ═══════════════════════════════════════════════════════════════
# TWEAK #1 — GLOBAL aiohttp CONNECTION POOL
# ───────────────────────────────────────────────────────────────
# Instead of creating a new ClientSession on every request
# (which opens + closes TCP connections each time = slow),
# we maintain ONE shared session with a connector pool.
#
# TCPConnector settings tuned for Railway 8 vCPU / 8 GB:
#   limit=200        → max total open connections across all coroutines
#   limit_per_host=30 → max connections to any single Shopify store
#   ttl_dns_cache=300 → cache DNS for 5 min (avoids repeated DNS lookups)
#   keepalive_timeout=30 → keep TCP connections alive for reuse
# ═══════════════════════════════════════════════════════════════

_http_session: aiohttp.ClientSession | None = None


async def get_http_session() -> aiohttp.ClientSession:
    """Return (or lazily create) the global shared HTTP session."""
    global _http_session
    if _http_session is None or _http_session.closed:
        connector = _get_ssl_connector(
            verify=True,
            limit=200,
            limit_per_host=30,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
            keepalive_timeout=30,
        )
        timeout = aiohttp.ClientTimeout(total=30, connect=5)
        _http_session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        )
    return _http_session


# ═══════════════════════════════════════════════════════════════
# TWEAK #6 — TTL-BASED LRU CACHE FOR fetch_products
# ───────────────────────────────────────────────────────────────
# fetch_products() hits /products.json on the target store.
# Same domain gets called many times — no point fetching again
# if we just fetched it 5 minutes ago.
#
# Cache design:
#   - maxsize=512   → remember up to 512 unique domains
#   - TTL = 300 sec → entries expire after 5 minutes
#   - Key = (domain, proxy_str) — proxy-aware
# ═══════════════════════════════════════════════════════════════

_PRODUCT_CACHE: dict[str, tuple[float, object]] = {}
_CACHE_TTL = 300          # seconds
_CACHE_MAXSIZE = 512


async def fetch_products_cached(domain: str, proxy_str=None):
    """
    TTL-cached wrapper around core.fetch_products().
    Returns cached result if fresh, otherwise fetches and caches.
    """
    cache_key = f"{domain}||{proxy_str or ''}"
    now = time.monotonic()

    # Cache hit?
    if cache_key in _PRODUCT_CACHE:
        cached_at, cached_result = _PRODUCT_CACHE[cache_key]
        if now - cached_at < _CACHE_TTL:
            return cached_result

    # Cache miss — fetch fresh
    result = await _original_fetch_products(domain, proxy_str)

    # Don't cache failures — if site is down/erroring, retry next request
    if isinstance(result, tuple) and result[0] is False:
        return result

    # Evict oldest entry if cache is full
    if len(_PRODUCT_CACHE) >= _CACHE_MAXSIZE:
        oldest_key = min(_PRODUCT_CACHE, key=lambda k: _PRODUCT_CACHE[k][0])
        del _PRODUCT_CACHE[oldest_key]

    _PRODUCT_CACHE[cache_key] = (now, result)
    return result


# Monkey-patch core so process_card() uses cached version automatically
core.fetch_products = fetch_products_cached


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def json_response(data: dict, status_code: int = 200) -> Response:
    """Return a JSON Response object."""
    return Response(
        status_code=status_code,
        headers=Headers({"Content-Type": "application/json"}),
        description=json.dumps(data),
    )


# ═══════════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════════

app = Robyn(__file__)


@app.get("/shopify")
async def shopify_checker(request: Request):
    try:
        params = request.query_params

        # FIX: unquote params defensively — handles any double-encoding edge cases
        site       = unquote(params.get("site", "") or "").strip() or None
        cc_string  = unquote(params.get("cc", "") or "").strip() or None
        proxy_str  = unquote(params.get("proxy", "") or "").strip() or None
        variant_id = unquote(params.get("variant", "") or "").strip() or None

        if not site:
            return json_response(
                {"error": "Missing 'site' parameter", "status": False},
                status_code=400,
            )

        if not cc_string:
            return json_response(
                {
                    "error": "Missing 'cc' parameter in format CC|MM|YYYY|CVV",
                    "status": False,
                },
                status_code=400,
            )

        try:
            cc_parts = parse_cc_string(cc_string)
            cc  = cc_parts["cc"]
            mes = cc_parts["mes"]
            ano = cc_parts["ano"]
            cvv = cc_parts["cvv"]
        except ValueError as e:
            return json_response({"error": str(e), "status": False}, status_code=400)

        success, message, gateway, price, currency = await process_card_async(
            cc, mes, ano, cvv, site, variant_id, proxy_str, shared_session=await get_http_session()
        )

        clean_response = extract_clean_response(message)

        return json_response(
            {
                "Gateway":  gateway,
                "Price":    float(price) if str(price).replace(".", "", 1).isdigit() else 0.0,
                "Response": clean_response,
                "Status":   success,
                "cc":       cc_string,
            }
        )

    except Exception as e:
        cc_string_safe = request.query_params.get("cc", "")
        return json_response(
            {
                "error":    str(e),
                "status":   False,
                "Gateway":  "UNKNOWN",
                "Price":    0.0,
                "Response": f"ERROR: {str(e)}",
                "cc":       cc_string_safe,
            },
            status_code=500,
        )


@app.get("/health")
async def health(request: Request):
    return json_response({"status": "ok"})


@app.get("/cache/stats")
async def cache_stats(request: Request):
    """Debug endpoint — shows product cache stats."""
    now = time.monotonic()
    total = len(_PRODUCT_CACHE)
    fresh = sum(
        1 for _, (cached_at, _) in _PRODUCT_CACHE.items()
        if now - cached_at < _CACHE_TTL
    )
    return json_response({
        "cache_total_entries": total,
        "cache_fresh_entries": fresh,
        "cache_expired_entries": total - fresh,
        "cache_ttl_seconds": _CACHE_TTL,
        "cache_max_size": _CACHE_MAXSIZE,
    })


# ═══════════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN LIFECYCLE
# ═══════════════════════════════════════════════════════════════

@app.startup_handler
async def on_startup():
    """Pre-warm the global HTTP session on app start."""
    await get_http_session()
    print("[Startup] Global aiohttp connection pool initialized ✅")
    print(f"[Startup] Product cache ready (TTL={_CACHE_TTL}s, maxsize={_CACHE_MAXSIZE}) ✅")


@app.shutdown_handler
async def on_shutdown():
    """Gracefully close the HTTP session on shutdown."""
    global _http_session
    if _http_session and not _http_session.closed:
        await _http_session.close()
        print("[Shutdown] aiohttp session closed cleanly ✅")


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))

    # ─────────────────────────────────────────────────────────
    # Railway Hobby Plan per replica: 8 vCPU / 8 GB RAM
    #   --processes 7  → 7 worker processes (8 vCPU - 1 for OS)
    #   --workers   4  → 4 async workers per process
    #   Total slots ≈  28 concurrent requests
    #   RAM per process ≈ 8 GB / 7 ≈ ~1.1 GB  ✅
    # ─────────────────────────────────────────────────────────
    app.start(host="0.0.0.0", port=port, client_timeout=60, keep_alive_timeout=30)
