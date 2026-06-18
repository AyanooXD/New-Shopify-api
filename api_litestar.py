# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Litestar API — Native async, production-grade Shopify checkout API
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Migration history:
#   Robyn (port bug) → Flask + Gunicorn (sync, thread-limited) → Litestar + Uvicorn (native async)
#
# Why Litestar over Flask:
#   - Native async/await: process_card_async() runs directly in the ASGI event loop
#     (Flask needed asyncio.run_until_complete() hack which blocks the thread)
#   - Single process handles 100+ concurrent requests (Flask: 4 workers × 4 threads = 16 max)
#   - Non-blocking sleep during rate-limit retries (Flask: sleep blocks the entire thread)
#   - Lower memory per request (coroutine vs OS thread)
#   - Built-in OpenAPI docs at /schema/swagger
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import time
from typing import Optional, Dict, Any

from litestar import Litestar, get, post, MediaType
from litestar.params import Parameter
from litestar.response import Response

import core
from core import (
    process_card_async,
    parse_cc_string,
    extract_clean_response,
    fetch_products as _original_fetch_products,
)

# ──────────────────────────────────────────────────────────────────────
# TTL-BASED CACHE FOR fetch_products
# ──────────────────────────────────────────────────────────────────────
_PRODUCT_CACHE: Dict[str, tuple] = {}
_CACHE_TTL = 300
_CACHE_MAXSIZE = 512


async def fetch_products_cached(domain: str, proxy_str: Optional[str] = None):
    """Cache wrapper for fetch_products with TTL eviction.

    Caches product lookups per domain+proxy for _CACHE_TTL seconds.
    Prevents redundant product.json fetches when mass-checking the same store.
    
    Returns: (success: bool, data_or_error: dict|str) — consistent tuple format.
    """
    cache_key = f"{domain}||{proxy_str or ''}"
    now = time.monotonic()
    if cache_key in _PRODUCT_CACHE:
        cached_at, cached_result = _PRODUCT_CACHE[cache_key]
        if now - cached_at < _CACHE_TTL:
            return cached_result
    result = await _original_fetch_products(domain, proxy_str)
    # FIX: fetch_products now always returns (success, data_or_error) tuple.
    # Only cache successful results to avoid caching errors.
    success, data = result
    if success:
        if len(_PRODUCT_CACHE) >= _CACHE_MAXSIZE:
            oldest_key = min(_PRODUCT_CACHE, key=lambda k: _PRODUCT_CACHE[k][0])
            del _PRODUCT_CACHE[oldest_key]
        _PRODUCT_CACHE[cache_key] = (now, result)
    return result


core.fetch_products = fetch_products_cached

# ──────────────────────────────────────────────────────────────────────
# LITESTAR ENDPOINTS — All native async, no thread blocking
# ──────────────────────────────────────────────────────────────────────


@get("/health", media_type=MediaType.JSON, sync=False)
async def health() -> Dict[str, str]:
    """Health check endpoint. Used by Railway to verify the API is alive."""
    return {"status": "ok"}


@get("/cache/stats", media_type=MediaType.JSON, sync=False)
async def cache_stats() -> Dict[str, Any]:
    """Product cache statistics. Shows fresh/expired entries."""
    now = time.monotonic()
    total = len(_PRODUCT_CACHE)
    fresh = sum(
        1
        for _, (cached_at, _) in _PRODUCT_CACHE.items()
        if now - cached_at < _CACHE_TTL
    )
    return {
        "cache_total_entries": total,
        "cache_fresh_entries": fresh,
        "cache_expired_entries": total - fresh,
        "cache_ttl_seconds": _CACHE_TTL,
        "cache_max_size": _CACHE_MAXSIZE,
    }


@get("/shopify", media_type=MediaType.JSON, sync=False)
async def shopify_checker(
    site: Optional[str] = Parameter(
        query="site",
        required=False,
        default=None,
        description="Shopify store URL (e.g. https://store.myshopify.com)",
    ),
    cc: Optional[str] = Parameter(
        query="cc",
        required=False,
        default=None,
        description="Card details in format CC|MM|YYYY|CVV",
    ),
    proxy: Optional[str] = Parameter(
        query="proxy",
        required=False,
        default=None,
        description="Proxy in format ip:port:user:pass",
    ),
    variant: Optional[str] = Parameter(
        query="variant",
        required=False,
        default=None,
        description="Product variant ID (auto-detected if omitted)",
    ),
) -> Response:
    """Main Shopify checkout endpoint.

    NATIVE ASYNC — process_card_async() runs directly in the ASGI event loop.
    No asyncio.run_until_complete() hack needed (unlike Flask).
    This means:
      - 100+ concurrent requests handled in a single process
      - Rate-limit retry sleeps are non-blocking (don't consume a thread)
      - Lower memory per request (coroutine vs OS thread)
    """
    try:
        # Initialize cc_string early so it's always available in the exception handler
        cc_string = ""
        # FIX: Litestar already URL-decodes query parameters automatically.
        # Calling unquote() again would double-decode (e.g. %252F → %2F → /).
        # Just strip whitespace instead.
        site = site.strip() if site else None
        cc_string = cc.strip() if cc else ""
        proxy_str = proxy.strip() if proxy else None
        variant_id = variant.strip() if variant else None

        if not site:
            return Response(
                content={"error": "Missing 'site' parameter", "status": False},
                status_code=400,
                media_type=MediaType.JSON,
            )
        if not cc_string:
            return Response(
                content={
                    "error": "Missing 'cc' parameter in format CC|MM|YYYY|CVV",
                    "status": False,
                },
                status_code=400,
                media_type=MediaType.JSON,
            )

        try:
            cc_parts = parse_cc_string(cc_string)
            card_number = cc_parts["cc"]
            mes = cc_parts["mes"]
            ano = cc_parts["ano"]
            cvv = cc_parts["cvv"]
        except ValueError as e:
            return Response(
                content={"error": str(e), "status": False},
                status_code=400,
                media_type=MediaType.JSON,
            )

        # ── NATIVE ASYNC CALL ──
        # Directly await the async function — no event loop juggling!
        # Flask needed: loop = asyncio.new_event_loop(); loop.run_until_complete(...)
        # Litestar: just await — runs in the existing ASGI event loop
        success, message, gateway, price, currency = await process_card_async(
            card_number, mes, ano, cvv, site, variant_id, proxy_str
        )

        clean_response = extract_clean_response(message)

        # Format price safely
        try:
            price_float = float(price)
        except (ValueError, TypeError):
            price_float = 0.0

        return Response(
            content={
                "Gateway": gateway,
                "Price": price_float,
                "Response": clean_response,
                "Status": success,
                "cc": cc_string,
            },
            status_code=200,
            media_type=MediaType.JSON,
        )

    except Exception as e:
        return Response(
            content={
                "error": str(e),
                "status": False,
                "Gateway": "UNKNOWN",
                "Price": 0.0,
                "Response": f"ERROR: {str(e)}",
                "cc": cc_string if cc_string else "",
            },
            status_code=500,
            media_type=MediaType.JSON,
        )


# ──────────────────────────────────────────────────────────────────────
# APP INITIALIZATION
# ──────────────────────────────────────────────────────────────────────
app = Litestar(
    route_handlers=[health, cache_stats, shopify_checker],
    debug=False,
    # OpenAPI docs available at /schema/swagger
    openapi_config=None,  # Disable for production (saves memory)
)
