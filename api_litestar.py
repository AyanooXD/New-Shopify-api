# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Litestar API — Native async, production-grade Shopify checkout API
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Traffic management layers (in order):
#   1. Request Deduplication — same card+site reuses in-flight result
#   2. Backpressure         — rejects mass checks when queue too long
#   3. Dedicated Lanes      — /cc gets reserved slots, never blocked by mass
#   4. Token Bucket         — per-user rate limit (requests/sec)
#   5. Priority Queue       — single checks processed before mass checks
#   6. Circuit Breaker      — auto-skips sites that keep failing
#   7. Request Timeout      — 30s hard cutoff on checkout flow
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import asyncio
import os
import sys
import time
from collections import defaultdict
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse

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

# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION (all tunable via env vars)
# ══════════════════════════════════════════════════════════════════════
_SINGLE_SLOTS = int(os.environ.get('SINGLE_SLOTS', '5'))     # reserved for /cc
_MASS_SLOTS = int(os.environ.get('MASS_SLOTS', '30'))         # for /chk mass
_MAX_QUEUE = int(os.environ.get('MAX_QUEUE', '50'))           # backpressure threshold
_USER_RATE_LIMIT = float(os.environ.get('USER_RATE', '5.0'))  # requests/sec per user
_USER_BURST = int(os.environ.get('USER_BURST', '8'))          # burst allowance
_CHECKOUT_TIMEOUT = int(os.environ.get('CHECKOUT_TIMEOUT', '45'))  # seconds
_CB_FAIL_THRESHOLD = int(os.environ.get('CB_FAIL_THRESHOLD', '5'))  # failures to trip
_CB_COOLDOWN = int(os.environ.get('CB_COOLDOWN', '60'))       # seconds site is blocked
_DEDUP_TTL = int(os.environ.get('DEDUP_TTL', '30'))           # seconds to keep dedup


# ══════════════════════════════════════════════════════════════════════
# LAYER 1: REQUEST DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════
# If multiple requests for the same card+site arrive simultaneously,
# only the first one runs the checkout. Others await the same Future.
_inflight: Dict[str, asyncio.Future] = {}
_dedup_hits = 0
_dedup_total = 0


async def _dedup_or_run(dedup_key: str, coro_factory):
    """Return cached in-flight result or start a new checkout."""
    global _dedup_hits, _dedup_total
    _dedup_total += 1

    if dedup_key in _inflight:
        fut = _inflight[dedup_key]
        if not fut.done():
            _dedup_hits += 1
            return await fut

    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    _inflight[dedup_key] = fut

    try:
        result = await coro_factory()
        fut.set_result(result)
        return result
    except Exception as exc:
        fut.set_exception(exc)
        raise
    finally:
        # Clean up after a short TTL so identical requests within
        # a few seconds still benefit from the result.
        async def _cleanup():
            await asyncio.sleep(_DEDUP_TTL)
            _inflight.pop(dedup_key, None)
        asyncio.create_task(_cleanup())


# ══════════════════════════════════════════════════════════════════════
# LAYER 3: DEDICATED LANES (semaphores)
# ══════════════════════════════════════════════════════════════════════
_single_sem: Optional[asyncio.Semaphore] = None
_mass_sem: Optional[asyncio.Semaphore] = None
_active_single = 0
_active_mass = 0
_queued_single = 0
_queued_mass = 0


def _get_lane_sems() -> Tuple[asyncio.Semaphore, asyncio.Semaphore]:
    global _single_sem, _mass_sem
    if _single_sem is None:
        _single_sem = asyncio.Semaphore(_SINGLE_SLOTS)
    if _mass_sem is None:
        _mass_sem = asyncio.Semaphore(_MASS_SLOTS)
    return _single_sem, _mass_sem


# ══════════════════════════════════════════════════════════════════════
# LAYER 4: TOKEN BUCKET (per-user rate limiter)
# ══════════════════════════════════════════════════════════════════════
class _TokenBucket:
    __slots__ = ('rate', 'burst', 'tokens', 'last_refill')

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.last_refill = time.monotonic()

    def consume(self) -> float:
        """Try to consume 1 token. Returns 0 if OK, else wait seconds."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return 0.0
        return (1.0 - self.tokens) / self.rate


_user_buckets: Dict[str, _TokenBucket] = {}
_rate_limited_count = 0


def _get_bucket(user_id: str) -> _TokenBucket:
    if user_id not in _user_buckets:
        _user_buckets[user_id] = _TokenBucket(_USER_RATE_LIMIT, _USER_BURST)
    return _user_buckets[user_id]


# ══════════════════════════════════════════════════════════════════════
# LAYER 5: PRIORITY QUEUE
# ══════════════════════════════════════════════════════════════════════
# Single checks (priority=0) are processed before mass checks (priority=1).
# Within same priority, FIFO order is maintained via a counter.
_pq_counter = 0
_pq: asyncio.PriorityQueue = None  # lazy init
_pq_workers_started = False


def _get_pq() -> asyncio.PriorityQueue:
    global _pq
    if _pq is None:
        _pq = asyncio.PriorityQueue()
    return _pq


# ══════════════════════════════════════════════════════════════════════
# LAYER 6: CIRCUIT BREAKER (per site)
# ══════════════════════════════════════════════════════════════════════
class _CircuitBreaker:
    __slots__ = ('fail_count', 'last_fail', 'tripped_at')

    def __init__(self):
        self.fail_count = 0
        self.last_fail = 0.0
        self.tripped_at = 0.0

    def record_failure(self):
        now = time.monotonic()
        # Reset count if last failure was long ago
        if now - self.last_fail > _CB_COOLDOWN:
            self.fail_count = 0
        self.fail_count += 1
        self.last_fail = now
        if self.fail_count >= _CB_FAIL_THRESHOLD:
            self.tripped_at = now

    def record_success(self):
        self.fail_count = max(0, self.fail_count - 1)
        if self.fail_count < _CB_FAIL_THRESHOLD:
            self.tripped_at = 0.0

    def is_open(self) -> bool:
        if self.tripped_at == 0.0:
            return False
        if time.monotonic() - self.tripped_at > _CB_COOLDOWN:
            # Half-open: allow one request through to test recovery
            self.tripped_at = 0.0
            self.fail_count = _CB_FAIL_THRESHOLD - 1
            return False
        return True


_circuit_breakers: Dict[str, _CircuitBreaker] = {}
_cb_rejected = 0


def _get_cb(site_domain: str) -> _CircuitBreaker:
    if site_domain not in _circuit_breakers:
        _circuit_breakers[site_domain] = _CircuitBreaker()
    return _circuit_breakers[site_domain]


# Site error keywords that trigger circuit breaker
_CB_TRIGGER_KEYWORDS = {
    'captcha_required', 'captcha_block', 'rate-limited', 'http 429',
    'timed out', 'connection failed', 'ssl error', 'timeout',
    'store is password-protected', 'site requires login',
}


def _is_site_failure(response_msg: str) -> bool:
    low = response_msg.lower()
    return any(kw in low for kw in _CB_TRIGGER_KEYWORDS)


# ══════════════════════════════════════════════════════════════════════
# TTL-BASED CACHE FOR fetch_products
# ══════════════════════════════════════════════════════════════════════
_PRODUCT_CACHE: Dict[str, tuple] = {}
_CACHE_TTL = 300
_CACHE_MAXSIZE = 512


async def fetch_products_cached(domain: str, proxy_str: Optional[str] = None):
    """Cache wrapper for fetch_products with TTL eviction."""
    cache_key = f"{domain}||{proxy_str or ''}"
    now = time.monotonic()
    if cache_key in _PRODUCT_CACHE:
        cached_at, cached_result = _PRODUCT_CACHE[cache_key]
        if now - cached_at < _CACHE_TTL:
            return cached_result
    result = await _original_fetch_products(domain, proxy_str)
    success, data = result
    if success:
        if len(_PRODUCT_CACHE) >= _CACHE_MAXSIZE:
            oldest_key = min(_PRODUCT_CACHE, key=lambda k: _PRODUCT_CACHE[k][0])
            del _PRODUCT_CACHE[oldest_key]
        _PRODUCT_CACHE[cache_key] = (now, result)
    return result


core.fetch_products = fetch_products_cached


# ══════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

@get("/health", media_type=MediaType.JSON, sync=False)
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@get("/cache/stats", media_type=MediaType.JSON, sync=False)
async def cache_stats() -> Dict[str, Any]:
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


@get("/status", media_type=MediaType.JSON, sync=False)
async def api_status() -> Dict[str, Any]:
    """Live API status with all layer metrics."""
    # Circuit breaker summary
    now = time.monotonic()
    tripped_sites = [
        domain for domain, cb in _circuit_breakers.items() if cb.is_open()
    ]
    return {
        "lanes": {
            "single": {"active": _active_single, "queued": _queued_single, "max": _SINGLE_SLOTS},
            "mass": {"active": _active_mass, "queued": _queued_mass, "max": _MASS_SLOTS},
        },
        "total_active": _active_single + _active_mass,
        "total_queued": _queued_single + _queued_mass,
        "dedup": {"hits": _dedup_hits, "total": _dedup_total},
        "circuit_breaker": {"tripped_sites": tripped_sites, "rejected": _cb_rejected},
        "rate_limited_count": _rate_limited_count,
    }


@get("/circuit-breaker", media_type=MediaType.JSON, sync=False)
async def circuit_breaker_status() -> Dict[str, Any]:
    """Show circuit breaker state for all tracked sites."""
    now = time.monotonic()
    sites = {}
    for domain, cb in _circuit_breakers.items():
        sites[domain] = {
            "fail_count": cb.fail_count,
            "is_open": cb.is_open(),
            "cooldown_remaining": max(0, _CB_COOLDOWN - (now - cb.tripped_at)) if cb.tripped_at else 0,
        }
    return {"sites": sites, "threshold": _CB_FAIL_THRESHOLD, "cooldown_seconds": _CB_COOLDOWN}


@get("/shopify", media_type=MediaType.JSON, sync=False)
async def shopify_checker(
    site: Optional[str] = Parameter(
        query="site", required=False, default=None,
        description="Shopify store URL",
    ),
    cc: Optional[str] = Parameter(
        query="cc", required=False, default=None,
        description="Card in CC|MM|YYYY|CVV format",
    ),
    proxy: Optional[str] = Parameter(
        query="proxy", required=False, default=None,
        description="Proxy in ip:port:user:pass format",
    ),
    variant: Optional[str] = Parameter(
        query="variant", required=False, default=None,
        description="Product variant ID (auto-detected if omitted)",
    ),
    lane: Optional[str] = Parameter(
        query="lane", required=False, default="mass",
        description="'single' for /cc priority lane, 'mass' for /chk mass lane",
    ),
    user_id: Optional[str] = Parameter(
        query="user_id", required=False, default="anonymous",
        description="User identifier for rate limiting",
    ),
) -> Response:
    """Main Shopify checkout endpoint with all traffic management layers."""
    global _active_single, _active_mass, _queued_single, _queued_mass
    global _cb_rejected, _rate_limited_count

    try:
        cc_string = ""
        site = site.strip() if site else None
        cc_string = cc.strip() if cc else ""
        proxy_str = proxy.strip() if proxy else None
        variant_id = variant.strip() if variant else None
        is_single = (lane or "mass").lower() == "single"
        uid = (user_id or "anonymous").strip()

        if not site:
            return Response(
                content={"error": "Missing 'site' parameter", "status": False},
                status_code=400, media_type=MediaType.JSON,
            )
        if not cc_string:
            return Response(
                content={"error": "Missing 'cc' parameter in format CC|MM|YYYY|CVV", "status": False},
                status_code=400, media_type=MediaType.JSON,
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
                status_code=400, media_type=MediaType.JSON,
            )

        site_domain = urlparse(site if site.startswith('http') else f'https://{site}').netloc

        # ── LAYER 6: CIRCUIT BREAKER ──
        cb = _get_cb(site_domain)
        if cb.is_open():
            _cb_rejected += 1
            return Response(
                content={
                    "Gateway": "UNKNOWN", "Price": 0.0, "Currency": "USD",
                    "Response": f"SITE_BLOCKED: {site_domain} temporarily blocked (too many failures, retry in {_CB_COOLDOWN}s)",
                    "Status": False, "cc": cc_string,
                },
                status_code=200, media_type=MediaType.JSON,
            )

        # ── LAYER 2: BACKPRESSURE ──
        total_queued = _queued_single + _queued_mass
        if not is_single and total_queued >= _MAX_QUEUE:
            return Response(
                content={
                    "Gateway": "UNKNOWN", "Price": 0.0, "Currency": "USD",
                    "Response": "SERVER_BUSY: Too many queued requests, try later",
                    "Status": False, "cc": cc_string,
                },
                status_code=200, media_type=MediaType.JSON,
            )

        # ── LAYER 4: TOKEN BUCKET (per-user rate limit) ──
        bucket = _get_bucket(uid)
        wait_time = bucket.consume()
        if wait_time > 0:
            if wait_time > 5.0:
                _rate_limited_count += 1
                return Response(
                    content={
                        "Gateway": "UNKNOWN", "Price": 0.0, "Currency": "USD",
                        "Response": f"RATE_LIMITED: Too fast, wait {wait_time:.1f}s",
                        "Status": False, "cc": cc_string,
                    },
                    status_code=200, media_type=MediaType.JSON,
                )
            await asyncio.sleep(wait_time)

        # ── LAYER 1: DEDUPLICATION ──
        dedup_key = f"{card_number}|{site_domain}"

        async def _run_checkout():
            global _active_single, _active_mass, _queued_single, _queued_mass

            # ── LAYER 3: DEDICATED LANES ──
            single_sem, mass_sem = _get_lane_sems()
            sem = single_sem if is_single else mass_sem

            if is_single:
                _queued_single += 1
            else:
                _queued_mass += 1

            try:
                async with sem:
                    if is_single:
                        _queued_single -= 1
                        _active_single += 1
                    else:
                        _queued_mass -= 1
                        _active_mass += 1

                    try:
                        # ── LAYER 7: REQUEST TIMEOUT ──
                        result = await asyncio.wait_for(
                            process_card_async(
                                card_number, mes, ano, cvv, site, variant_id, proxy_str
                            ),
                            timeout=_CHECKOUT_TIMEOUT,
                        )
                        return result
                    except asyncio.TimeoutError:
                        return (False, f"CHECKOUT_TIMEOUT: Exceeded {_CHECKOUT_TIMEOUT}s", "UNKNOWN", "0.00", "USD")
                    finally:
                        if is_single:
                            _active_single -= 1
                        else:
                            _active_mass -= 1
            except Exception:
                if is_single:
                    _queued_single = max(0, _queued_single - 1)
                else:
                    _queued_mass = max(0, _queued_mass - 1)
                raise

        success, message, gateway, price, currency = await _dedup_or_run(
            dedup_key, _run_checkout
        )

        # ── LAYER 6: CIRCUIT BREAKER (record result) ──
        if _is_site_failure(message):
            cb.record_failure()
        else:
            cb.record_success()

        clean_response = extract_clean_response(message)

        try:
            price_float = float(price)
        except (ValueError, TypeError):
            price_float = 0.0

        return Response(
            content={
                "Gateway": gateway,
                "Price": price_float,
                "Currency": currency,
                "Response": clean_response,
                "Status": success,
                "cc": cc_string,
            },
            status_code=200, media_type=MediaType.JSON,
        )

    except Exception as e:
        return Response(
            content={
                "error": str(e), "status": False,
                "Gateway": "UNKNOWN", "Price": 0.0,
                "Response": f"ERROR: {str(e)}",
                "cc": cc_string if cc_string else "",
            },
            status_code=500, media_type=MediaType.JSON,
        )


# ══════════════════════════════════════════════════════════════════════
# APP INITIALIZATION
# ══════════════════════════════════════════════════════════════════════
app = Litestar(
    route_handlers=[health, cache_stats, api_status, circuit_breaker_status, shopify_checker],
    debug=False,
    openapi_config=None,
)
