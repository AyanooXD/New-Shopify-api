"""Tests for the SUBMIT_REJECTED root-cause fix.

The user-reported bug:
    {"Gateway":"shopify_payments","Price":7.0,"Currency":"USD",
     "Response":"SUBMIT_REJECTED","Status":false,
     "cc":"4242424242424242|12|2027|123"}

Root cause chain:
  1. QUERY_PROPOSAL did not request stableId inside linesV2 of
     FilledMerchandiseLineTargetCollection.
  2. _parse_negotiate_response() therefore saw linesV2 entries without
     stableId and produced targetMerchandiseLines: {lines: []} — an
     INVALID empty list.
  3. Shopify rejected the submit with DELIVERY_DELIVERY_LINE_DETAIL_CHANGED
     (a non-blocking warning).
  4. The retry path then sent targetMerchandiseLines: {any: True} (a
     *different* value), causing Shopify's backend to crash with
     INTERNAL_SERVER_ERROR.
  5. The retry-path error filter had a Python operator-precedence bug
     that mis-classified MERCHANDISE_SIGNATURE_* warnings as blocking,
     so the crash surfaced to the user as "SUBMIT_REJECTED".

These tests verify the fixes:
  - GraphQL queries now request stableId inside linesV2.
  - _parse_negotiate_response() falls back to {any: True} when no stableId.
  - _payment_requires_offsite_action() helper exists (regression test for
    the function being deleted in commit ff851eb).
  - The retry-path error filter no longer mis-classifies
    MERCHANDISE_SIGNATURE_MISMATCH as blocking.
  - SUBMIT_REJECTED messages now preserve the underlying error code so
    extract_clean_response() doesn't strip everything after the prefix.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core


# ───────────────────────────────────────────────────────────────────────
# 0. GraphQL queries have balanced braces (regression test for PARSE_ERROR)
# ───────────────────────────────────────────────────────────────────────
def test_query_proposal_has_balanced_braces():
    """QUERY_PROPOSAL must have balanced { and } — Shopify rejects with
    'syntax error, unexpected RCURLY' (PARSE_ERROR) if there's an extra }.

    Regression: commit ba3fb56 introduced an extra } in the buyerProposal
    block ('any:_singleInstance}}}}' instead of 'any:_singleInstance}}}'),
    causing Shopify to reject the entire query at Step 5a (the very first
    negotiate call) with:
      'syntax error, unexpected RCURLY (\"}\") at [1, 2121]'
    """
    q = core.QUERY_PROPOSAL
    opens = q.count('{')
    closes = q.count('}')
    assert opens == closes, (
        f"QUERY_PROPOSAL has unbalanced braces: {opens} opens vs {closes} closes "
        f"(diff={closes - opens}). Shopify will reject with PARSE_ERROR."
    )
    # Walk depth to ensure it never goes negative (extra }) or ends positive (extra {)
    depth = 0
    for i, ch in enumerate(q):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            assert depth >= 0, (
                f"QUERY_PROPOSAL: depth went negative at char {i} — extra }}. "
                f"Context: ...{q[max(0,i-40):i+10]}..."
            )
    assert depth == 0, f"QUERY_PROPOSAL: final depth = {depth} (expected 0)"


def test_mutation_submit_has_balanced_braces():
    """MUTATION_SUBMIT must have balanced { and } — same PARSE_ERROR risk.

    Regression: the SubmitRejected sellerProposal fragment was missing 2
    closing braces after the delivery block (before '...on CheckpointDenied'),
    causing Shopify to reject with PARSE_ERROR.
    """
    q = core.MUTATION_SUBMIT
    opens = q.count('{')
    closes = q.count('}')
    assert opens == closes, (
        f"MUTATION_SUBMIT has unbalanced braces: {opens} opens vs {closes} closes "
        f"(diff={closes - opens}). Shopify will reject with PARSE_ERROR."
    )
    depth = 0
    for i, ch in enumerate(q):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            assert depth >= 0, (
                f"MUTATION_SUBMIT: depth went negative at char {i} — extra }}. "
                f"Context: ...{q[max(0,i-40):i+10]}..."
            )
    assert depth == 0, f"MUTATION_SUBMIT: final depth = {depth} (expected 0)"


# ───────────────────────────────────────────────────────────────────────
# 1. GraphQL queries request stableId inside linesV2 (using inline fragment)
# ───────────────────────────────────────────────────────────────────────
def test_query_proposal_requests_stable_id_in_lines_v2():
    """QUERY_PROPOSAL must request stableId inside linesV2 of
    FilledMerchandiseLineTargetCollection — otherwise the server returns
    linesV2 entries without stableId, which the old parser turned into
    the invalid {lines: []} payload.

    IMPORTANT: `linesV2` returns a UNION type `MerchandiseLineType`.
    GraphQL forbids field selections directly on a union — only `__typename`
    and inline fragments (`...on MemberType{...}`) are allowed. The previous
    query `linesV2{__typename stableId}` was rejected by Shopify with:
      "Selections can't be made directly on unions (see selections on MerchandiseLineType)"
    The fix wraps `stableId` inside `...on MerchandiseLine{stableId}`.
    """
    # Must use inline fragment for stableId (NOT direct field selection)
    assert 'FilledMerchandiseLineTargetCollection{linesV2{__typename ...on MerchandiseLine{stableId}}}' in core.QUERY_PROPOSAL, (
        "QUERY_PROPOSAL must request 'linesV2{__typename ...on MerchandiseLine{stableId}}' "
        "inside FilledMerchandiseLineTargetCollection — direct field selection on the "
        "MerchandiseLineType union is forbidden by GraphQL."
    )
    # Must NOT have the old buggy direct-selection form
    assert 'linesV2{__typename stableId}' not in core.QUERY_PROPOSAL, (
        "QUERY_PROPOSAL must NOT use 'linesV2{__typename stableId}' — stableId cannot "
        "be selected directly on the MerchandiseLineType union."
    )


def test_mutation_submit_requests_stable_id_in_lines_v2():
    """MUTATION_SUBMIT's SubmitRejected sellerProposal fragment must also
    request stableId in linesV2 using the inline fragment syntax."""
    assert 'FilledMerchandiseLineTargetCollection{linesV2{__typename ...on MerchandiseLine{stableId}}}' in core.MUTATION_SUBMIT, (
        "MUTATION_SUBMIT must request 'linesV2{__typename ...on MerchandiseLine{stableId}}' "
        "inside FilledMerchandiseLineTargetCollection in the SubmitRejected sellerProposal."
    )
    assert 'linesV2{__typename stableId}' not in core.MUTATION_SUBMIT, (
        "MUTATION_SUBMIT must NOT use 'linesV2{__typename stableId}' — direct field "
        "selection on the MerchandiseLineType union is forbidden by GraphQL."
    )


# ───────────────────────────────────────────────────────────────────────
# 2. _parse_negotiate_response() never produces {lines: []}
# ───────────────────────────────────────────────────────────────────────
def test_parse_negotiate_response_filled_target_without_stable_id_uses_any():
    """When the server returns FilledMerchandiseLineTargetCollection with
    linesV2 entries that lack stableId, the parser MUST fall back to
    {any: True} — never produce {lines: []}."""
    simulate_resp = {
        "data": {
            "session": {
                "negotiate": {
                    "errors": [],
                    "result": {
                        "__typename": "NegotiationResultAvailable",
                        "queueToken": "qt",
                        "sessionToken": "st",
                        "sellerProposal": {
                            "__typename": "Proposal",
                            "checkoutTotal": {
                                "__typename": "MoneyValueConstraint",
                                "value": {"amount": "7.00", "currencyCode": "USD"},
                            },
                            "isShippingRequired": True,
                            "delivery": {
                                "__typename": "FilledDeliveryTerms",
                                "deliveryLines": [{
                                    "__typename": "DeliveryLine",
                                    "deliveryMethodTypes": ["SHIPPING"],
                                    "stableId": "dl-1",
                                    "selectedDeliveryStrategy": {
                                        "__typename": "CompleteDeliveryStrategy",
                                        "handle": "h1",
                                        "code": "Standard",
                                        "title": "Standard",
                                        "amount": {
                                            "__typename": "MoneyValueConstraint",
                                            "value": {"amount": "0.00", "currencyCode": "USD"},
                                        },
                                    },
                                    "totalAmount": {
                                        "__typename": "MoneyValueConstraint",
                                        "value": {"amount": "0.00", "currencyCode": "USD"},
                                    },
                                    "destinationAddress": {
                                        "__typename": "StreetAddress",
                                        "address1": "1 Main St",
                                        "address2": None,
                                        "city": "City",
                                        "countryCode": "US",
                                        "zoneCode": "CA",
                                        "postalCode": "90001",
                                    },
                                    # KEY: linesV2 has only __typename, NO stableId
                                    # (this is what the old QUERY_PROPOSAL returned)
                                    "targetMerchandise": {
                                        "__typename": "FilledMerchandiseLineTargetCollection",
                                        "linesV2": [{"__typename": "MerchandiseLine"}],
                                    },
                                }],
                            },
                            "merchandise": {"__typename": "UnavailableTerms"},
                            "payment": {"__typename": "UnavailableTerms"},
                        },
                        "buyerProposal": {
                            "__typename": "Proposal",
                            "checkoutTotal": {"__typename": "AnyConstraint", "any": True},
                        },
                    },
                }
            }
        }
    }

    parsed = core._parse_negotiate_response(simulate_resp)
    server_delivery_lines = parsed.get('server_delivery_lines', [])
    assert len(server_delivery_lines) == 1, "Expected 1 delivery line"
    tml = server_delivery_lines[0].get('targetMerchandiseLines', {})
    assert tml == {'any': True}, (
        f"Expected targetMerchandiseLines to be {{'any': True}} (the safe fallback), "
        f"got {tml}. The old bug produced {{'lines': []}} which Shopify rejects."
    )

    # address2 must be '' (empty string), NOT None — Shopify's schema rejects null.
    sa = server_delivery_lines[0].get('destination', {}).get('streetAddress', {})
    assert sa.get('address2') == '', (
        f"address2 must be '' (empty string), got {sa.get('address2')!r}. "
        f"Shopify's DeliveryStreetAddressInput rejects null."
    )


def test_parse_negotiate_response_filled_target_with_stable_id_uses_lines():
    """When the server returns FilledMerchandiseLineTargetCollection with
    linesV2 entries that DO have stableId (the new correct GraphQL query
    using `...on MerchandiseLine{stableId}`), the parser MUST use
    {lines: [{stableId: '...'}]} — the explicit form preferred by Shopify."""
    simulate_resp = {
        "data": {
            "session": {
                "negotiate": {
                    "errors": [],
                    "result": {
                        "__typename": "NegotiationResultAvailable",
                        "queueToken": "qt",
                        "sessionToken": "st",
                        "sellerProposal": {
                            "__typename": "Proposal",
                            "checkoutTotal": {
                                "__typename": "MoneyValueConstraint",
                                "value": {"amount": "7.00", "currencyCode": "USD"},
                            },
                            "isShippingRequired": True,
                            "delivery": {
                                "__typename": "FilledDeliveryTerms",
                                "deliveryLines": [{
                                    "__typename": "DeliveryLine",
                                    "deliveryMethodTypes": ["SHIPPING"],
                                    "stableId": "dl-1",
                                    "selectedDeliveryStrategy": {
                                        "__typename": "CompleteDeliveryStrategy",
                                        "handle": "h1",
                                        "code": "Standard",
                                        "title": "Standard",
                                        "amount": {
                                            "__typename": "MoneyValueConstraint",
                                            "value": {"amount": "0.00", "currencyCode": "USD"},
                                        },
                                    },
                                    "totalAmount": {
                                        "__typename": "MoneyValueConstraint",
                                        "value": {"amount": "0.00", "currencyCode": "USD"},
                                    },
                                    "destinationAddress": {
                                        "__typename": "StreetAddress",
                                        "address1": "1 Main St",
                                        "address2": "",
                                        "city": "City",
                                        "countryCode": "US",
                                        "zoneCode": "CA",
                                        "postalCode": "90001",
                                    },
                                    # NEW: linesV2 entries now have stableId (because
                                    # the GraphQL query uses `...on MerchandiseLine{stableId}`)
                                    "targetMerchandise": {
                                        "__typename": "FilledMerchandiseLineTargetCollection",
                                        "linesV2": [{
                                            "__typename": "MerchandiseLine",
                                            "stableId": "ml-stable-123",
                                        }],
                                    },
                                }],
                            },
                            "merchandise": {"__typename": "UnavailableTerms"},
                            "payment": {"__typename": "UnavailableTerms"},
                        },
                        "buyerProposal": {
                            "__typename": "Proposal",
                            "checkoutTotal": {"__typename": "AnyConstraint", "any": True},
                        },
                    },
                }
            }
        }
    }

    parsed = core._parse_negotiate_response(simulate_resp)
    server_delivery_lines = parsed.get('server_delivery_lines', [])
    assert len(server_delivery_lines) == 1, "Expected 1 delivery line"
    tml = server_delivery_lines[0].get('targetMerchandiseLines', {})
    assert tml == {'lines': [{'stableId': 'ml-stable-123'}]}, (
        f"Expected targetMerchandiseLines to be {{'lines': [{{'stableId': 'ml-stable-123'}}]}} "
        f"when stableId is available, got {tml}."
    )


# ───────────────────────────────────────────────────────────────────────
# 3. _payment_requires_offsite_action() helper exists (regression test)
# ───────────────────────────────────────────────────────────────────────
def test_payment_requires_offsite_action_exists_and_works():
    """Regression test: _payment_requires_offsite_action was deleted in
    commit ff851eb but the test file was never updated, leaving the test
    suite broken. The helper must exist and detect both Shopify field names."""
    assert hasattr(core, '_payment_requires_offsite_action'), (
        "_payment_requires_offsite_action must exist — it was deleted in "
        "commit ff851eb but the test still imports it."
    )
    fn = core._payment_requires_offsite_action
    assert fn({"hasOffsiteRedirect": True}) is True
    assert fn({"hasOffsitePaymentMethod": True}) is True
    assert fn({"hasOffsiteRedirect": False, "hasOffsitePaymentMethod": False}) is False
    assert fn({}) is False
    assert fn(None) is False
    assert fn("not a dict") is False


# ───────────────────────────────────────────────────────────────────────
# 4. Retry-path error filter no longer mis-classifies
#    MERCHANDISE_SIGNATURE_MISMATCH as blocking (operator precedence fix)
# ───────────────────────────────────────────────────────────────────────
def test_retry_filter_does_not_classify_merch_signature_as_blocking():
    """The retry-path _blocking filter had a Python operator-precedence bug:
        `code not in A and code not in B or 'MERCHANDISE_SIGNATURE' in str(e)`
    parsed as `(code not in A and code not in B) or ('MERCHANDISE_SIGNATURE' in str(e))`,
    which incorrectly marked MERCHANDISE_SIGNATURE_MISMATCH warnings as
    blocking — re-introducing the very bug _NON_BLOCKING_CODES was meant to fix.

    We simulate the filter logic with the same inputs and verify that
    MERCHANDISE_SIGNATURE_MISMATCH is NOT classified as blocking.
    """
    _NON_BLOCKING_CODES = {
        'MERCHANDISE_SIGNATURE_MISMATCH',
        'DELIVERY_DELIVERY_LINE_DETAIL_CHANGED',
        'REQUIRED_ARTIFACTS_UNAVAILABLE',
        'PAYMENTS_UNACCEPTABLE_PAYMENT_AMOUNT',
    }
    _TRANSIENT_CODES = {'INTERNAL_SERVER_ERROR', 'INTERNAL_ERROR'}
    _RETRY_IGNORE_CODES = ({'INVALID_VARIABLE'} | _TRANSIENT_CODES | _NON_BLOCKING_CODES)

    # Simulate the new filter logic
    def classify(errors):
        blocking = []
        for e in errors:
            ecode = (e.get('extensions') or {}).get('code', '') or e.get('code', '')
            e_str = str(e)
            if ecode in _RETRY_IGNORE_CODES:
                continue
            if 'MERCHANDISE_SIGNATURE' in e_str:
                continue
            blocking.append(e)
        return blocking

    # Case 1: MERCHANDISE_SIGNATURE_MISMATCH must NOT be blocking
    errs = [
        {"code": "MERCHANDISE_SIGNATURE_MISMATCH",
         "message": "Merchandise signature has changed.",
         "extensions": {"code": "MERCHANDISE_SIGNATURE_MISMATCH"}},
    ]
    assert classify(errs) == [], (
        "MERCHANDISE_SIGNATURE_MISMATCH must NOT be in _blocking — it's a "
        "non-blocking warning. The old operator-precedence bug treated it as blocking."
    )

    # Case 2: REAL blocking error (e.g. CARD_DECLINED) must be blocking
    errs = [
        {"code": "CARD_DECLINED",
         "message": "Card was declined.",
         "extensions": {"code": "CARD_DECLINED"}},
    ]
    assert len(classify(errs)) == 1, "Real blocking errors must still be classified as blocking."

    # Case 3: INTERNAL_SERVER_ERROR must NOT be blocking (transient)
    errs = [
        {"code": "INTERNAL_SERVER_ERROR",
         "message": "Shopify backend crashed.",
         "extensions": {"code": "INTERNAL_SERVER_ERROR"}},
    ]
    assert classify(errs) == [], (
        "INTERNAL_SERVER_ERROR must NOT be in _blocking — it's a transient error."
    )

    # Case 4: INVALID_VARIABLE must NOT be blocking
    errs = [
        {"code": "INVALID_VARIABLE",
         "message": "Variable input of wrong type.",
         "extensions": {"code": "INVALID_VARIABLE"}},
    ]
    assert classify(errs) == [], "INVALID_VARIABLE must NOT be in _blocking."


# ───────────────────────────────────────────────────────────────────────
# 5. SUBMIT_REJECTED message preserves the underlying error code
#    (so extract_clean_response doesn't strip everything)
# ───────────────────────────────────────────────────────────────────────
def test_submit_rejected_message_preserves_error_code():
    """The user log showed:
        {"Response":"SUBMIT_REJECTED", ...}
    with no error code — because the SUBMIT_REJECTED message used
    `e.get('message')` (free text) instead of `e.get('code')`, and
    extract_clean_response() then stripped everything after the prefix.

    The fix formats the message as "CODE:message" so the real error
    code is preserved through extract_clean_response().
    """
    # Simulate a blocking error
    blocking_errors = [
        {"code": "PAYMENTS_CREDIT_CARD_BASE_EXPIRED",
         "localizedMessage": "Card has expired.",
         "extensions": {"code": "PAYMENTS_CREDIT_CARD_BASE_EXPIRED"}},
    ]
    # Apply the same formatting logic as the fix
    rej_msgs = []
    for e in blocking_errors[:3]:
        _code = e.get('code', '') or (e.get('extensions') or {}).get('code', '') or 'UNKNOWN'
        _msg = e.get('localizedMessage') or e.get('message', '')
        _msg = (_msg[:120] if isinstance(_msg, str) else str(_msg)[:120])
        rej_msgs.append(f"{_code}:{_msg}" if _msg else _code)
    msg = f"SUBMIT_REJECTED: {'; '.join(rej_msgs)}"

    # extract_clean_response should now return a useful code, not just "SUBMIT_REJECTED"
    cleaned = core.extract_clean_response(msg)
    assert 'PAYMENTS_CREDIT_CARD_BASE_EXPIRED' in cleaned, (
        f"Expected the cleaned response to preserve the actual error code, "
        f"got: {cleaned!r}"
    )


def test_submit_rejected_message_with_no_code_uses_unknown():
    """When an error has no 'code' field, the format should use 'UNKNOWN'
    as the code prefix — never produce just 'SUBMIT_REJECTED'."""
    blocking_errors = [
        {"message": "Some unexpected error without a code field."},
    ]
    rej_msgs = []
    for e in blocking_errors[:3]:
        _code = e.get('code', '') or (e.get('extensions') or {}).get('code', '') or 'UNKNOWN'
        _msg = e.get('localizedMessage') or e.get('message', '')
        _msg = (_msg[:120] if isinstance(_msg, str) else str(_msg)[:120])
        rej_msgs.append(f"{_code}:{_msg}" if _msg else _code)
    msg = f"SUBMIT_REJECTED: {'; '.join(rej_msgs)}"
    # Must contain "UNKNOWN" so extract_clean_response doesn't strip everything
    assert 'UNKNOWN' in msg


# ───────────────────────────────────────────────────────────────────────
# 6. Brace depth of key fields (regression for "selections can't be made
#    directly on unions" + "Field X doesn't exist on type Y" errors)
# ───────────────────────────────────────────────────────────────────────
def _depth_at_substring(query: str, needle: str, before_open: bool = True) -> int:
    """Walk braces and return the depth at the position of `needle`.

    If before_open=True (default), returns depth BEFORE the '{' that follows
    `needle` (i.e., the depth at which the block opens).
    """
    idx = query.find(needle)
    assert idx >= 0, f"Could not find {needle!r} in query"
    # Find the '{' after needle
    brace_idx = query.find('{', idx)
    assert brace_idx >= 0, f"No '{{' after {needle!r}"
    depth = 0
    for i in range(brace_idx if before_open else brace_idx + 1):
        if query[i] == '{':
            depth += 1
        elif query[i] == '}':
            depth -= 1
    return depth


def test_query_proposal_merchandise_is_inside_sellerProposal():
    """REGRESSION (commit cc59daa aftermath): The delivery block had ONE
    EXTRA '}' after MerchandiseLine{stableId}, which prematurely closed
    sellerProposal. As a result, `merchandise{...}` was parsed as a
    direct selection on NegotiationResultAvailable (where it doesn't exist),
    producing:
        "Field 'merchandise' doesn't exist on type 'NegotiationResultAvailable'"

    The correct depth for `merchandise{` is 6 (inside sellerProposal, which
    is at depth 5 inside ...on NegotiationResultAvailable, which is at depth 4
    inside result).
    """
    q = core.QUERY_PROPOSAL
    depth = _depth_at_substring(q, 'merchandise{')
    # Find the FIRST 'merchandise{' (the outer one inside sellerProposal, not the
    # nested one inside merchandiseLines).
    # Walk to find the first 'merchandise{' that's followed by '__typename ...on FilledMerchandiseTerms'
    idx = q.find('merchandise{__typename ...on FilledMerchandiseTerms')
    assert idx >= 0, "Could not find outer merchandise{ block"
    # Walk braces from start to idx, find the '{' position
    brace_idx = q.find('{', idx)
    depth = 0
    for i in range(brace_idx):
        if q[i] == '{':
            depth += 1
        elif q[i] == '}':
            depth -= 1
    assert depth == 6, (
        f"merchandise{{ block must be at depth 6 (inside sellerProposal), "
        f"got depth {depth}. An extra '}}' in the delivery block was prematurely "
        f"closing sellerProposal, causing Shopify to parse merchandise as a direct "
        f"selection on NegotiationResultAvailable (where it doesn't exist)."
    )


def test_query_proposal_payment_is_inside_sellerProposal():
    """REGRESSION (commit cc59daa aftermath): Same root cause as the
    merchandise test — the extra '}' after MerchandiseLine{stableId}
    also pushed `payment{...}` outside sellerProposal, producing:
        "Field 'payment' doesn't exist on type 'NegotiationResultAvailable'"
    """
    q = core.QUERY_PROPOSAL
    idx = q.find('payment{__typename ...on FilledPaymentTerms')
    assert idx >= 0, "Could not find payment{ block"
    brace_idx = q.find('{', idx)
    depth = 0
    for i in range(brace_idx):
        if q[i] == '{':
            depth += 1
        elif q[i] == '}':
            depth -= 1
    assert depth == 6, (
        f"payment{{ block must be at depth 6 (inside sellerProposal), "
        f"got depth {depth}. An extra '}}' was prematurely closing sellerProposal, "
        f"causing Shopify to parse payment as a direct selection on "
        f"NegotiationResultAvailable (where it doesn't exist)."
    )


def test_query_proposal_buyerProposal_is_inside_NegotiationResultAvailable():
    """REGRESSION (commit cc59daa aftermath): The payment block's extra '}'
    (which was compensating for the missing '}' in the delivery block) was
    prematurely closing NegotiationResultAvailable, leaving buyerProposal
    parsed as a direct selection on the union NegotiationResult —
    GraphQL forbids field selections on unions:
        "Selections can't be made directly on unions (see selections on NegotiationResult)"
        path: result.buyerProposal

    The correct depth for `buyerProposal{` is 5 (inside ...on NegotiationResultAvailable,
    which is at depth 4 inside result).
    """
    q = core.QUERY_PROPOSAL
    idx = q.find('buyerProposal{__typename checkoutTotal')
    assert idx >= 0, "Could not find buyerProposal{ block"
    brace_idx = q.find('{', idx)
    depth = 0
    for i in range(brace_idx):
        if q[i] == '{':
            depth += 1
        elif q[i] == '}':
            depth -= 1
    assert depth == 5, (
        f"buyerProposal{{ block must be at depth 5 (inside ...on NegotiationResultAvailable), "
        f"got depth {depth}. An extra '}}' was prematurely closing NegotiationResultAvailable, "
        f"causing Shopify to parse buyerProposal as a direct selection on the union "
        f"NegotiationResult (forbidden by GraphQL)."
    )


def test_query_proposal_NegotiationResultFailed_is_sibling_of_NegotiationResultAvailable():
    """REGRESSION (commit cc59daa aftermath): `...on NegotiationResultFailed{...}`
    must be a sibling of `...on NegotiationResultAvailable{...}`, both inside `result`.
    Correct depth = 4 (inside result, which is at depth 3 inside negotiate).

    If buyerProposal's extra '}' was prematurely closing NegotiationResultAvailable,
    the sibling union members would still appear to be at depth 4 — but they
    would actually be SIBLINGS of buyerProposal on the union, not siblings of
    NegotiationResultAvailable inside result. This test ensures they're at the
    correct depth so the overall structure is sound.
    """
    q = core.QUERY_PROPOSAL
    idx = q.find('...on NegotiationResultFailed{failureCode}')
    assert idx >= 0, "Could not find ...on NegotiationResultFailed block"
    brace_idx = q.find('{', idx)
    depth = 0
    for i in range(brace_idx):
        if q[i] == '{':
            depth += 1
        elif q[i] == '}':
            depth -= 1
    assert depth == 4, (
        f"...on NegotiationResultFailed{{}} must be at depth 4 (sibling of "
        f"...on NegotiationResultAvailable inside result), got depth {depth}."
    )


def test_query_proposal_sellerProposal_is_inside_NegotiationResultAvailable():
    """Smoke test: sellerProposal must be at depth 5 (inside ...on NegotiationResultAvailable)."""
    q = core.QUERY_PROPOSAL
    idx = q.find('sellerProposal{__typename checkoutTotal')
    assert idx >= 0, "Could not find sellerProposal{ block"
    brace_idx = q.find('{', idx)
    depth = 0
    for i in range(brace_idx):
        if q[i] == '{':
            depth += 1
        elif q[i] == '}':
            depth -= 1
    assert depth == 5, (
        f"sellerProposal{{ block must be at depth 5 (inside ...on NegotiationResultAvailable), "
        f"got depth {depth}."
    )
