from core import _extract_payment_error_response, _payment_requires_offsite_action


def test_extract_payment_error_prefers_nested_code_over_generic_top_level():
    """Shopify returns GENERIC_ERROR at top-level but specific code in message dict."""
    error = {
        "__typename": "PaymentFailed",
        "code": "GENERIC_ERROR",
        "message": {"code": "INSUFFICIENT_FUNDS"},
        "messageUntranslated": "Your card was declined.",
    }

    assert _extract_payment_error_response(error) == "INSUFFICIENT_FUNDS"


def test_extract_payment_error_uses_message_when_code_is_generic():
    """When code is GENERIC_ERROR but messageUntranslated has human-readable detail."""
    error = {
        "__typename": "PaymentFailed",
        "code": "GENERIC_ERROR",
        "messageUntranslated": "Card issuer declined the transaction.",
    }

    assert _extract_payment_error_response(error) == "Card issuer declined the transaction."


def test_extract_payment_error_preserves_bare_generic_code():
    """When Shopify only returns GENERIC_ERROR with no other detail, return it as-is.

    This is the correct behavior: GENERIC_ERROR is what Shopify actually sent,
    so we should not replace it with a made-up CARD_DECLINED. The old duplicate
    version of _extract_payment_error_response was incorrectly mapping bare
    GENERIC_ERROR → CARD_DECLINED, which hid the real response from the user.
    """
    error = {"__typename": "PaymentFailed", "code": "GENERIC_ERROR"}

    assert _extract_payment_error_response(error) == "GENERIC_ERROR"


def test_extract_payment_error_prefers_declineCode_over_code():
    """declineCode is more specific than code — should be returned first."""
    error = {
        "__typename": "PaymentFailed",
        "code": "GENERIC_ERROR",
        "declineCode": "DO_NOT_HONOR",
    }

    assert _extract_payment_error_response(error) == "DO_NOT_HONOR"


def test_extract_payment_error_specific_code_not_overridden():
    """If code is already specific (not GENERIC_ERROR), return it directly."""
    error = {
        "__typename": "PaymentFailed",
        "code": "INSUFFICIENT_FUNDS",
    }

    assert _extract_payment_error_response(error) == "INSUFFICIENT_FUNDS"


def test_extract_payment_error_nested_message_with_generic_code_and_detail():
    """Nested message dict has GENERIC_ERROR code but also has messageUntranslated."""
    error = {
        "__typename": "PaymentFailed",
        "code": "GENERIC_ERROR",
        "message": {"code": "GENERIC_ERROR"},
        "messageUntranslated": "Card issuer declined the transaction.",
    }

    assert _extract_payment_error_response(error) == "Card issuer declined the transaction."


def test_extract_payment_error_deeply_nested_specific_code():
    """Specific code buried inside paymentError nested container."""
    error = {
        "__typename": "PaymentFailed",
        "code": "GENERIC_ERROR",
        "paymentError": {
            "code": "GENERIC_ERROR",
            "declineCode": "EXPIRED_CARD",
        },
    }

    assert _extract_payment_error_response(error) == "EXPIRED_CARD"


def test_extract_payment_error_non_dict_returns_unknown():
    """If error is not a dict, return UNKNOWN_PAYMENT_ERROR."""
    assert _extract_payment_error_response("some string") == "UNKNOWN_PAYMENT_ERROR"
    assert _extract_payment_error_response(None) == "UNKNOWN_PAYMENT_ERROR"
    assert _extract_payment_error_response(42) == "UNKNOWN_PAYMENT_ERROR"


def test_payment_requires_offsite_action_supports_shopify_field_name():
    assert _payment_requires_offsite_action({"hasOffsitePaymentMethod": True}) is True


def test_extract_clean_response_does_not_drop_detail_after_generic_prefix():
    from core import extract_clean_response

    assert (
        extract_clean_response("GENERIC_ERROR Card issuer declined the transaction.")
        == "GENERIC_ERROR Card issuer declined the transaction."
    )


def test_extract_clean_response_preserves_bare_generic_code():
    from core import extract_clean_response

    assert extract_clean_response("GENERIC_ERROR") == "GENERIC_ERROR"
