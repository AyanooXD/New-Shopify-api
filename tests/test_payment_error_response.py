from core import _extract_payment_error_response, _payment_requires_offsite_action


def test_extract_payment_error_prefers_nested_code_over_generic_top_level():
    error = {
        "__typename": "PaymentFailed",
        "code": "GENERIC_ERROR",
        "message": {"code": "INSUFFICIENT_FUNDS"},
        "messageUntranslated": "Your card was declined.",
    }

    assert _extract_payment_error_response(error) == "INSUFFICIENT_FUNDS"


def test_extract_payment_error_uses_message_when_code_is_generic():
    error = {
        "__typename": "PaymentFailed",
        "code": "GENERIC_ERROR",
        "messageUntranslated": "Card issuer declined the transaction.",
    }

    assert _extract_payment_error_response(error) == "Card issuer declined the transaction."


def test_extract_payment_error_preserves_bare_generic_code():
    error = {"__typename": "PaymentFailed", "code": "GENERIC_ERROR"}

    assert _extract_payment_error_response(error) == "GENERIC_ERROR"


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
