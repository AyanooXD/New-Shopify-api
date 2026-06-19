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


def test_extract_payment_error_maps_bare_generic_to_card_declined():
    error = {"__typename": "PaymentFailed", "code": "GENERIC_ERROR"}

    assert _extract_payment_error_response(error) == "CARD_DECLINED"


def test_payment_requires_offsite_action_supports_shopify_field_name():
    assert _payment_requires_offsite_action({"hasOffsitePaymentMethod": True}) is True
