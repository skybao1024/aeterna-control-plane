"""Strict test protocol and the exact vendored cross-language package."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.client.aeterna_trigger_test import (
    TriggerTestRequest,
    TriggerTestResponse,
    TriggerTestView,
)
from app.services.common.aeterna_security import decode_base64url, verify_signature

ROOT = Path(__file__).parents[1] / "fixtures" / "aeterna-protocol-v1"
OPERATIONS = (
    "read",
    "create",
    "provision",
    "activate",
    "warning-challenge",
    "warning-verify",
    "activity",
    "stop",
    "retry",
    "recipient-challenge",
    "recipient-verify",
    "release-secret",
    "rotation-confirm",
)


def load(relative):
    return json.loads((ROOT / relative).read_text())


@pytest.mark.parametrize("operation", OPERATIONS)
def test_closed_request_and_signature_match_exact_public_fixture(operation):
    request = load(f"fixtures/valid/trigger-test-{operation}-request.json")
    TriggerTestRequest.model_validate(request)
    fixture = load(f"fixtures/signatures/trigger-test-{operation}.json")
    assert verify_signature(
        decode_base64url(fixture["public_key"], 32),
        request["signed"],
        request["signature"],
    )
    request["signed"]["domain"] = "aeterna.setup.status.v1"
    with pytest.raises(ValidationError):
        TriggerTestRequest.model_validate(request)


@pytest.mark.parametrize("operation", OPERATIONS)
def test_closed_success_response_matches_exact_public_fixture(operation):
    response = load(f"fixtures/valid/trigger-test-{operation}-response.json")
    TriggerTestResponse.model_validate(response)


@pytest.mark.parametrize(
    "path,value",
    [
        ("protocol_version", True),
        ("signed.protocol_version", True),
        ("signed.signature_version", True),
        ("signed.effects_acknowledged", 1),
        ("signed.effects_acknowledged", False),
        ("signed.include_recovery", 1),
    ],
)
def test_boolean_and_integer_types_are_never_coerced(path, value):
    request = load("fixtures/valid/trigger-test-create-request.json")
    target = request
    parts = path.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    with pytest.raises(ValidationError):
        TriggerTestRequest.model_validate(request)


@pytest.mark.parametrize(
    "mutation", ["extra", "date", "duplicate", "version", "email", "recipient"]
)
def test_invalid_safe_views_are_rejected(mutation):
    view = load("fixtures/valid/trigger-test-read-response.json")["data"]["view"]
    if mutation == "extra":
        view["session"]["source_srs"] = "A" * 43
    elif mutation == "date":
        view["session"]["observedAt"] = "2026-02-30T00:00:00Z"
    elif mutation == "duplicate":
        view["session"]["evidence"][0]["key"] = view["session"]["evidence"][1]["key"]
    elif mutation == "version":
        view["session"]["version"] = 0
    elif mutation == "email":
        view["ownerEmail"] = "not a mailbox"
    else:
        view["session"]["recipientId"] = "anything"
    with pytest.raises(ValidationError):
        TriggerTestView.model_validate(view)
