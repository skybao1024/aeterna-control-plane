"""Closed explicit resend schema and cross-language signature evidence."""

import json
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.client.aeterna_recovery_notice import (
    RecoveryNoticeResendRequest,
    RecoveryNoticeResendResponse,
)
from app.services.common.aeterna_security import decode_base64url, verify_signature


def document(**overrides):
    return {
        "protocol_version": 1,
        "signed": {
            "canonicalization": "jcs-rfc8785",
            "domain": "aeterna.recovery-notice.resend.v1",
            "operation": "recovery_notice.resend",
            "protocol_version": 1,
            "signature_version": 1,
            "request_id": str(uuid.uuid4()),
            "account_id": str(uuid.uuid4()),
            "authorizing_device_id": str(uuid.uuid4()),
            "contact_id": str(uuid.uuid4()),
            **overrides,
        },
        "signature": "A" * 86,
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"email": "arbitrary@example.com"},
        {"contact_ids": [str(uuid.uuid4())]},
        {"contact_id": None},
        {"domain": "aeterna.recovery-notice.read.v1"},
        {"operation": "recovery_notice.read"},
        {"message": "arbitrary message"},
    ],
)
def test_resend_never_accepts_address_message_or_read_request_replay(overrides):
    with pytest.raises(ValidationError):
        RecoveryNoticeResendRequest.model_validate(document(**overrides))


def test_resend_public_vectors_have_no_recovery_capability():
    root = Path(__file__).parents[1] / "fixtures" / "aeterna-protocol-v1"
    request = json.loads(
        (root / "fixtures/valid/recovery-notice-resend-request.json").read_text(
            encoding="utf-8"
        )
    )
    RecoveryNoticeResendRequest.model_validate(request)
    response = json.loads(
        (root / "fixtures/valid/recovery-notice-resend-response.json").read_text(
            encoding="utf-8"
        )
    )
    RecoveryNoticeResendResponse.model_validate(response)
    for field in ("email", "claim_link", "claim_token", "srs", "erc", "message"):
        altered = {
            **response,
            "data": {**response["data"], field: "synthetic-forbidden"},
        }
        with pytest.raises(ValidationError):
            RecoveryNoticeResendResponse.model_validate(altered)
    fixture = json.loads(
        (root / "fixtures/signatures/recovery-notice-resend.json").read_text(
            encoding="utf-8"
        )
    )
    public_key = decode_base64url(fixture["public_key"], 32)
    assert verify_signature(public_key, fixture["document"], fixture["signature"])
    for name in ("cross-domain", "modified-contact"):
        altered = json.loads(
            (
                root / f"fixtures/signatures/recovery-notice-resend-{name}.json"
            ).read_text(encoding="utf-8")
        )["envelope"]
        assert not verify_signature(public_key, altered["signed"], altered["signature"])
