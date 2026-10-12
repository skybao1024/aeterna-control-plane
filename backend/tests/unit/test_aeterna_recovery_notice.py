"""Closed request and fail-closed post-release disclosure boundaries."""

import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.schemas.client.aeterna_recovery_notice import (
    RecoveryNoticeData,
    RecoveryNoticeRequest,
    RecoveryNoticeResponse,
)
from app.services.client.aeterna_recovery_notice import AeternaRecoveryNoticeService
from app.services.common.aeterna_security import decode_base64url, verify_signature


def request_document(contact_ids=(), **overrides):
    return {
        "protocol_version": 1,
        "signed": {
            "canonicalization": "jcs-rfc8785",
            "domain": "aeterna.recovery-notice.read.v1",
            "operation": "recovery_notice.read",
            "protocol_version": 1,
            "signature_version": 1,
            "request_id": str(uuid.uuid4()),
            "account_id": str(uuid.uuid4()),
            "authorizing_device_id": str(uuid.uuid4()),
            "contact_ids": list(contact_ids) if contact_ids is not None else None,
            **overrides,
        },
        "signature": "A" * 86,
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"domain": "aeterna.owner-configuration.read.v1"},
        {"operation": "owner_configuration.read"},
        {"contact_ids": None},
        {"email": "synthetic@example.com"},
        {"authorizing_device_id": "not-a-device"},
    ],
)
def test_notice_request_rejects_cross_domain_null_and_unsigned_details(overrides):
    with pytest.raises(ValidationError):
        RecoveryNoticeRequest.model_validate(request_document(**overrides))


def test_notice_request_bounds_and_deduplicates_known_contact_ids():
    contact_id = str(uuid.uuid4())
    for contact_ids in (
        [contact_id, contact_id],
        [str(uuid.uuid4()) for _ in range(11)],
    ):
        with pytest.raises(ValidationError):
            RecoveryNoticeRequest.model_validate(request_document(contact_ids))


def test_notice_response_cannot_disclose_recipients_before_release():
    data = {
        "account_id": str(uuid.uuid4()),
        "device_id": str(uuid.uuid4()),
        "observed_at": "2030-01-01T00:00:00Z",
        "state": "ACTIVE",
        "epoch": 1,
        "last_activity_at": "2030-01-01T00:00:00Z",
        "released_at": None,
        "recipients": [
            {
                "contact_id": str(uuid.uuid4()),
                "email": "synthetic@example.com",
                "kind": "release",
                "status": "delivered",
            }
        ],
    }
    with pytest.raises(ValidationError):
        RecoveryNoticeData.model_validate(data)
    data.update(state="RELEASED", recipients=[])
    with pytest.raises(ValidationError):
        RecoveryNoticeData.model_validate(data)


def test_notice_public_vectors_match_closed_schema_and_device_signature():
    fixture_root = Path(__file__).parents[1] / "fixtures" / "aeterna-protocol-v1"
    for path in (fixture_root / "fixtures" / "valid").glob(
        "recovery-notice-read-response*.json"
    ):
        RecoveryNoticeResponse.model_validate(
            json.loads(path.read_text(encoding="utf-8"))
        )
    fixture = json.loads(
        (
            fixture_root / "fixtures" / "signatures" / "recovery-notice-read.json"
        ).read_text(encoding="utf-8")
    )
    document = json.loads(
        (
            fixture_root / "fixtures" / "valid" / "recovery-notice-read-request.json"
        ).read_text(encoding="utf-8")
    )
    RecoveryNoticeRequest.model_validate(document)
    public_key = decode_base64url(fixture["public_key"], 32)
    assert verify_signature(public_key, fixture["document"], fixture["signature"])
    for name in ("cross-domain", "modified-contacts"):
        altered = json.loads(
            (
                fixture_root
                / "fixtures"
                / "signatures"
                / f"recovery-notice-read-{name}.json"
            ).read_text(encoding="utf-8")
        )["envelope"]
        assert not verify_signature(public_key, altered["signed"], altered["signature"])


@pytest.mark.parametrize(
    "statuses, expected",
    [
        (["delivered", "failed"], "delivered"),
        (["provider_accepted", "queued"], "submitted"),
        (["queued", "retry_pending", "sending"], "pending"),
        (["failed", "bounced", "complained", "cancelled"], "failed"),
        (["ambiguous"], "unknown"),
    ],
)
def test_mail_evidence_never_claims_readership(statuses, expected):
    service = AeternaRecoveryNoticeService()
    assert (
        service._delivery_status(
            [SimpleNamespace(status=status) for status in statuses]
        )
        == expected
    )
