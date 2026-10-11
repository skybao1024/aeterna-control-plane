"""Contact messages retain their saved locale after invitation acceptance."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.aeterna_identity import AeternaAccount
from app.models.aeterna_notification import AeternaContact, AeternaEmailOutboxEvent
from app.services.common.aeterna_email_adapter import EmailDeliveryFailure
from app.services.common.aeterna_security import AeternaIdentityKeys, encrypt_email
from app.services.internal.aeterna_email_delivery import AeternaEmailDeliveryService


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_type,subject_fragment",
    [
        ("contact-test", "邮件送达测试"),
        ("recovery-claim-link", "恢复访问已可用"),
        ("recovery-otp", "恢复验证码"),
        ("recovery-claimed-contact", "恢复安全通知"),
    ],
)
async def test_accepted_contact_messages_use_saved_chinese_locale(
    event_type, subject_fragment
):
    now = datetime(2026, 10, 11, tzinfo=UTC)
    keys = AeternaIdentityKeys(
        pii_key=bytes([0x11]) * 32,
        lookup_key=bytes([0x22]) * 32,
        otp_key=bytes([0x33]) * 32,
    )
    account_id, contact_id, reference_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    ciphertext, nonce, version = encrypt_email(
        keys, "synthetic@example.com", "contact", contact_id
    )
    contact = AeternaContact(
        id=contact_id,
        account_id=account_id,
        notification_locale="zh-CN",
        consent_status="ACCEPTED",
        verified_at=now,
        email_ciphertext=ciphertext,
        email_nonce=nonce,
        email_key_version=version,
    )
    event = AeternaEmailOutboxEvent(
        id=uuid.uuid4(),
        account_id=account_id,
        contact_id=contact_id,
        recipient_kind="contact",
        event_type=event_type,
        recovery_link_id=reference_id if event_type == "recovery-claim-link" else None,
        recovery_challenge_id=reference_id if event_type == "recovery-otp" else None,
    )
    reference = SimpleNamespace(
        id=reference_id,
        token_key_version=1,
        otp_key_version=1,
        status="active",
        expires_at=now + timedelta(minutes=10),
    )
    db = AsyncMock()
    db.get.side_effect = [None, reference]
    delivery = AeternaEmailDeliveryService(key_provider=lambda: keys)
    delivery._recovery_entry_available = AsyncMock(return_value=True)
    envelope = await delivery._render(
        db, keys, AeternaAccount(id=account_id), contact, event, now
    )
    assert subject_fragment in envelope.subject
    assert "This is a delivery test" not in envelope.text_body
    assert "Use this one-time code" not in envelope.text_body
    if event_type == "recovery-otp":
        assert "10 分钟" in envelope.text_body


@pytest.mark.asyncio
async def test_corrupt_contact_locale_fails_closed_before_rendering():
    contact = AeternaContact(id=uuid.uuid4(), notification_locale="unknown")
    event = AeternaEmailOutboxEvent(recipient_kind="contact", event_type="contact-test")
    db = AsyncMock()
    db.get.return_value = None
    delivery = AeternaEmailDeliveryService()
    with pytest.raises(EmailDeliveryFailure) as invalid:
        await delivery._render(
            db,
            None,
            AeternaAccount(id=uuid.uuid4()),
            contact,
            event,
            datetime(2026, 10, 11, tzinfo=UTC),
        )
    assert invalid.value.code == "contact-locale-invalid"
