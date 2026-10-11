"""Invitation clarity, localization, expiry, and fixed disclosure boundaries."""

from datetime import UTC, datetime

import pytest

from app.services.common.aeterna_contact_email_copy import (
    contact_email_copy,
    render_contact_invitation,
)


@pytest.mark.parametrize("locale", ["en", "zh-CN"])
def test_invitation_identifies_inviter_and_explains_role_without_private_data(locale):
    action_url = (
        f"https://claim.example.com/contact-invitation?locale={locale}#token=synthetic"
    )
    content = render_contact_invitation(
        locale=locale,
        owner_email="owner@example.com",
        action_url=action_url,
        expires_at=datetime(2026, 10, 18, 9, 12, tzinfo=UTC),
    )
    copy = contact_email_copy(locale)
    assert "owner@example.com" in content.subject
    assert "owner@example.com" in content.text_body
    assert copy.about_text in content.text_body
    assert copy.role_text in content.text_body
    assert copy.choice_text in content.text_body
    assert copy.privacy_text in content.text_body
    assert "2026-10-18 09:12" in content.text_body
    assert action_url in content.text_body
    assert f'lang="{locale}"' in content.html_body
    assert content.html_body.count("<a ") == 1
    assert "claim.example.com" in content.html_body
    assert "<img" not in content.html_body
    assert "<script" not in content.html_body
    assert "/recovery-claim" not in content.text_body
    assert "SRS" not in content.text_body
    assert "ERC" not in content.text_body
    if locale == "en":
        assert "invites you to be a recovery contact" in content.subject
        assert "7 days after creation" in content.text_body
        assert "immediate access" in content.text_body
        assert "user's own device" in content.text_body
        assert "receive recovery notifications" in content.text_body
    else:
        assert "邀请你成为恢复联系人" in content.subject
        assert "有效期为 7 天" in content.text_body
        assert "不会立即授予" in content.text_body
        assert "用户自己设备" in content.text_body
        assert "接收恢复通知" in content.text_body


def test_invitation_html_escapes_inviter_and_action_url():
    content = render_contact_invitation(
        locale="en",
        owner_email='<synthetic>&"@example.com',
        action_url='https://claim.example.com/contact-invitation?locale=en&x="<synthetic>"#token=test',
        expires_at=datetime(2026, 10, 18, tzinfo=UTC),
    )
    assert "<synthetic>" not in content.html_body
    assert "&lt;synthetic&gt;&amp;&quot;@example.com" in content.html_body
    assert "&amp;x=&quot;&lt;synthetic&gt;&quot;#token=test" in content.html_body


def test_copy_rejects_unrecognized_persisted_locale():
    with pytest.raises(ValueError, match="Unsupported contact notification locale"):
        contact_email_copy("../../unexpected")
