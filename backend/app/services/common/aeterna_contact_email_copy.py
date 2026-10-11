"""Fixed contact email resources and escaped transactional invitation layout."""

import html
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from app.core.aeterna_locale import NotificationLocale, validate_notification_locale


class ContactEmailCopy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    invitation_subject: str
    invitation_heading: str
    inviter_label: str
    invitation_intro: str
    about_heading: str
    about_text: str
    role_heading: str
    role_text: str
    choice_heading: str
    choice_text: str
    privacy_text: str
    invitation_cta: str
    expiry_text: str
    security_text: str
    fallback_label: str
    origin_label: str
    footer_text: str
    test_subject: str
    test_text: str
    claim_subject: str
    claim_text: str
    otp_subject: str
    otp_text: str
    security_subject: str
    security_notice_text: str
    note_label: str


@lru_cache(maxsize=2)
def contact_email_copy(locale: NotificationLocale) -> ContactEmailCopy:
    locale = validate_notification_locale(locale)
    resource = Path(__file__).parent / "locales" / f"contact_emails.{locale}.json"
    return ContactEmailCopy.model_validate_json(resource.read_text(encoding="utf-8"))


@dataclass(frozen=True, slots=True)
class InvitationEmailContent:
    subject: str
    text_body: str
    html_body: str


def render_contact_invitation(
    *,
    locale: NotificationLocale,
    owner_email: str,
    action_url: str,
    expires_at: datetime,
) -> InvitationEmailContent:
    """Expose only fixed consent copy, the inviter, and the invitation bearer."""

    copy = contact_email_copy(locale)
    values = {
        "owner_email": owner_email,
        "expires_at": expires_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M"),
    }
    intro = copy.invitation_intro.format(**values)
    expiry = copy.expiry_text.format(**values)
    security = copy.security_text.format(**values)
    footer = copy.footer_text.format(**values)
    origin = urlsplit(action_url).netloc
    text_body = "\n\n".join(
        (
            copy.invitation_heading,
            f"{copy.inviter_label}: {owner_email}",
            intro,
            f"{copy.about_heading}\n{copy.about_text}",
            f"{copy.role_heading}\n{copy.role_text}",
            f"{copy.choice_heading}\n{copy.choice_text}",
            copy.privacy_text,
            f"{copy.invitation_cta}:\n{action_url}",
            f"{copy.origin_label}: {origin}",
            expiry,
            security,
            footer,
        )
    )
    escape = html.escape
    sections = "".join(
        f'<h2 style="font-size:17px;margin:24px 0 8px">{escape(heading)}</h2>'
        f'<p style="margin:0 0 16px">{escape(body)}</p>'
        for heading, body in (
            (copy.about_heading, copy.about_text),
            (copy.role_heading, copy.role_text),
            (copy.choice_heading, copy.choice_text),
        )
    )
    html_body = (
        f'<!doctype html><html lang="{escape(locale)}"><head>'
        '<meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width, initial-scale=1"></head>'
        '<body style="margin:0;background:#f5f7fb;color:#17243b;'
        'font-family:Arial,sans-serif;font-size:15px;line-height:1.65">'
        '<main style="max-width:600px;margin:24px auto;padding:28px;'
        'background:#ffffff;border:1px solid #e1e6ef;border-radius:12px;overflow-wrap:anywhere">'
        '<p style="margin:0 0 12px;color:#53627a;font-weight:bold">Aeterna Relay</p>'
        f'<h1 style="font-size:25px;line-height:1.3;margin:0 0 20px">'
        f"{escape(copy.invitation_heading)}</h1>"
        f'<p style="padding:12px 16px;background:#f0f4fa;border-radius:8px;'
        f'overflow-wrap:anywhere"><strong>{escape(copy.inviter_label)}:</strong><br>'
        f"{escape(owner_email)}</p><p>{escape(intro)}</p>{sections}"
        f'<p style="color:#53627a">{escape(copy.privacy_text)}</p>'
        '<p style="margin:28px 0 12px">'
        f'<a href="{escape(action_url, quote=True)}" style="display:inline-block;'
        "background:#285cce;color:#ffffff;padding:12px 20px;border-radius:7px;"
        f'text-decoration:none;font-weight:bold">{escape(copy.invitation_cta)}</a></p>'
        f'<p style="font-size:13px;color:#53627a">{escape(copy.origin_label)}: '
        f"{escape(origin)}</p><p>{escape(expiry)}</p><p>{escape(security)}</p>"
        '<div style="border-top:1px solid #e1e6ef;margin-top:24px;padding-top:16px;'
        'font-size:13px;color:#53627a">'
        f"<p>{escape(copy.fallback_label)}</p>"
        f'<p style="overflow-wrap:anywhere;word-break:break-all">{escape(action_url)}</p>'
        f"<p>{escape(footer)}</p></div></main></body></html>"
    )
    return InvitationEmailContent(
        copy.invitation_subject.format(**values), text_body, html_body
    )
