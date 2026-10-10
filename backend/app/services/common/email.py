"""Application email rendering through the shared, constrained provider boundary."""

import logging
import uuid
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.services.common.aeterna_email_adapter import (
    AeternaEmailAdapter,
    AeternaEmailEnvelope,
    EmailDeliveryFailure,
    get_aeterna_email_adapter,
)

logger = logging.getLogger("email_service")

EMAIL_APP_NAME = "Aeterna Relay"

TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "resources" / "emails"
jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


class _EmailTextRenderer(HTMLParser):
    """Extract readable copy and links from existing application HTML templates."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_depth = 0
        self.link_targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"head", "style", "script"}:
            self.hidden_depth += 1
        if self.hidden_depth:
            return
        if tag in {"p", "div", "br", "li", "h1", "h2", "h3", "tr", "hr"}:
            self.parts.append("\n")
        if tag == "a":
            self.link_targets.append(dict(attrs).get("href") or "")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"head", "style", "script"}:
            self.hidden_depth = max(0, self.hidden_depth - 1)
            return
        if self.hidden_depth:
            return
        if tag == "a" and self.link_targets:
            target = self.link_targets.pop()
            if target:
                self.parts.append(f" ({target})")
        if tag in {"p", "div", "li", "h1", "h2", "h3", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden_depth:
            self.parts.append(data)

    def render(self, html_content: str) -> str:
        self.feed(html_content)
        self.close()
        lines = (" ".join(line.split()) for line in "".join(self.parts).splitlines())
        return "\n".join(line for line in lines if line)


class EmailService:
    """Render account email and submit exactly once to the shared adapter."""

    def __init__(self, adapter: AeternaEmailAdapter | None = None):
        self.adapter = adapter if adapter is not None else get_aeterna_email_adapter()

    async def send(
        self,
        to_emails: str | list[str],
        subject: str,
        html_content: str,
        from_email: str | None = None,
        from_name: str | None = None,
    ) -> bool:
        """Submit one recipient without sender overrides or fallback delivery."""

        if not html_content or not html_content.strip():
            logger.error("Email HTML content is empty, sending failed")
            return False
        if from_email is not None or from_name is not None:
            raise EmailDeliveryFailure(
                "email-sender-override-forbidden", retryable=False
            )
        recipients = [to_emails] if isinstance(to_emails, str) else to_emails
        if len(recipients) != 1:
            raise EmailDeliveryFailure("email-recipient-count-invalid", retryable=False)
        envelope = AeternaEmailEnvelope(
            recipient=recipients[0],
            subject=subject,
            text_body=_EmailTextRenderer().render(html_content),
            html_body=html_content,
            track_in_outbox=False,
        )
        try:
            # The random correlation key contains no address, code, or body. It is
            # not a provider idempotency token; this service never replays a send.
            await self.adapter.send(envelope, str(uuid.uuid4()))
        except EmailDeliveryFailure:
            logger.error("Email provider delivery failed")
            raise
        except Exception:
            logger.error("Email provider outcome is ambiguous")
            raise EmailDeliveryFailure(
                "provider-failure-ambiguous", retryable=False, ambiguous=True
            ) from None
        logger.info("Email accepted by provider")
        return True

    async def send_with_template(
        self,
        to_emails: str | list[str],
        template_name: str,
        template_params: dict[str, Any],
        subject: str,
        from_email: str | None = None,
        from_name: str | None = None,
    ) -> bool:
        """Render an existing server-owned template before provider submission."""

        try:
            template = jinja_env.get_template(template_name)
            html_content = template.render(**template_params)
            return await self.send(
                to_emails=to_emails,
                subject=subject,
                html_content=html_content,
                from_email=from_email,
                from_name=from_name,
            )
        except Exception:
            logger.error("Email template delivery failed")
            raise

    async def send_verification_email(
        self,
        email: str,
        first_name: str,
        verification_code: str,
        expires_in_minutes: int = 5,
    ) -> bool:
        """Send the existing verification copy with its server-side lifetime."""

        return await self.send_with_template(
            to_emails=email,
            template_name="auth/verification.html",
            template_params={
                "app_name": EMAIL_APP_NAME,
                "first_name": first_name,
                "verification_code": verification_code,
                "expires_in_minutes": expires_in_minutes,
            },
            subject=f"Verify your {EMAIL_APP_NAME} email address",
        )


def get_email_service() -> EmailService:
    """Assemble account mail with the same adapter as durable Outbox delivery."""

    return EmailService(adapter=get_aeterna_email_adapter())
