"""Injected notification boundary for account identity challenges and notices."""

from typing import Protocol

from app.services.common.email import EmailService, get_email_service


class AeternaAccountNotifier(Protocol):
    async def send_challenge(
        self, email: str, code: str, expires_in_minutes: int
    ) -> bool: ...

    async def send_security_notice(self, email: str, event: str) -> bool: ...


class EmailAeternaAccountNotifier:
    """SMTP adapter that receives plaintext only for the duration of a send."""

    def __init__(self, email_service: EmailService):
        self.email_service = email_service

    async def send_challenge(
        self, email: str, code: str, expires_in_minutes: int
    ) -> bool:
        return await self.email_service.send_verification_email(
            email=email,
            first_name="Aeterna user",
            verification_code=code,
            expires_in_minutes=expires_in_minutes,
        )

    async def send_security_notice(self, email: str, event: str) -> bool:
        return await self.email_service.send(
            to_emails=email,
            subject="Aeterna account security notice",
            html_content=(
                "<p>A security-sensitive device binding event occurred for your "
                f"Aeterna account.</p><p>Event: {event}</p>"
            ),
        )


def get_aeterna_account_notifier() -> AeternaAccountNotifier:
    return EmailAeternaAccountNotifier(get_email_service())
