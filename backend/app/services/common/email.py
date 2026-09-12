import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings

# Configure logging
logger = logging.getLogger("email_service")

# Configure FastMail connection
mail_conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM_ADDRESS,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_HOST,
    MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
    MAIL_STARTTLS=(
        settings.MAIL_ENCRYPTION.lower() == "tls"
        if hasattr(settings, "MAIL_ENCRYPTION")
        else False
    ),
    MAIL_SSL_TLS=(
        settings.MAIL_ENCRYPTION.lower() == "ssl"
        if hasattr(settings, "MAIL_ENCRYPTION")
        else False
    ),
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)

# Initialize FastMail
fastmail = FastMail(mail_conf)

# Set template directory
TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "resources" / "emails"
if not TEMPLATES_DIR.exists():
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

# Initialize Jinja2 environment
jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


class EmailService:
    """Email service class providing email sending functionality"""

    def __init__(self, thread_pool_service=None):
        """Initialize EmailService with dependencies"""
        from app.services.common.thread_pool import get_thread_pool_service

        self.thread_pool_service = thread_pool_service or get_thread_pool_service()

    def _send_sync(
        self,
        to_emails: Union[str, List[str]],
        subject: str,
        html_content: str,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> bool:
        """
        Send email using synchronous method
        """
        if isinstance(to_emails, str):
            to_emails = [to_emails]

        message = MIMEMultipart("alternative")
        message["Subject"] = subject

        from_email = from_email or settings.MAIL_FROM_ADDRESS
        from_name = from_name or settings.MAIL_FROM_NAME

        message["From"] = f"{from_name} <{from_email}>"
        message["To"] = ", ".join(to_emails)

        part = MIMEText(html_content, "html")
        message.attach(part)

        try:
            with smtplib.SMTP(settings.MAIL_HOST, settings.MAIL_PORT) as server:
                # If TLS encryption is needed
                if (
                    hasattr(settings, "MAIL_ENCRYPTION")
                    and settings.MAIL_ENCRYPTION.lower() == "tls"
                ):
                    server.starttls()

                # If login is required
                server.login(settings.MAIL_USERNAME, settings.MAIL_PASSWORD)

                server.sendmail(from_email, to_emails, message.as_string())

            logger.info(f"Email sent successfully to {to_emails}")
            return True
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            raise

    async def send(
        self,
        to_emails: Union[str, List[str]],
        subject: str,
        html_content: str,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> bool:
        """
        Send email asynchronously
        """
        if isinstance(to_emails, str):
            to_emails = [to_emails]

        try:
            # Ensure html_content is not empty
            if not html_content or len(html_content.strip()) == 0:
                logger.error("Email HTML content is empty, sending failed")
                return False

            # Send email using FastMail (asynchronous method)
            message = MessageSchema(
                subject=subject,
                recipients=to_emails,
                body=html_content,  # Try using body parameter
                subtype="html",
            )

            await fastmail.send_message(message)
            logger.info(f"Email sent asynchronously to {to_emails}")
            return True
        except Exception as e:
            logger.warning(f"FastMail sending failed, trying synchronous method: {e}")
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self.thread_pool_service.get_executor(),
                self._send_sync,
                to_emails,
                subject,
                html_content,
                from_email,
                from_name,
            )

    async def send_with_template(
        self,
        to_emails: Union[str, List[str]],
        template_name: str,
        template_params: Dict[str, Any],
        subject: str,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> bool:
        """
        Send email using template

        Parameters:
        -----------
        to_emails: Recipient list or single recipient
        template_name: Template name (e.g., 'auth/verification.html')
        template_params: Template parameters
        subject: Email subject
        from_email: Sender email, defaults to configured value
        from_name: Sender name, defaults to configured value
        """
        try:
            # Add default parameters
            params = {
                "img_host": (
                    settings.AWS_ENDPOINT if hasattr(settings, "AWS_ENDPOINT") else ""
                ),
                **template_params,
            }

            # Render template
            template = jinja_env.get_template(template_name)
            html_content = template.render(**params)
            # Send email
            return await self.send(
                to_emails=to_emails,
                subject=subject,
                html_content=html_content,
                from_email=from_email,
                from_name=from_name,
            )
        except Exception as e:
            logger.error(f"Error sending email with template: {e}")
            raise

    # Dedicated methods for convenience
    async def send_verification_email(
        self, email: str, first_name: str, verification_code: str
    ) -> bool:
        """
        Send account verification email
        """
        return await self.send_with_template(
            to_emails=email,
            template_name="auth/verification.html",
            template_params={"first_name": first_name, "code": verification_code},
            subject="Bienvenue chez Moriarty - Activez votre compte",
        )


def get_email_service() -> EmailService:
    """Get EmailService instance (dependency injection)"""
    return EmailService()
