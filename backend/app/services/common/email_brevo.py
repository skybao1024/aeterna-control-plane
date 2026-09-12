import asyncio
from typing import Any, Dict, List, Optional

import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

from app.core.config import settings
from app.services.common.thread_pool import ThreadPoolService


def _send_verification_sync(email: str, verification_code: str):
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = settings.BREVO_API_KEY
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    subject = "Verify Your Email"
    html_content = f"""
    <html>
        <body>
            <h2>Welcome to register!</h2>
            <p>Your verification code is: <strong>{verification_code}</strong></p>
            <p>This verification code will expire in 30 minutes.</p>
        </body>
    </html>
    """
    sender = {
        "name": settings.BREVO_EMAIL_FROM_NAME,
        "email": settings.BREVO_EMAIL_FROM,
    }
    to = [{"email": email}]

    try:
        return api_instance.send_transac_email(
            {
                "sender": sender,
                "to": to,
                "subject": subject,
                "htmlContent": html_content,
            }
        )
    except ApiException as e:
        print(f"Exception when calling SMTPApi->send_transac_email: {e}")
        raise


async def send_verification_email(
    email: str, verification_code: str, thread_pool_service: ThreadPoolService = None
):
    """Send verification email using thread pool service"""
    if thread_pool_service is None:
        thread_pool_service = ThreadPoolService()

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        thread_pool_service.get_executor(),
        _send_verification_sync,
        email,
        verification_code,
    )


async def send_template_email(
    to_emails: List[str],
    template_id: int,
    template_params: Optional[Dict[str, Any]] = None,
    subject: Optional[str] = None,
    sender: Optional[Dict[str, str]] = None,
    thread_pool_service: ThreadPoolService = None,
):
    """Send template email using thread pool service"""
    if thread_pool_service is None:
        thread_pool_service = ThreadPoolService()

    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = settings.BREVO_API_KEY
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    if sender is None:
        sender = {"name": settings.EMAIL_FROM_NAME, "email": settings.EMAIL_FROM}
    to = [{"email": email} for email in to_emails]

    email_params = {
        "sender": sender,
        "to": to,
        "templateId": template_id,
    }
    if template_params:
        email_params["params"] = template_params
    if subject:
        email_params["subject"] = subject

    def _send_template_sync():
        try:
            return api_instance.send_transac_email(email_params)
        except ApiException as e:
            print(f"Exception when calling SMTPApi->send_transac_email: {e}")
            raise

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        thread_pool_service.get_executor(), _send_template_sync
    )
