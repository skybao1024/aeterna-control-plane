"""Isolated M05 live-test app; run with uvicorn inside the backend container.

Working directory: /app. This fixture is never a production application entry
point. It adds no HTTP routes; only service clocks are replaced.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.config import settings
from app.route import create_app
from app.services.client.aeterna_heartbeat import (
    AeternaHeartbeatService,
    get_aeterna_heartbeat_service,
)
from app.services.client.aeterna_identity import (
    AeternaIdentityService,
    get_aeterna_identity_service,
)
from app.services.client.aeterna_notification import (
    AeternaNotificationService,
    get_aeterna_notification_service,
)
from app.services.client.aeterna_recovery import (
    AeternaRecoveryService,
    get_aeterna_recovery_service,
)
from app.services.client.aeterna_setup import (
    AeternaSetupService,
    get_aeterna_setup_service,
)
from app.services.internal.account_policy_outbox import (
    AccountPolicyOutboxService,
    get_account_policy_outbox_service,
)
from app.services.internal.account_policy_transition import (
    AccountPolicyTransitionService,
    get_account_policy_transition_service,
)
from app.services.internal.aeterna_email_delivery import (
    AeternaEmailDeliveryService,
    get_aeterna_email_delivery_service,
)

CLOCK_PATH = Path("/tmp/aeterna-m05-acceptance-clock.txt")


def require_isolated_fixture() -> None:
    """Fail closed before any database or delivery action."""
    if not (
        settings.ENV == "development"
        and settings.POSTGRES_DB == "m05_smoke"
        and settings.AETERNA_RECOVERY_KEY_PROVIDER == "local-test"
        and not settings.AETERNA_EMAIL_PRODUCTION_ENABLED
        and not settings.AETERNA_RECOVERY_KMS_ENABLED
        and settings.MAIL_HOST == "mailpit"
        and settings.MAIL_PORT == 1025
    ):
        raise RuntimeError("M05 acceptance requires the isolated local fixture")


class Clock:
    def __call__(self):
        value = float(CLOCK_PATH.read_text()) if CLOCK_PATH.exists() else 0
        if not 0 <= value <= 60 * 86400:
            raise RuntimeError("M05 fixture clock is out of bounds")
        return datetime.now(UTC) + timedelta(seconds=value)

    def now(self):
        return self()


require_isolated_fixture()
clock = Clock()
app = create_app()
for dependency, service in (
    (get_aeterna_identity_service, AeternaIdentityService),
    (get_aeterna_setup_service, AeternaSetupService),
    (get_aeterna_notification_service, AeternaNotificationService),
    (get_aeterna_recovery_service, AeternaRecoveryService),
    (get_account_policy_transition_service, AccountPolicyTransitionService),
    (get_account_policy_outbox_service, AccountPolicyOutboxService),
    (get_aeterna_email_delivery_service, AeternaEmailDeliveryService),
):
    app.dependency_overrides[dependency] = lambda service=service: service(clock=clock)
app.dependency_overrides[get_aeterna_heartbeat_service] = (
    lambda: AeternaHeartbeatService(
        clock=clock, policy_service=AccountPolicyTransitionService(clock=clock)
    )
)
