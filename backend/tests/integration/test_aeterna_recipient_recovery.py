"""Isolated PostgreSQL evidence for recipient custody and durable Vault rotation."""

import asyncio
import importlib
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import base as database
from app.db.models import Base
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.models.account_policy import AccountPolicy
from app.models.aeterna_identity import (
    AeternaAccount,
    AeternaAccountChallenge,
    AeternaDevice,
)
from app.models.aeterna_management import AeternaManagementAlias
from app.models.aeterna_notification import AeternaContact, AeternaEmailOutboxEvent
from app.models.aeterna_recipient_recovery import AeternaRecipientRecoveryRotation
from app.models.aeterna_recovery import (
    AeternaRecoveryClaimLink,
    AeternaRecoveryGrant,
    AeternaRecoveryRecord,
)
from app.schemas.client.aeterna_recipient_recovery import (
    RecipientRecoveryAbandonRequest,
    RecipientRecoveryConfirmRequest,
    RecipientRecoveryPrepareRequest,
    RecipientRecoveryProvisionRequest,
    RecipientRecoverySecretRequest,
    RecoveryCustodyChallengeRequest,
    RecoveryCustodyVerifyRequest,
)
from app.schemas.client.aeterna_recovery import (
    RecoveryClaimStartRequest,
    RecoveryClaimVerifyRequest,
    RecoveryRecordProvisionRequest,
    RecoveryRotationProvisionRequest,
)
from app.services.client.aeterna_recipient_recovery import (
    AeternaRecipientRecoveryService,
)
from app.services.client.aeterna_recovery import AeternaRecoveryService
from app.services.common.aeterna_security import (
    derive_recovery_link_token,
    derive_recovery_otp,
    email_lookup,
    encode_base64url,
    encrypt_email,
)
from app.services.internal.aeterna_email_delivery import AeternaEmailDeliveryService
from tests.integration.test_aeterna_recovery import (
    CapturingEmailAdapter,
    FailingDecryptProvider,
    MutableClock,
    create_fixture,
    provision_and_confirm,
    recovery_provider,
    release_policy,
    signed_document,
    synthetic_keys,
)

pytestmark = pytest.mark.asyncio(loop_scope="session")
SOURCE_DIGEST = encode_base64url(bytes([0x66]) * 32)
TARGET_DIGEST = encode_base64url(bytes([0x77]) * 32)
COMMITMENT = encode_base64url(bytes([0x55]) * 32)


@pytest_asyncio.fixture(autouse=True, scope="module", loop_scope="session")
async def isolated_recipient_database():
    """Isolate each module, including when registered as a shared pytest plugin."""
    schema = f"recipient_test_{uuid.uuid4().hex}"
    previous_engine = database.engine
    previous_sessions = database.AsyncSessionLocal
    admin = create_async_engine(database.SQLALCHEMY_DATABASE_URL, echo=False)
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        database.SQLALCHEMY_DATABASE_URL,
        echo=False,
        connect_args={"server_settings": {"search_path": schema}},
    )
    for path in (Path(__file__).parents[2] / "app" / "models").glob("*.py"):
        importlib.import_module(f"app.models.{path.stem}")
    migration = importlib.import_module(
        "migrations.versions.f4ca2910b803_add_recipient_vault_rotation"
    )

    def migrate(connection):
        Base.metadata.create_all(
            connection,
            tables=[
                table
                for table in Base.metadata.sorted_tables
                if table.name
                not in {
                    "aeterna_recipient_recovery_rotations",
                    "aeterna_management_aliases",
                    "aeterna_custody_challenges",
                }
            ],
        )
        connection.execute(
            text("ALTER TABLE aeterna_recovery_otp_challenges DROP COLUMN scope")
        )
        connection.execute(
            text(
                "ALTER TABLE aeterna_recovery_claim_tokens DROP CONSTRAINT ck_aeterna_recovery_claim_tokens_scope"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE aeterna_recovery_claim_tokens ADD CONSTRAINT ck_aeterna_recovery_claim_tokens_scope CHECK (scope = 'recovery.srs.read')"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE aeterna_recovery_audit DROP CONSTRAINT ck_aeterna_recovery_audit_event_type"
            )
        )
        connection.execute(
            text(
                "ALTER TABLE aeterna_recovery_audit ADD CONSTRAINT ck_aeterna_recovery_audit_event_type "
                f"CHECK (event_type IN ({migration.OLD_AUDIT_EVENTS}))"
            )
        )
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            migration.downgrade()
            migration.upgrade()
            management_migration = importlib.import_module(
                "migrations.versions.3acbf214b906_add_management_aliases_and_custody_challenges"
            )
            management_migration.upgrade()
            management_migration.downgrade()
            management_migration.upgrade()

    try:
        async with engine.begin() as connection:
            await connection.run_sync(migrate)
        database.engine = engine
        database.AsyncSessionLocal = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        yield
    finally:
        database.engine = previous_engine
        database.AsyncSessionLocal = previous_sessions
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def setup(*, released=True):
    now = datetime(2030, 6, 1, tzinfo=UTC)
    clock = MutableClock(now)
    provider = recovery_provider()
    recovery = AeternaRecoveryService(
        provision_provider=lambda: provider,
        claim_provider=lambda: provider,
        identity_key_provider=synthetic_keys,
        clock=clock,
    )
    service = AeternaRecipientRecoveryService(recovery_service=recovery)
    fixture = await create_fixture(now)
    await provision_and_confirm(recovery, fixture)
    if released:
        await release_policy(fixture.account_id, now)
        async with database.get_session_local()() as db:
            await recovery.materialize_released_account(db, fixture.account_id)
    return recovery, service, fixture, clock


async def claim(recovery, fixture):
    sessions = database.get_session_local()
    async with sessions() as db:
        link = await db.scalar(
            select(AeternaRecoveryClaimLink)
            .join(AeternaRecoveryGrant)
            .where(
                AeternaRecoveryGrant.contact_id == fixture.contact_id,
                AeternaRecoveryGrant.recovery_id == fixture.recovery_id,
            )
            .order_by(AeternaRecoveryClaimLink.created_at.desc())
        )
    token = derive_recovery_link_token(
        synthetic_keys(), link.id, link.token_key_version
    )
    async with sessions() as db:
        data = await recovery.start_recipient_claim(
            db,
            RecoveryClaimStartRequest(
                protocol_version=1, request_id=str(uuid.uuid4()), claim_link_token=token
            ),
        )
    # An expired email link queues a replacement; use its synthetic fragment next.
    async with sessions() as db:
        replacement = await db.scalar(
            select(AeternaRecoveryClaimLink)
            .join(AeternaRecoveryGrant)
            .where(
                AeternaRecoveryGrant.contact_id == fixture.contact_id,
                AeternaRecoveryGrant.recovery_id == fixture.recovery_id,
            )
            .order_by(AeternaRecoveryClaimLink.created_at.desc())
        )
    if replacement.id != link.id:
        token = derive_recovery_link_token(
            synthetic_keys(), replacement.id, replacement.token_key_version
        )
        async with sessions() as db:
            data = await recovery.start_recipient_claim(
                db,
                RecoveryClaimStartRequest(
                    protocol_version=1,
                    request_id=str(uuid.uuid4()),
                    claim_link_token=token,
                ),
            )
    async with sessions() as db:
        return await recovery.verify_recipient_claim(
            db,
            RecoveryClaimVerifyRequest(
                protocol_version=1,
                request_id=str(uuid.uuid4()),
                challenge_id=data["challenge_id"],
                claim_link_token=token,
                code=derive_recovery_otp(
                    synthetic_keys(), uuid.UUID(data["challenge_id"])
                ),
            ),
        )


def recipient_document(fixture, authorization, rotation_id, operation, **members):
    document = signed_document(
        fixture,
        domain=f"aeterna.recipient-recovery.{operation}.v1",
        operation=f"recipient_recovery.{operation}",
        members={
            "wrapper_digest": SOURCE_DIGEST,
            "rotation_id": str(rotation_id),
            **members,
        },
    )
    document["claim_token"] = authorization["claim_token"]
    return document


async def call(service, operation, model, document):
    async with database.get_session_local()() as db:
        try:
            return await getattr(service, operation)(
                db, model.model_validate(document), document
            )
        except AeternaProtocolException:
            await db.rollback()
            raise


async def prepare_rotation(recovery, service, fixture, authorization=None):
    authorization = authorization or await claim(recovery, fixture)
    rotation_id = uuid.uuid4()
    secret = recipient_document(fixture, authorization, rotation_id, "secret")
    await call(service, "release_secret", RecipientRecoverySecretRequest, secret)
    target = {"target_recovery_id": str(uuid.uuid4()), "erc_commitment": COMMITMENT}
    provision = recipient_document(
        fixture, authorization, rotation_id, "provision", **target
    )
    provisioned = await call(
        service, "provision", RecipientRecoveryProvisionRequest, provision
    )
    prepared = recipient_document(
        fixture,
        authorization,
        rotation_id,
        "prepare",
        **target,
        target_wrapper_digest=TARGET_DIGEST,
    )
    await call(service, "prepare", RecipientRecoveryPrepareRequest, prepared)
    confirm = recipient_document(
        fixture,
        authorization,
        rotation_id,
        "confirm",
        **target,
        target_wrapper_digest=TARGET_DIGEST,
    )
    return rotation_id, authorization, provision, provisioned, prepared, confirm


async def test_same_vault_confirm_replay_is_atomic_and_preserves_owner_account():
    recovery, service, fixture, clock = await setup()
    shared_commitment = bytes([0x44]) * 32
    other = replace(fixture, vault_id=uuid.uuid4(), recovery_id=uuid.uuid4())
    # A second record shares the account commitment but represents a distinct Vault.
    async with database.get_session_local().begin() as db:
        record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        account = await db.get(AeternaAccount, fixture.account_id)
        record.erc_commitment = shared_commitment
        account.erc_commitment = shared_commitment
        account.erc_commitment_epoch = 1
        account.erc_commitment_generation = 1
        values = {
            column.name: getattr(record, column.name)
            for column in record.__table__.columns
        }
        values.update(
            id=other.recovery_id,
            vault_id=other.vault_id,
            provision_request_id=uuid.uuid4(),
        )
        db.add(AeternaRecoveryRecord(**values))
    async with database.get_session_local()() as db:
        await recovery.materialize_released_account(db, fixture.account_id)
    rotation_id, authorization, _, _, _, confirm = await prepare_rotation(
        recovery, service, fixture
    )
    outcomes = await asyncio.gather(
        *[
            call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
            for _ in range(2)
        ]
    )
    assert all(
        outcome["state"] == "complete" and not outcome["protection_active"]
        for outcome in outcomes
    )
    assert outcomes[0] == outcomes[1]
    async with database.get_session_local()() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        source = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        untouched = await db.get(AeternaRecoveryRecord, other.recovery_id)
        policy = await db.scalar(
            select(AccountPolicy).where(AccountPolicy.account_id == fixture.account_id)
        )
        grants = list(
            (
                await db.scalars(
                    select(AeternaRecoveryGrant).where(
                        AeternaRecoveryGrant.account_id == fixture.account_id
                    )
                )
            ).all()
        )
        emails = list(
            (
                await db.scalars(
                    select(AeternaEmailOutboxEvent.event_type).where(
                        AeternaEmailOutboxEvent.account_id == fixture.account_id
                    )
                )
            ).all()
        )
    assert account.erc_commitment == shared_commitment
    assert (account.current_policy_epoch, account.current_recovery_generation) == (1, 1)
    assert policy.state == "RELEASED"
    assert source.state == "revoked"
    assert untouched.state == "sealed" and untouched.erc_commitment == shared_commitment
    assert {grant.recovery_id: grant.state for grant in grants} == {
        fixture.recovery_id: "revoked",
        other.recovery_id: "available",
    }
    assert "owner-recovery-otp" not in emails
    clock.current += timedelta(days=40)
    renewed = await claim(recovery, fixture)
    replay = recipient_document(
        fixture,
        renewed,
        rotation_id,
        "confirm",
        target_recovery_id=confirm["signed"]["target_recovery_id"],
        erc_commitment=COMMITMENT,
        target_wrapper_digest=TARGET_DIGEST,
    )
    assert (await call(service, "confirm", RecipientRecoveryConfirmRequest, replay))[
        "state"
    ] == "complete"


async def test_successor_srs_survives_token_expiry_and_lost_provision_response():
    recovery, service, fixture, clock = await setup()
    rotation_id, authorization, provision, provisioned, prepared, confirm = (
        await prepare_rotation(recovery, service, fixture)
    )
    clock.current += timedelta(days=120)
    with pytest.raises(AeternaProtocolException) as expired:
        await call(service, "provision", RecipientRecoveryProvisionRequest, provision)
    assert expired.value.code == "recovery.claim_unavailable"
    renewed = await claim(recovery, fixture)
    retry = recipient_document(
        fixture,
        renewed,
        rotation_id,
        "provision",
        target_recovery_id=provision["signed"]["target_recovery_id"],
        erc_commitment=COMMITMENT,
    )
    redelivered = await call(
        service, "provision", RecipientRecoveryProvisionRequest, retry
    )
    assert redelivered["srs"] == provisioned["srs"]
    assert redelivered["target_generation"] == 1
    assert redelivered["target_policy_epoch"] == redelivered["source_policy_epoch"]
    retry_confirm = recipient_document(
        fixture,
        renewed,
        rotation_id,
        "confirm",
        target_recovery_id=confirm["signed"]["target_recovery_id"],
        erc_commitment=COMMITMENT,
        target_wrapper_digest=TARGET_DIGEST,
    )
    assert (
        await call(service, "confirm", RecipientRecoveryConfirmRequest, retry_confirm)
    )["state"] == "complete"


async def test_recipient_entry_and_delayed_email_remain_usable_after_two_days():
    recovery, _service, fixture, clock = await setup()
    clock.current += timedelta(days=2)
    adapter = CapturingEmailAdapter(clock.current)
    delivery = AeternaEmailDeliveryService(
        adapter=adapter, key_provider=synthetic_keys, clock=clock
    )
    async with database.get_session_local()() as db:
        event = await db.scalar(
            select(AeternaEmailOutboxEvent).where(
                AeternaEmailOutboxEvent.account_id == fixture.account_id,
                AeternaEmailOutboxEvent.event_type == "recovery-claim-link",
            )
        )
        link = await db.get(AeternaRecoveryClaimLink, event.recovery_link_id)
        assert link.expires_at < clock.current
        result = await delivery.dispatch_event(db, event.id)
    assert result.status == "provider_accepted"
    assert len(adapter.envelopes) == 1
    assert "24 hours" not in adapter.envelopes[0].text_body
    token = derive_recovery_link_token(
        synthetic_keys(), link.id, link.token_key_version
    )
    async with database.get_session_local()() as db:
        data = await recovery.start_recipient_claim(
            db,
            RecoveryClaimStartRequest(
                protocol_version=1, request_id=str(uuid.uuid4()), claim_link_token=token
            ),
        )
    async with database.get_session_local()() as db:
        event = await db.scalar(
            select(AeternaEmailOutboxEvent).where(
                AeternaEmailOutboxEvent.recovery_challenge_id
                == uuid.UUID(data["challenge_id"]),
                AeternaEmailOutboxEvent.event_type == "recovery-otp",
            )
        )
        assert (
            await delivery.dispatch_event(db, event.id)
        ).status == "provider_accepted"
    assert len(adapter.envelopes) == 2
    payload = RecoveryClaimVerifyRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        claim_link_token=token,
        challenge_id=data["challenge_id"],
        code=derive_recovery_otp(synthetic_keys(), uuid.UUID(data["challenge_id"])),
    )
    async with database.get_session_local()() as db:
        with pytest.raises(AeternaProtocolException) as legacy:
            await recovery.verify_claim(db, payload)
    assert legacy.value.code == "recovery.claim_unavailable"
    async with database.get_session_local()() as db:
        authorization = await recovery.verify_recipient_claim(db, payload)
    assert authorization["scope"] == "recovery.recipient.rotate"
    assert authorization["recovery_id"] == str(fixture.recovery_id)


async def test_downgrade_cannot_delete_durable_successor_material():
    recovery, service, fixture, _clock = await setup()
    rotation_id, _authorization, _provision, _data, _prepared, _confirm = (
        await prepare_rotation(recovery, service, fixture)
    )
    migration = importlib.import_module(
        "migrations.versions.f4ca2910b803_add_recipient_vault_rotation"
    )

    def downgrade(connection):
        with Operations.context(MigrationContext.configure(connection)):
            migration.downgrade()

    with pytest.raises(RuntimeError, match="downgrade refused"):
        async with database.get_engine().begin() as connection:
            await connection.run_sync(downgrade)
    async with database.get_session_local()() as db:
        assert (
            await db.get(AeternaRecipientRecoveryRotation, rotation_id)
        ).encrypted_srs is not None


async def test_recipient_and_owner_record_namespaces_reject_id_reuse():
    recovery, service, fixture, _clock = await setup()
    authorization = await claim(recovery, fixture)
    rotation_id = uuid.uuid4()
    secret = recipient_document(fixture, authorization, rotation_id, "secret")
    await call(service, "release_secret", RecipientRecoverySecretRequest, secret)
    duplicate = recipient_document(
        fixture,
        authorization,
        rotation_id,
        "provision",
        target_recovery_id=str(fixture.recovery_id),
        erc_commitment=COMMITMENT,
    )
    with pytest.raises(AeternaProtocolException) as existing:
        await call(service, "provision", RecipientRecoveryProvisionRequest, duplicate)
    assert existing.value.code == "recovery.recipient_rotation_conflict"
    target_id = uuid.uuid4()
    provision = recipient_document(
        fixture,
        authorization,
        rotation_id,
        "provision",
        target_recovery_id=str(target_id),
        erc_commitment=COMMITMENT,
    )
    await call(service, "provision", RecipientRecoveryProvisionRequest, provision)
    target_fixture = replace(fixture, recovery_id=target_id)
    ordinary = signed_document(
        target_fixture,
        domain="aeterna.recovery-record.provision.v1",
        operation="recovery_record.provision",
        members={"crypto_format_version": 1, "recovery_context_version": 1},
    )
    with pytest.raises(AeternaProtocolException) as enrollment:
        await call(
            recovery, "provision_record", RecoveryRecordProvisionRequest, ordinary
        )
    assert enrollment.value.code == "recovery.recipient_rotation_conflict"
    owner_rotation = signed_document(
        target_fixture,
        domain="aeterna.recovery-rotation.provision.v1",
        operation="recovery_rotation.provision",
        members={
            "kind": "erc_rotation",
            "rotation_id": str(uuid.uuid4()),
            "source_policy_epoch": 1,
            "source_generation": 1,
            "target_policy_epoch": 1,
            "target_generation": 2,
        },
    )
    with pytest.raises(AeternaProtocolException) as owner:
        await call(
            recovery,
            "provision_rotation",
            RecoveryRotationProvisionRequest,
            owner_rotation,
        )
    assert owner.value.code == "recovery.recipient_rotation_conflict"


async def test_abandon_retains_material_and_releases_only_uncommitted_reservation():
    recovery, service, fixture, _clock = await setup()
    rotation_id, authorization, _provision, _provisioned, _prepared, _confirm = (
        await prepare_rotation(recovery, service, fixture)
    )
    async with database.get_session_local()() as db:
        original = await db.get(AeternaRecipientRecoveryRotation, rotation_id)
        ciphertext = original.encrypted_srs
    document = recipient_document(fixture, authorization, rotation_id, "abandon")
    result = await call(service, "abandon", RecipientRecoveryAbandonRequest, document)
    assert result["state"] == "abandoned"
    assert (
        await call(service, "abandon", RecipientRecoveryAbandonRequest, document)
    ) == result
    async with database.get_session_local()() as db:
        retained = await db.get(AeternaRecipientRecoveryRotation, rotation_id)
        source = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
    assert retained.encrypted_srs == ciphertext
    assert source.state == "sealed"
    fresh = recipient_document(fixture, authorization, uuid.uuid4(), "secret")
    assert (
        await call(service, "release_secret", RecipientRecoverySecretRequest, fresh)
    )["state"] == "reserved"


async def test_concurrent_reservations_and_changed_prepared_target_are_rejected():
    recovery, service, fixture, _clock = await setup()
    authorization = await claim(recovery, fixture)
    first = recipient_document(fixture, authorization, uuid.uuid4(), "secret")
    second = recipient_document(fixture, authorization, uuid.uuid4(), "secret")

    async def reserve(document):
        try:
            return await call(
                service, "release_secret", RecipientRecoverySecretRequest, document
            )
        except AeternaProtocolException as error:
            return error.code

    outcomes = await asyncio.gather(reserve(first), reserve(second))
    assert sum(isinstance(result, dict) for result in outcomes) == 1
    assert "recovery.recipient_rotation_in_progress" in outcomes
    winning = first if isinstance(outcomes[0], dict) else second
    rotation_id = uuid.UUID(winning["signed"]["rotation_id"])
    target = {"target_recovery_id": str(uuid.uuid4()), "erc_commitment": COMMITMENT}
    provision = recipient_document(
        fixture, authorization, rotation_id, "provision", **target
    )
    await call(service, "provision", RecipientRecoveryProvisionRequest, provision)
    for digest in (TARGET_DIGEST, encode_base64url(bytes([0x88]) * 32)):
        document = recipient_document(
            fixture,
            authorization,
            rotation_id,
            "prepare",
            **target,
            target_wrapper_digest=digest,
        )
        if digest == TARGET_DIGEST:
            await call(service, "prepare", RecipientRecoveryPrepareRequest, document)
        else:
            with pytest.raises(AeternaProtocolException) as conflict:
                await call(
                    service, "prepare", RecipientRecoveryPrepareRequest, document
                )
            assert conflict.value.code == "recovery.recipient_rotation_conflict"


@pytest.mark.parametrize(
    "failure", ["signature", "wrapper", "consent", "release", "provider"]
)
async def test_invalid_authority_or_material_failure_does_not_reserve(failure):
    recovery, service, fixture, _clock = await setup()
    authorization = await claim(recovery, fixture)
    rotation_id = uuid.uuid4()
    document = recipient_document(
        fixture,
        authorization,
        rotation_id,
        "secret",
        **({"wrapper_digest": TARGET_DIGEST} if failure == "wrapper" else {}),
    )
    if failure == "signature":
        document["signature"] = encode_base64url(bytes([0x11]) * 64)
    elif failure == "provider":
        recovery.claim_provider = lambda: FailingDecryptProvider(recovery_provider())
    elif failure in {"consent", "release"}:
        async with database.get_session_local().begin() as db:
            if failure == "consent":
                contact = await db.get(AeternaContact, fixture.contact_id)
                contact.consent_status = "DECLINED"
                contact.accepted_at = None
                contact.verified_at = None
                contact.declined_at = recovery._now()
            else:
                policy = await db.scalar(
                    select(AccountPolicy).where(
                        AccountPolicy.account_id == fixture.account_id
                    )
                )
                policy.state = "ACTIVE"
                policy.released_at = None
    with pytest.raises(AeternaProtocolException):
        await call(service, "release_secret", RecipientRecoverySecretRequest, document)
    async with database.get_session_local()() as db:
        assert await db.get(AeternaRecipientRecoveryRotation, rotation_id) is None
        grant = await db.scalar(
            select(AeternaRecoveryGrant).where(
                AeternaRecoveryGrant.recovery_id == fixture.recovery_id
            )
        )
    assert grant.state == "available"


async def test_custody_verification_requires_current_active_sealed_commitment():
    recovery, service, fixture, _clock = await setup(released=False)
    async with database.get_session_local().begin() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        account.erc_commitment = bytes([0x55]) * 32
        account.erc_commitment_epoch = 1
        account.erc_commitment_generation = 1
        record.erc_commitment = bytes([0x55]) * 32

    async def custody(**changes):
        challenge_document = signed_document(
            fixture,
            domain="aeterna.recovery-custody.challenge.v1",
            operation="recovery_custody.challenge",
            members={"wrapper_digest": SOURCE_DIGEST},
        )
        challenge = await call(
            service,
            "challenge_custody",
            RecoveryCustodyChallengeRequest,
            challenge_document,
        )
        return signed_document(
            fixture,
            domain="aeterna.recovery-custody.verify.v1",
            operation="recovery_custody.verify",
            members={
                "wrapper_digest": SOURCE_DIGEST,
                "erc_commitment": COMMITMENT,
                "challenge_id": challenge["challenge_id"],
                "challenge": challenge["challenge"],
                **changes,
            },
        )

    assert await call(
        service, "verify_custody", RecoveryCustodyVerifyRequest, await custody()
    ) == {"verified": True}
    with pytest.raises(AeternaProtocolException) as wrong:
        await call(
            service,
            "verify_custody",
            RecoveryCustodyVerifyRequest,
            await custody(erc_commitment=encode_base64url(bytes([0x88]) * 32)),
        )
    assert wrong.value.code == "recovery.erc_mismatch"
    with pytest.raises(AeternaProtocolException) as stale:
        await call(
            service,
            "verify_custody",
            RecoveryCustodyVerifyRequest,
            await custody(wrapper_digest=TARGET_DIGEST),
        )
    assert stale.value.code == "recovery.record_unavailable"
    await release_policy(fixture.account_id, recovery._now())
    with pytest.raises(AeternaProtocolException) as released:
        await call(
            service, "verify_custody", RecoveryCustodyVerifyRequest, await custody()
        )
    assert released.value.code == "recovery.record_unavailable"


async def custody_documents(
    service, fixture, *, commitment=COMMITMENT, wrapper=SOURCE_DIGEST
):
    challenge_document = signed_document(
        fixture,
        domain="aeterna.recovery-custody.challenge.v1",
        operation="recovery_custody.challenge",
        members={"wrapper_digest": wrapper},
    )
    challenge = await call(
        service,
        "challenge_custody",
        RecoveryCustodyChallengeRequest,
        challenge_document,
    )
    verify = signed_document(
        fixture,
        domain="aeterna.recovery-custody.verify.v1",
        operation="recovery_custody.verify",
        members={
            "wrapper_digest": wrapper,
            "erc_commitment": commitment,
            "challenge_id": challenge["challenge_id"],
            "challenge": challenge["challenge"],
        },
    )
    return challenge_document, challenge, verify


async def active_custody():
    recovery, service, fixture, clock = await setup(released=False)
    async with database.get_session_local().begin() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        record = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        account.erc_commitment = bytes([0x55]) * 32
        account.erc_commitment_epoch = 1
        account.erc_commitment_generation = 1
        record.erc_commitment = bytes([0x55]) * 32
    return recovery, service, fixture, clock


async def test_custody_nonce_replay_expiry_and_concurrent_exact_retry():
    _, service, fixture, clock = await active_custody()
    challenge_document, challenge, verify = await custody_documents(service, fixture)
    assert (
        await call(
            service,
            "challenge_custody",
            RecoveryCustodyChallengeRequest,
            challenge_document,
        )
        == challenge
    )
    results = await asyncio.gather(
        *(
            call(service, "verify_custody", RecoveryCustodyVerifyRequest, verify)
            for _ in range(2)
        )
    )
    assert results == [{"verified": True}, {"verified": True}]
    changed = signed_document(
        fixture,
        domain="aeterna.recovery-custody.verify.v1",
        operation="recovery_custody.verify",
        members={
            **{
                key: value
                for key, value in verify["signed"].items()
                if key not in {"request_id"}
            },
            "erc_commitment": encode_base64url(bytes([0x88]) * 32),
        },
    )
    with pytest.raises(AeternaProtocolException) as replay:
        await call(service, "verify_custody", RecoveryCustodyVerifyRequest, changed)
    assert replay.value.code == "request.idempotency_conflict"
    clock.current += timedelta(minutes=5)
    with pytest.raises(AeternaProtocolException) as expired:
        await call(service, "verify_custody", RecoveryCustodyVerifyRequest, verify)
    assert expired.value.code == "recovery.custody_challenge_unavailable"


async def test_failed_commitment_consumes_challenge_without_secret_release():
    _, service, fixture, _ = await active_custody()
    _, _, verify = await custody_documents(
        service, fixture, commitment=encode_base64url(bytes([0x88]) * 32)
    )
    with pytest.raises(AeternaProtocolException) as mismatch:
        await call(service, "verify_custody", RecoveryCustodyVerifyRequest, verify)
    assert mismatch.value.code == "recovery.erc_mismatch"
    verify["signed"]["erc_commitment"] = COMMITMENT
    from app.services.common.aeterna_security import canonicalize

    verify["signature"] = encode_base64url(
        fixture.signing_key.sign(canonicalize(verify["signed"]))
    )
    with pytest.raises(AeternaProtocolException) as replay:
        await call(service, "verify_custody", RecoveryCustodyVerifyRequest, verify)
    assert replay.value.code == "request.idempotency_conflict"


async def test_recipient_confirmation_transfers_management_and_successor_custody():
    recovery, service, fixture, clock = await setup()
    rotation_id, _, _, provisioned, _, confirm = await prepare_rotation(
        recovery, service, fixture
    )
    async with database.get_session_local()() as db:
        assert (
            await db.scalar(
                select(AeternaManagementAlias.id).where(
                    AeternaManagementAlias.account_id == fixture.account_id
                )
            )
            is None
        )
    result = await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
    assert result["account_management_transferred"] is True
    assert result["management_email"] == "contact@example.com"
    from app.services.client.aeterna_notification import AeternaNotificationService
    from tests.integration.test_aeterna_notification import configuration_call

    configuration = await configuration_call(
        AeternaNotificationService(key_provider=synthetic_keys, clock=clock),
        fixture,
        "owner_configuration.read",
        {"contact_ids": []},
    )
    assert configuration["owner_email"] == "contact@example.com"
    assert configuration["management_email"] == "contact@example.com"
    successor = replace(
        fixture, recovery_id=uuid.UUID(provisioned["target_recovery_id"])
    )
    _, _, verify = await custody_documents(service, successor, wrapper=TARGET_DIGEST)
    assert await call(
        service, "verify_custody", RecoveryCustodyVerifyRequest, verify
    ) == {"verified": True}
    async with database.get_session_local()() as db:
        from app.services.common.aeterna_management import (
            AeternaManagementAuthorityService,
        )

        account = await db.get(AeternaAccount, fixture.account_id)
        authority = AeternaManagementAuthorityService()
        assert await authority.accepts_mailbox(
            db, account, email_lookup(synthetic_keys(), "contact@example.com")
        )
        assert not await authority.accepts_mailbox(
            db, account, email_lookup(synthetic_keys(), "owner@example.com")
        )
        assert (
            await authority.mailbox(db, synthetic_keys(), account)
            == "contact@example.com"
        )
        assert (
            await db.get(AeternaRecipientRecoveryRotation, rotation_id)
        ).management_alias_id is not None


async def test_explicit_policy_configuration_creates_new_epoch_after_confirmation():
    from app.schemas.client.aeterna_setup import PolicyConfigureRequest
    from app.services.client.aeterna_setup import AeternaSetupService

    recovery, service, fixture, clock = await setup()
    configure = signed_document(
        fixture,
        domain="aeterna.policy.configure.v1",
        operation="policy.configure",
        include_recovery_binding=False,
        members={"inactivity_days": 30, "warning_days": 7, "grace_days": 7},
    )
    setup_service = AeternaSetupService(clock=clock)
    with pytest.raises(AeternaProtocolException) as early:
        await call(setup_service, "configure_policy", PolicyConfigureRequest, configure)
    assert early.value.code == "policy.unavailable"
    _, _, _, _, _, confirm = await prepare_rotation(recovery, service, fixture)
    await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
    configured = await call(
        setup_service, "configure_policy", PolicyConfigureRequest, configure
    )
    assert configured["policy"]["epoch"] == 2
    assert configured["policy"]["generation"] == 1
    assert configured["policy"]["state"] == "ACTIVE"
    assert (
        await call(setup_service, "configure_policy", PolicyConfigureRequest, configure)
        == configured
    )
    async with database.get_session_local()() as db:
        historical = await db.scalar(
            select(AccountPolicy).where(
                AccountPolicy.account_id == fixture.account_id, AccountPolicy.epoch == 1
            )
        )
        assert historical.state == "RELEASED" and historical.retired_at is not None
        assert (await db.get(AeternaAccount, fixture.account_id)).erc_commitment is None
        assert (await db.get(AeternaDevice, fixture.device_id)).policy_epoch == 2
        assert (
            await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        ).state == "revoked"


async def test_targeted_contact_mailbox_verification_does_not_merge_external_account():
    from app.schemas.client.aeterna_protocol import (
        AccountChallengeRequest,
        AccountChallengeVerificationRequest,
        DeviceBindingApprovalRequest,
    )
    from app.services.client.aeterna_identity import AeternaIdentityService
    from tests.integration.test_aeterna_identity_protocol import (
        public_key,
        request_binding,
        signed_envelope,
        signing_key,
    )

    class SyntheticNotifier:
        async def send_challenge(self, email, code, expires_in_minutes):
            assert email == "contact@example.com" and code == "12345678"
            return True

        async def send_security_notice(self, email, event):
            assert email == "contact@example.com" and event == "device.bound"
            return True

    recovery, service, fixture, clock = await setup()
    external_id = uuid.uuid4()
    ciphertext, nonce, version = encrypt_email(
        synthetic_keys(), "contact@example.com", "account", external_id
    )
    async with database.get_session_local().begin() as db:
        db.add(
            AeternaAccount(
                id=external_id,
                email_lookup=email_lookup(synthetic_keys(), "contact@example.com"),
                email_ciphertext=ciphertext,
                email_nonce=nonce,
                email_key_version=version,
                is_active=True,
            )
        )
    _, _, _, _, _, confirm = await prepare_rotation(recovery, service, fixture)
    await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
    identity = AeternaIdentityService(
        key_provider=synthetic_keys, clock=clock, otp_factory=lambda: "12345678"
    )
    request = AccountChallengeRequest(
        protocol_version=1,
        request_id=str(uuid.uuid4()),
        email="contact@example.com",
        purpose="device_binding",
        account_id=str(fixture.account_id),
    )
    async with database.get_session_local()() as db:
        data = await identity.initiate_challenge(
            db,
            request,
            request.model_dump(exclude_none=True),
            "192.0.2.19",
            SyntheticNotifier(),
        )
    async with database.get_session_local()() as db:
        grant = await identity.verify_challenge(
            db,
            AccountChallengeVerificationRequest(
                protocol_version=1,
                request_id=str(uuid.uuid4()),
                challenge_id=data["challenge_id"],
                code="12345678",
            ),
        )
    assert grant["account_id"] == str(fixture.account_id)
    assert grant["account_id"] != str(external_id)
    new_device_id = uuid.uuid4()
    new_key = signing_key(0x6A)
    async with database.get_session_local()() as db:
        _, pending = await request_binding(
            db, identity, grant, new_key, str(new_device_id), "Recovered contact device"
        )
    assert pending["account_id"] == str(fixture.account_id)
    assert pending["state"] == "pending"
    async with database.get_session_local()() as db:
        assert await db.get(AeternaDevice, new_device_id) is None
    signed = {
        "canonicalization": "jcs-rfc8785",
        "domain": "aeterna.device-binding.approval.v1",
        "operation": "device_binding.approval",
        "protocol_version": 1,
        "signature_version": 1,
        "request_id": str(uuid.uuid4()),
        "account_id": str(fixture.account_id),
        "binding_id": pending["binding_id"],
        "approving_device_id": str(fixture.device_id),
        "device_id": str(new_device_id),
        "public_key": public_key(new_key),
        "challenge": pending["challenge"],
    }
    approval = signed_envelope(signed, fixture.signing_key)
    async with database.get_session_local()() as db:
        status, approved = await identity.approve_binding(
            db,
            DeviceBindingApprovalRequest.model_validate(approval),
            approval,
            SyntheticNotifier(),
        )
    assert status == 200 and approved["state"] == "active"
    async with database.get_session_local()() as db:
        assert (
            await db.get(AeternaDevice, new_device_id)
        ).account_id == fixture.account_id
        assert (await db.get(AeternaAccount, external_id)).first_device_bound_at is None
    old = request.model_copy(
        update={"request_id": str(uuid.uuid4()), "email": "owner@example.com"}
    )
    clock.current += timedelta(minutes=2)
    async with database.get_session_local()() as db:
        with pytest.raises(AeternaProtocolException) as former:
            await identity.initiate_challenge(
                db,
                old,
                old.model_dump(exclude_none=True),
                "192.0.2.20",
                SyntheticNotifier(),
            )
    assert former.value.code == "auth.challenge_invalid"


async def test_multiple_completed_managers_keep_mailbox_proofs_and_primary():
    from app.models.aeterna_identity import AeternaBindingGrant
    from app.services.common.aeterna_management import AeternaManagementAuthorityService

    recovery, service, fixture, clock = await setup()
    second_id = uuid.uuid4()
    second = replace(
        fixture, contact_id=second_id, recovery_id=uuid.uuid4(), vault_id=uuid.uuid4()
    )
    ciphertext, nonce, version = encrypt_email(
        synthetic_keys(), "second@example.com", "contact", second_id
    )
    async with database.get_session_local().begin() as db:
        db.add(
            AeternaContact(
                id=second_id,
                account_id=fixture.account_id,
                email_lookup=email_lookup(synthetic_keys(), "second@example.com"),
                email_ciphertext=ciphertext,
                email_nonce=nonce,
                email_key_version=version,
                disclosure_mode="PRIVATE_UNTIL_RELEASE",
                consent_status="ACCEPTED",
                accepted_at=clock.current,
                verified_at=clock.current,
            )
        )
        original = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        values = {
            column.name: getattr(original, column.name)
            for column in original.__table__.columns
        }
        values.update(
            id=second.recovery_id,
            vault_id=second.vault_id,
            provision_request_id=uuid.uuid4(),
        )
        second_record = AeternaRecoveryRecord(**values)
        envelope = recovery.provision_provider().generate_srs(
            service._context(second_record, second_record.id)
        )
        second_record.encrypted_srs = envelope.ciphertext
        second_record.kms_key_arn = envelope.key_arn
        second_record.kms_key_material_id = envelope.key_material_id
        envelope.plaintext[:] = bytes(len(envelope.plaintext))
        db.add(second_record)
    async with database.get_session_local()() as db:
        await recovery.materialize_released_account(db, fixture.account_id)
    _, _, _, _, _, confirm = await prepare_rotation(recovery, service, fixture)
    await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
    pending_id = uuid.uuid4()
    grant_id = uuid.uuid4()
    async with database.get_session_local().begin() as db:
        ciphertext, nonce, version = encrypt_email(
            synthetic_keys(), "contact@example.com", "challenge", pending_id
        )
        db.add(
            AeternaAccountChallenge(
                id=pending_id,
                request_id=uuid.uuid4(),
                request_digest=bytes([0x62]) * 32,
                purpose="device_binding",
                account_id=fixture.account_id,
                email_lookup=email_lookup(synthetic_keys(), "contact@example.com"),
                email_ciphertext=ciphertext,
                email_nonce=nonce,
                email_key_version=version,
                otp_verifier=bytes([0x63]) * 32,
                ip_lookup=bytes([0x64]) * 32,
                attempt_count=0,
                status="pending",
                expires_at=clock.current + timedelta(minutes=10),
                resend_after=clock.current,
                delivery_status="sent",
            )
        )
        await db.flush()
        db.add(
            AeternaBindingGrant(
                id=grant_id,
                challenge_id=pending_id,
                account_id=fixture.account_id,
                purpose="device_binding",
                token_digest=bytes([0x65]) * 32,
                expires_at=clock.current + timedelta(minutes=10),
            )
        )
    clock.current += timedelta(seconds=1)
    _, _, _, _, _, confirm_second = await prepare_rotation(recovery, service, second)
    result = await call(
        service, "confirm", RecipientRecoveryConfirmRequest, confirm_second
    )
    assert result["management_email"] == "second@example.com"
    from app.services.client.aeterna_notification import AeternaNotificationService
    from tests.integration.test_aeterna_notification import configuration_call

    configuration = await configuration_call(
        AeternaNotificationService(key_provider=synthetic_keys, clock=clock),
        second,
        "owner_configuration.read",
        {"contact_ids": []},
    )
    assert configuration["owner_email"] == "contact@example.com"
    assert configuration["management_email"] == "second@example.com"
    async with database.get_session_local()() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        authority = AeternaManagementAuthorityService()
        assert (
            await authority.mailbox(db, synthetic_keys(), account)
            == "contact@example.com"
        )
        assert (
            await authority.preferred_mailbox(
                db, synthetic_keys(), account, fixture.device_id
            )
            == "second@example.com"
        )
        for email in ("contact@example.com", "second@example.com"):
            assert await authority.accepts_mailbox(
                db, account, email_lookup(synthetic_keys(), email)
            )
        assert (await db.get(AeternaAccountChallenge, pending_id)).status == "pending"
        assert (await db.get(AeternaBindingGrant, grant_id)).expires_at > clock.current
        aliases = list(
            (
                await db.scalars(
                    select(AeternaManagementAlias).where(
                        AeternaManagementAlias.account_id == fixture.account_id
                    )
                )
            ).all()
        )
        assert len(aliases) == 2 and sum(alias.is_primary for alias in aliases) == 1
        await db.rollback()
    # New protection and Owner recovery use this device's successful manager.
    from app.schemas.client.aeterna_recovery import OwnerRecoveryStartRequest
    from app.schemas.client.aeterna_setup import PolicyConfigureRequest
    from app.services.client.aeterna_setup import AeternaSetupService

    configure = signed_document(
        fixture,
        domain="aeterna.policy.configure.v1",
        operation="policy.configure",
        include_recovery_binding=False,
        members={"inactivity_days": 30, "warning_days": 7, "grace_days": 7},
    )
    await call(
        AeternaSetupService(clock=clock),
        "configure_policy",
        PolicyConfigureRequest,
        configure,
    )
    fresh = replace(fixture, vault_id=uuid.uuid4(), recovery_id=uuid.uuid4())
    await provision_and_confirm(recovery, fresh)
    async with database.get_session_local().begin() as db:
        (await db.get(AeternaDevice, fixture.device_id)).last_seen_at = clock.current
    owner = signed_document(
        fresh,
        domain="aeterna.owner-recovery.start.v1",
        operation="owner_recovery.start",
        members={
            "policy_epoch": 2,
            "recovery_generation": 1,
            "wrapper_digest": SOURCE_DIGEST,
        },
    )
    started = await call(
        recovery, "start_owner_recovery", OwnerRecoveryStartRequest, owner
    )
    adapter = CapturingEmailAdapter(clock.current)
    delivery = AeternaEmailDeliveryService(
        adapter=adapter, key_provider=synthetic_keys, clock=clock
    )
    async with database.get_session_local()() as db:
        event = await db.scalar(
            select(AeternaEmailOutboxEvent).where(
                AeternaEmailOutboxEvent.owner_recovery_id
                == uuid.UUID(started["owner_recovery_id"]),
                AeternaEmailOutboxEvent.event_type == "owner-recovery-otp",
            )
        )
        assert (
            await delivery.dispatch_event(db, event.id)
        ).status == "provider_accepted"
    assert adapter.envelopes[0].recipient == "second@example.com"
    # Editing or removing contact identity does not delete completed mailbox snapshots.
    async with database.get_session_local().begin() as db:
        contact = await db.get(AeternaContact, second_id)
        contact.deleted_at = clock.current
    async with database.get_session_local()() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        assert (
            await authority.preferred_mailbox(
                db, synthetic_keys(), account, fixture.device_id
            )
            == "second@example.com"
        )


async def test_legacy_completed_receipt_explicitly_adds_missing_handoff():
    recovery, service, fixture, clock = await setup()
    rotation_id, _, _, _, _, confirm = await prepare_rotation(
        recovery, service, fixture
    )
    async with database.get_session_local().begin() as db:
        rotation = await db.get(AeternaRecipientRecoveryRotation, rotation_id)
        rotation.state = "complete"
        rotation.completed_at = clock.current
        source = await db.get(AeternaRecoveryRecord, fixture.recovery_id)
        source.state = "revoked"
        source.abandoned_at = clock.current
        grant = await db.get(AeternaRecoveryGrant, rotation.grant_id)
        grant.state = "revoked"
    result = await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
    assert (
        result["account_management_transferred"]
        and result["management_email"] == "contact@example.com"
    )
    assert (
        await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
        == result
    )


async def test_custody_limits_are_atomic_and_dependency_failure_is_closed():
    from redis.exceptions import ConnectionError

    from app.services.common.aeterna_custody_limiter import (
        DEVICE_REQUEST_LIMIT,
        AeternaCustodyLimiter,
    )

    limiter = AeternaCustodyLimiter(key_provider=synthetic_keys)
    identity = f"synthetic-device-{uuid.uuid4()}"

    async def attempt():
        try:
            await limiter.check("device", identity, str(uuid.uuid4()))
            return "accepted"
        except AeternaProtocolException as error:
            assert error.retry_after_seconds > 0
            return error.code

    results = await asyncio.gather(
        *(attempt() for _ in range(DEVICE_REQUEST_LIMIT + 4))
    )
    assert results.count("accepted") == DEVICE_REQUEST_LIMIT
    assert results.count("auth.rate_limited") == 4

    class UnavailableRedis:
        async def eval(self, *args):
            raise ConnectionError("Synthetic Redis unavailability")

    with pytest.raises(AeternaProtocolException) as closed:
        await AeternaCustodyLimiter(
            redis=UnavailableRedis(), key_provider=synthetic_keys
        ).check("ip", "192.0.2.3", str(uuid.uuid4()))
    assert closed.value.code == "service.temporarily_unavailable"


async def test_custody_ip_gate_precedes_body_and_database_work():
    from starlette.requests import Request

    from app.api.client.v1.aeterna_recovery import (
        challenge_recovery_custody,
        verify_recovery_custody,
    )

    class DeniedLimiter:
        async def check(self, scope, identity, request_id):
            assert scope == "ip"
            raise AeternaProtocolException(
                429, "auth.rate_limited", retry_after_seconds=60
            )

    service = type(
        "SyntheticCustodyService", (), {"custody_limiter": DeniedLimiter()}
    )()

    async def forbidden_receive():
        raise AssertionError("Denied request must not parse its body")

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/synthetic",
            "headers": [],
            "client": ("192.0.2.4", 12345),
        },
        receive=forbidden_receive,
    )
    for route in (challenge_recovery_custody, verify_recovery_custody):
        with pytest.raises(AeternaProtocolException) as denied:
            await route(request=request, db=None, service=service)
        assert denied.value.code == "auth.rate_limited"


async def test_expired_custody_nonce_cleanup_keeps_live_retry_receipt():
    from app.models.aeterna_management import AeternaCustodyChallenge

    _, service, fixture, clock = await active_custody()
    _, expired, verify = await custody_documents(service, fixture)
    await call(service, "verify_custody", RecoveryCustodyVerifyRequest, verify)
    clock.current += timedelta(minutes=4)
    _, live, live_verify = await custody_documents(service, fixture)
    clock.current += timedelta(minutes=2)
    await custody_documents(service, fixture)
    async with database.get_session_local()() as db:
        assert (
            await db.get(AeternaCustodyChallenge, uuid.UUID(expired["challenge_id"]))
            is None
        )
        assert (
            await db.get(AeternaCustodyChallenge, uuid.UUID(live["challenge_id"]))
            is not None
        )
    assert await call(
        service, "verify_custody", RecoveryCustodyVerifyRequest, live_verify
    ) == {"verified": True}


async def test_first_handoff_cancels_original_owner_otp_requests_and_grants():
    from app.models.aeterna_recovery import AeternaOwnerRecoveryRequest
    from app.schemas.client.aeterna_recovery import OwnerRecoveryVerifyRequest
    from app.services.common.aeterna_security import otp_verifier

    recovery, service, fixture, clock = await setup()
    owner_request_id = uuid.uuid4()
    challenge_id = uuid.uuid4()
    code = derive_recovery_otp(synthetic_keys(), challenge_id)
    async with database.get_session_local().begin() as db:
        db.add(
            AeternaOwnerRecoveryRequest(
                id=owner_request_id,
                account_id=fixture.account_id,
                device_id=fixture.device_id,
                recovery_id=fixture.recovery_id,
                vault_id=fixture.vault_id,
                policy_epoch=1,
                recovery_generation=1,
                rekey_required=True,
                wrapper_digest=bytes([0x66]) * 32,
                state="pending_email",
                start_request_id=uuid.uuid4(),
                start_request_digest=bytes([0x23]) * 32,
                challenge_id=challenge_id,
                otp_verifier=otp_verifier(
                    synthetic_keys(), challenge_id, "owner-recovery", code
                ),
                otp_key_version=1,
                attempt_count=0,
                challenge_expires_at=clock.current + timedelta(minutes=10),
                expires_at=clock.current + timedelta(minutes=10),
            )
        )
    _, _, _, _, _, confirm = await prepare_rotation(recovery, service, fixture)
    await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
    async with database.get_session_local()() as db:
        request = await db.get(AeternaOwnerRecoveryRequest, owner_request_id)
        assert request.state == "cancelled" and request.cancelled_at == clock.current
    async with database.get_session_local()() as db:
        with pytest.raises(AeternaProtocolException) as old:
            await recovery.verify_owner_recovery(
                db,
                OwnerRecoveryVerifyRequest(
                    protocol_version=1,
                    request_id=str(uuid.uuid4()),
                    owner_recovery_id=str(owner_request_id),
                    challenge_id=str(challenge_id),
                    code=code,
                ),
            )
    assert old.value.code == "recovery.otp_invalid"


async def test_original_binding_grant_and_concurrent_owner_otp_cannot_survive_handoff():
    from app.models.aeterna_identity import AeternaBindingGrant
    from app.models.aeterna_recovery import AeternaOwnerRecoveryRequest
    from app.schemas.client.aeterna_recovery import OwnerRecoveryVerifyRequest
    from app.services.client.aeterna_identity import AeternaIdentityService
    from app.services.common.aeterna_security import make_token, otp_verifier

    recovery, service, fixture, clock = await setup()
    challenge_id = uuid.uuid4()
    binding_challenge_id = uuid.uuid4()
    request_id = uuid.uuid4()
    grant_id = uuid.uuid4()
    token, token_hash = make_token()
    code = derive_recovery_otp(synthetic_keys(), challenge_id)
    async with database.get_session_local().begin() as db:
        account = await db.get(AeternaAccount, fixture.account_id)
        ciphertext, nonce, version = encrypt_email(
            synthetic_keys(), "owner@example.com", "challenge", binding_challenge_id
        )
        db.add(
            AeternaAccountChallenge(
                id=binding_challenge_id,
                request_id=uuid.uuid4(),
                request_digest=bytes([0x28]) * 32,
                purpose="device_binding",
                account_id=fixture.account_id,
                email_lookup=account.email_lookup,
                email_ciphertext=ciphertext,
                email_nonce=nonce,
                email_key_version=version,
                otp_verifier=bytes([0x29]) * 32,
                ip_lookup=bytes([0x30]) * 32,
                attempt_count=0,
                status="consumed",
                expires_at=clock.current + timedelta(minutes=10),
                resend_after=clock.current,
                delivery_status="sent",
            )
        )
        await db.flush()
        db.add(
            AeternaBindingGrant(
                id=grant_id,
                challenge_id=binding_challenge_id,
                account_id=fixture.account_id,
                purpose="device_binding",
                token_digest=token_hash,
                expires_at=clock.current + timedelta(minutes=10),
            )
        )
        db.add(
            AeternaOwnerRecoveryRequest(
                id=request_id,
                account_id=fixture.account_id,
                device_id=fixture.device_id,
                recovery_id=fixture.recovery_id,
                vault_id=fixture.vault_id,
                policy_epoch=1,
                recovery_generation=1,
                rekey_required=True,
                wrapper_digest=bytes([0x66]) * 32,
                state="pending_email",
                start_request_id=uuid.uuid4(),
                start_request_digest=bytes([0x31]) * 32,
                challenge_id=challenge_id,
                otp_verifier=otp_verifier(
                    synthetic_keys(), challenge_id, "owner-recovery", code
                ),
                otp_key_version=1,
                attempt_count=0,
                challenge_expires_at=clock.current + timedelta(minutes=10),
                expires_at=clock.current + timedelta(minutes=10),
            )
        )
    _, _, _, _, _, confirm = await prepare_rotation(recovery, service, fixture)

    async def verify_owner():
        async with database.get_session_local()() as db:
            try:
                return await recovery.verify_owner_recovery(
                    db,
                    OwnerRecoveryVerifyRequest(
                        protocol_version=1,
                        request_id=str(uuid.uuid4()),
                        owner_recovery_id=str(request_id),
                        challenge_id=str(challenge_id),
                        code=code,
                    ),
                )
            except AeternaProtocolException as error:
                await db.rollback()
                return error.code

    confirmed, _ = await asyncio.gather(
        call(service, "confirm", RecipientRecoveryConfirmRequest, confirm),
        verify_owner(),
    )
    assert confirmed["account_management_transferred"]
    async with database.get_session_local()() as db:
        assert (
            await db.get(AeternaOwnerRecoveryRequest, request_id)
        ).state == "cancelled"
        identity = AeternaIdentityService(key_provider=synthetic_keys, clock=clock)
        with pytest.raises(AeternaProtocolException) as stale:
            await identity._grant(
                db,
                str(grant_id),
                token,
                str(uuid.uuid4()),
                allowed_purposes={"device_binding"},
            )
    assert stale.value.code == "auth.binding_grant_invalid"


async def test_superseded_successor_custody_binding_cannot_be_adopted():
    from app.schemas.client.aeterna_setup import PolicyConfigureRequest
    from app.services.client.aeterna_setup import AeternaSetupService

    recovery, service, fixture, clock = await setup()
    _, _, _, provisioned, _, confirm = await prepare_rotation(
        recovery, service, fixture
    )
    await call(service, "confirm", RecipientRecoveryConfirmRequest, confirm)
    successor = replace(
        fixture, recovery_id=uuid.UUID(provisioned["target_recovery_id"])
    )
    _, _, old_verify = await custody_documents(
        service, successor, wrapper=TARGET_DIGEST
    )
    configure = signed_document(
        fixture,
        domain="aeterna.policy.configure.v1",
        operation="policy.configure",
        include_recovery_binding=False,
        members={"inactivity_days": 30, "warning_days": 7, "grace_days": 7},
    )
    await call(
        AeternaSetupService(clock=clock),
        "configure_policy",
        PolicyConfigureRequest,
        configure,
    )
    owner = replace(fixture, recovery_id=uuid.uuid4())
    await provision_and_confirm(recovery, owner)
    with pytest.raises(AeternaProtocolException) as replaced:
        await call(service, "verify_custody", RecoveryCustodyVerifyRequest, old_verify)
    assert replaced.value.code == "recovery.record_unavailable"
    challenge = signed_document(
        successor,
        domain="aeterna.recovery-custody.challenge.v1",
        operation="recovery_custody.challenge",
        members={"wrapper_digest": TARGET_DIGEST},
    )
    with pytest.raises(AeternaProtocolException) as old:
        await call(
            service, "challenge_custody", RecoveryCustodyChallengeRequest, challenge
        )
    assert old.value.code == "recovery.record_unavailable"
