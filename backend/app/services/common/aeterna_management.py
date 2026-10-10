"""Reuse successful-recipient mailbox authority across account operations."""

import secrets
import uuid
from collections.abc import Callable

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.aeterna_identity import AeternaAccountChallenge, AeternaBindingGrant
from app.models.aeterna_management import AeternaManagementAlias
from app.models.aeterna_recovery import AeternaOwnerRecoveryRequest
from app.services.common.aeterna_security import (
    decrypt_email,
    email_lookup,
    encrypt_email,
)


class AeternaManagementAuthorityService:
    """Snapshots independently verified recipients without merging accounts."""

    def __init__(
        self,
        uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ):
        self.uuid_factory = uuid_factory
        self.random_bytes = random_bytes

    async def primary_alias(self, db, account_id):
        return await db.scalar(
            select(AeternaManagementAlias).where(
                AeternaManagementAlias.account_id == account_id,
                AeternaManagementAlias.is_primary.is_(True),
            )
        )

    async def accepts_mailbox(self, db, account, lookup):
        primary = await self.primary_alias(db, account.id)
        if primary is None:
            return secrets.compare_digest(account.email_lookup, lookup)
        return (
            await db.scalar(
                select(AeternaManagementAlias.id).where(
                    AeternaManagementAlias.account_id == account.id,
                    AeternaManagementAlias.email_lookup == lookup,
                )
            )
            is not None
        )

    async def mailbox(self, db, keys, account):
        alias = await self.primary_alias(db, account.id)
        source = alias or account
        return decrypt_email(
            keys,
            source.email_ciphertext,
            source.email_nonce,
            "account",
            account.id,
            source.email_key_version,
        )

    async def preferred_mailbox(self, db, keys, account, device_id):
        from app.models.aeterna_recipient_recovery import (
            AeternaRecipientRecoveryRotation,
        )

        alias = await db.scalar(
            select(AeternaManagementAlias)
            .join(
                AeternaRecipientRecoveryRotation,
                AeternaRecipientRecoveryRotation.management_alias_id
                == AeternaManagementAlias.id,
            )
            .where(
                AeternaRecipientRecoveryRotation.account_id == account.id,
                AeternaRecipientRecoveryRotation.device_id == device_id,
                AeternaRecipientRecoveryRotation.state == "complete",
            )
            .order_by(
                AeternaRecipientRecoveryRotation.completed_at.desc(),
                AeternaRecipientRecoveryRotation.id.desc(),
            )
            .limit(1)
        )
        if alias is None:
            return await self.mailbox(db, keys, account)
        return decrypt_email(
            keys,
            alias.email_ciphertext,
            alias.email_nonce,
            "account",
            account.id,
            alias.email_key_version,
        )

    async def transfer(self, db: AsyncSession, keys, account, contact, rotation, now):
        # The caller holds the account lock before touching any child authority.
        email = decrypt_email(
            keys,
            contact.email_ciphertext,
            contact.email_nonce,
            "contact",
            contact.id,
            contact.email_key_version,
        )
        lookup = email_lookup(keys, email)
        first_transfer = await self.primary_alias(db, account.id) is None
        alias = await db.scalar(
            select(AeternaManagementAlias).where(
                AeternaManagementAlias.account_id == account.id,
                AeternaManagementAlias.email_lookup == lookup,
            )
        )
        if alias is None:
            primary = await self.primary_alias(db, account.id)
            ciphertext, nonce, version = encrypt_email(
                keys, email, "account", account.id, nonce_factory=self.random_bytes
            )
            alias = AeternaManagementAlias(
                id=self.uuid_factory(),
                account_id=account.id,
                rotation_id=rotation.id,
                email_lookup=lookup,
                email_ciphertext=ciphertext,
                email_nonce=nonce,
                email_key_version=version,
                is_primary=primary is None,
                created_at=now,
                updated_at=now,
            )
            db.add(alias)
        rotation.management_alias_id = alias.id
        await db.flush()
        valid_lookups = select(AeternaManagementAlias.email_lookup).where(
            AeternaManagementAlias.account_id == account.id
        )
        invalid_challenges = select(AeternaAccountChallenge.id).where(
            AeternaAccountChallenge.account_id == account.id,
            AeternaAccountChallenge.email_lookup.not_in(valid_lookups),
        )
        # Pre-handoff mailbox proofs must never authorize a later device bind.
        await db.execute(
            update(AeternaAccountChallenge)
            .where(
                AeternaAccountChallenge.account_id == account.id,
                AeternaAccountChallenge.status == "pending",
                AeternaAccountChallenge.email_lookup.not_in(valid_lookups),
            )
            .values(status="expired", updated_at=now)
        )
        await db.execute(
            update(AeternaBindingGrant)
            .where(
                AeternaBindingGrant.account_id == account.id,
                AeternaBindingGrant.consumed_at.is_(None),
                AeternaBindingGrant.challenge_id.in_(invalid_challenges),
            )
            .values(expires_at=now, updated_at=now)
        )
        if first_transfer:
            await db.execute(
                update(AeternaOwnerRecoveryRequest)
                .where(
                    AeternaOwnerRecoveryRequest.account_id == account.id,
                    AeternaOwnerRecoveryRequest.state.in_(
                        {"pending_email", "cooling_down", "material_released"}
                    ),
                )
                .values(state="cancelled", cancelled_at=now, updated_at=now)
            )
        return email


def get_aeterna_management_authority_service():
    return AeternaManagementAuthorityService()
