"""Envelope provider boundary for delayed-recovery server release secrets."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Protocol

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

KMS_CONTEXT_VERSION = 1
SRS_BYTES = 32
MAX_CIPHERTEXT_BYTES = 8192
KMS_BINDING_DOMAIN = b"AETERNA-KMS-SRS-BINDING-v1\x00"
SINGLE_REGION_KEY_ARN = re.compile(
    r"arn:aws:kms:ap-southeast-1:[0-9]{12}:key/"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class RecoveryKeyUnavailable(RuntimeError):
    """Raised without provider diagnostics or secret material."""


@dataclass(slots=True)
class GeneratedSrsEnvelope:
    """A caller-owned mutable plaintext and its persistent encrypted copy."""

    plaintext: bytearray
    ciphertext: bytes
    key_arn: str
    key_material_id: str


class RecoveryKeyProvider(Protocol):
    def generate_srs(self, context: dict[str, str]) -> GeneratedSrsEnvelope: ...

    def decrypt_srs(
        self, ciphertext: bytes, key_arn: str, context: dict[str, str]
    ) -> bytearray: ...


def recovery_encryption_context(
    *,
    environment: str,
    protocol_version: int,
    account_id: uuid.UUID,
    device_id: uuid.UUID,
    vault_id: uuid.UUID,
    recovery_id: uuid.UUID,
) -> dict[str, str]:
    if not 0 < protocol_version <= 65535:
        raise RecoveryKeyUnavailable("Recovery key context is unavailable")
    digest = hashlib.sha256(
        KMS_BINDING_DOMAIN
        + protocol_version.to_bytes(2, "big")
        + account_id.bytes
        + device_id.bytes
        + vault_id.bytes
        + recovery_id.bytes
    ).digest()
    binding = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return {
        "aeterna-purpose": "recovery-srs",
        "aeterna-environment": environment,
        "aeterna-context-version": str(KMS_CONTEXT_VERSION),
        "aeterna-binding": binding,
    }


class AwsKmsRecoveryKeyProvider:
    """Single-Region AWS KMS adapter with an exact key and exact context."""

    def __init__(self, *, region: str, key_arn: str, client=None):
        if (
            region != "ap-southeast-1"
            or SINGLE_REGION_KEY_ARN.fullmatch(key_arn) is None
        ):
            raise RecoveryKeyUnavailable("Recovery key provider is unavailable")
        self.region = region
        self.key_arn = key_arn
        self.client = client or boto3.client("kms", region_name=region)

    def generate_srs(self, context: dict[str, str]) -> GeneratedSrsEnvelope:
        try:
            response = self.client.generate_data_key(
                KeyId=self.key_arn,
                KeySpec="AES_256",
                EncryptionContext=context,
            )
            plaintext = response["Plaintext"]
            ciphertext = bytes(response["CiphertextBlob"])
            returned_key = response["KeyId"]
        except Exception:
            raise RecoveryKeyUnavailable("Recovery key operation failed") from None
        if (
            not isinstance(plaintext, (bytes, bytearray))
            or len(plaintext) != SRS_BYTES
            or not ciphertext
            or len(ciphertext) > MAX_CIPHERTEXT_BYTES
            or returned_key != self.key_arn
        ):
            raise RecoveryKeyUnavailable("Recovery key operation failed")
        return GeneratedSrsEnvelope(
            plaintext=bytearray(plaintext),
            ciphertext=ciphertext,
            key_arn=self.key_arn,
            key_material_id=returned_key,
        )

    def decrypt_srs(
        self, ciphertext: bytes, key_arn: str, context: dict[str, str]
    ) -> bytearray:
        if (
            key_arn != self.key_arn
            or not ciphertext
            or len(ciphertext) > MAX_CIPHERTEXT_BYTES
        ):
            raise RecoveryKeyUnavailable("Recovery key operation failed")
        try:
            response = self.client.decrypt(
                CiphertextBlob=ciphertext,
                KeyId=self.key_arn,
                EncryptionAlgorithm="SYMMETRIC_DEFAULT",
                EncryptionContext=context,
            )
            plaintext = response["Plaintext"]
            returned_key = response["KeyId"]
        except Exception:
            raise RecoveryKeyUnavailable("Recovery key operation failed") from None
        if (
            not isinstance(plaintext, (bytes, bytearray))
            or len(plaintext) != SRS_BYTES
            or returned_key != self.key_arn
        ):
            raise RecoveryKeyUnavailable("Recovery key operation failed")
        return bytearray(plaintext)


class InMemoryRecoveryKeyProvider:
    """Explicit local test adapter; never selected from production configuration."""

    def __init__(self, key: bytes, random_bytes=secrets.token_bytes):
        if len(key) != 32:
            raise ValueError("The synthetic recovery key must contain 32 bytes")
        self.key = key
        self.random_bytes = random_bytes
        self.key_arn = "local-test-recovery-key"

    def generate_srs(self, context: dict[str, str]) -> GeneratedSrsEnvelope:
        plaintext = bytearray(self.random_bytes(SRS_BYTES))
        nonce = self.random_bytes(12)
        if len(plaintext) != SRS_BYTES or len(nonce) != 12:
            plaintext[:] = b"\x00" * len(plaintext)
            raise RecoveryKeyUnavailable("Recovery key operation failed")
        ciphertext = nonce + AESGCM(self.key).encrypt(
            nonce, bytes(plaintext), self._aad(context)
        )
        return GeneratedSrsEnvelope(
            plaintext=plaintext,
            ciphertext=ciphertext,
            key_arn=self.key_arn,
            key_material_id="local-test-material-v1",
        )

    def decrypt_srs(
        self, ciphertext: bytes, key_arn: str, context: dict[str, str]
    ) -> bytearray:
        if key_arn != self.key_arn or len(ciphertext) < 28:
            raise RecoveryKeyUnavailable("Recovery key operation failed")
        try:
            plaintext = AESGCM(self.key).decrypt(
                ciphertext[:12], ciphertext[12:], self._aad(context)
            )
        except Exception:
            raise RecoveryKeyUnavailable("Recovery key operation failed") from None
        if len(plaintext) != SRS_BYTES:
            raise RecoveryKeyUnavailable("Recovery key operation failed")
        return bytearray(plaintext)

    def _aad(self, context: dict[str, str]) -> bytes:
        return json.dumps(
            context, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")


def get_recovery_key_provider() -> RecoveryKeyProvider:
    if settings.AETERNA_RECOVERY_KEY_PROVIDER == "local-test":
        if (
            settings.ENV not in {"development", "test"}
            or settings.AETERNA_RECOVERY_KMS_ENABLED
        ):
            raise RecoveryKeyUnavailable("Recovery key provider is unavailable")
        return InMemoryRecoveryKeyProvider(_local_test_key())
    if (
        settings.AETERNA_RECOVERY_KEY_PROVIDER != "aws-kms"
        or not settings.AETERNA_RECOVERY_KMS_ENABLED
    ):
        raise RecoveryKeyUnavailable("Recovery key provider is unavailable")
    return AwsKmsRecoveryKeyProvider(
        region=settings.AETERNA_RECOVERY_KMS_REGION,
        key_arn=settings.AETERNA_RECOVERY_KMS_KEY_ARN,
    )


def _local_test_key() -> bytes:
    encoded = settings.AETERNA_RECOVERY_LOCAL_TEST_KEY
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is None:
        raise RecoveryKeyUnavailable("Recovery key configuration is invalid")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=")
    except (ValueError, base64.binascii.Error):
        raise RecoveryKeyUnavailable("Recovery key configuration is invalid") from None
    if (
        len(decoded) != SRS_BYTES
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != encoded
    ):
        raise RecoveryKeyUnavailable("Recovery key configuration is invalid")
    return decoded


def validate_recovery_key_configuration() -> None:
    provider = settings.AETERNA_RECOVERY_KEY_PROVIDER
    if provider == "disabled" and not settings.AETERNA_RECOVERY_KMS_ENABLED:
        return
    if (
        provider == "local-test"
        and settings.ENV in {"development", "test"}
        and not settings.AETERNA_RECOVERY_KMS_ENABLED
    ):
        _local_test_key()
        return
    if (
        provider != "aws-kms"
        or not settings.AETERNA_RECOVERY_KMS_ENABLED
        or settings.AETERNA_RECOVERY_KMS_REGION != "ap-southeast-1"
        or SINGLE_REGION_KEY_ARN.fullmatch(settings.AETERNA_RECOVERY_KMS_KEY_ARN)
        is None
    ):
        raise RecoveryKeyUnavailable("Recovery key configuration is invalid")
