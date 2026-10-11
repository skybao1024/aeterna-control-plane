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
import httpx
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KMS_CONTEXT_VERSION = 1
SRS_BYTES = 32
MAX_CIPHERTEXT_BYTES = 8192
KMS_BINDING_DOMAIN = b"AETERNA-KMS-SRS-BINDING-v1\x00"
DEFAULT_PROVISIONER_SOCKET = "/app/recovery-provisioner/provisioner.sock"
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


class RecoveryProvisionProvider(Protocol):
    def generate_srs(self, context: dict[str, str]) -> GeneratedSrsEnvelope: ...


class RecoveryClaimProvider(Protocol):
    def decrypt_srs(
        self, ciphertext: bytes, key_arn: str, context: dict[str, str]
    ) -> bytearray: ...


class RecoveryKeyProvider(RecoveryProvisionProvider, RecoveryClaimProvider, Protocol):
    """Combined provider contract retained only for local deterministic tests."""


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
        try:
            self.client = client or boto3.client(
                "kms",
                region_name=region,
                endpoint_url=f"https://kms.{region}.amazonaws.com",
                config=Config(
                    region_name=region,
                    signature_version="v4",
                    connect_timeout=3,
                    read_timeout=5,
                    retries={"total_max_attempts": 2, "mode": "standard"},
                    ignore_configured_endpoint_urls=True,
                ),
            )
        except Exception:
            raise RecoveryKeyUnavailable(
                "Recovery key provider is unavailable"
            ) from None

    def generate_srs(self, context: dict[str, str]) -> GeneratedSrsEnvelope:
        validate_recovery_encryption_context(context)
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
        validate_recovery_encryption_context(context)
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
        validate_recovery_encryption_context(context)
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
        validate_recovery_encryption_context(context)
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


class UnixSocketRecoveryProvisionProvider:
    """Generate recovery material through the isolated provisioner workload."""

    def __init__(
        self,
        *,
        socket_path: str,
        key_arn: str,
        transport: httpx.BaseTransport | None = None,
    ):
        if (
            not _valid_socket_path(socket_path)
            or SINGLE_REGION_KEY_ARN.fullmatch(key_arn) is None
        ):
            raise RecoveryKeyUnavailable("Recovery key provider is unavailable")
        self.socket_path = socket_path
        self.key_arn = key_arn
        self.transport = transport

    def generate_srs(self, context: dict[str, str]) -> GeneratedSrsEnvelope:
        validate_recovery_encryption_context(context)
        transport = self.transport or httpx.HTTPTransport(uds=self.socket_path)
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://recovery-provisioner",
                timeout=httpx.Timeout(8.0),
            ) as client:
                response = client.post("/v1/generate", json={"context": context})
                response.raise_for_status()
                payload = response.json()
        except Exception:
            raise RecoveryKeyUnavailable("Recovery key operation failed") from None
        if not isinstance(payload, dict) or set(payload) != {
            "ciphertext",
            "key_arn",
            "key_material_id",
            "plaintext",
        }:
            raise RecoveryKeyUnavailable("Recovery key operation failed")
        plaintext = bytearray(
            _decode_canonical_base64url(payload.get("plaintext"), SRS_BYTES)
        )
        try:
            ciphertext = _decode_canonical_base64(
                payload.get("ciphertext"), MAX_CIPHERTEXT_BYTES
            )
            key_arn = payload.get("key_arn")
            key_material_id = payload.get("key_material_id")
            if (
                key_arn != self.key_arn
                or key_material_id != self.key_arn
                or not ciphertext
            ):
                raise RecoveryKeyUnavailable("Recovery key operation failed")
        except RecoveryKeyUnavailable:
            plaintext[:] = b"\x00" * len(plaintext)
            raise
        return GeneratedSrsEnvelope(
            plaintext=plaintext,
            ciphertext=ciphertext,
            key_arn=key_arn,
            key_material_id=key_material_id,
        )


def _decode_canonical_base64url(value: object, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != 43 or "=" in value:
        raise RecoveryKeyUnavailable("Recovery key operation failed")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, base64.binascii.Error):
        raise RecoveryKeyUnavailable("Recovery key operation failed") from None
    if (
        len(decoded) != length
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise RecoveryKeyUnavailable("Recovery key operation failed")
    return decoded


def _decode_canonical_base64(value: object, maximum_length: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise RecoveryKeyUnavailable("Recovery key operation failed")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        raise RecoveryKeyUnavailable("Recovery key operation failed") from None
    if (
        not 0 < len(decoded) <= maximum_length
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise RecoveryKeyUnavailable("Recovery key operation failed")
    return decoded


def validate_recovery_encryption_context(
    context: dict[str, str], *, environment: str | None = None
) -> None:
    if not isinstance(context, dict) or set(context) != {
        "aeterna-purpose",
        "aeterna-environment",
        "aeterna-context-version",
        "aeterna-binding",
    }:
        raise RecoveryKeyUnavailable("Recovery key operation failed")
    expected_environment = environment or context.get("aeterna-environment")
    if (
        context.get("aeterna-purpose") != "recovery-srs"
        or context.get("aeterna-environment") != expected_environment
        or context.get("aeterna-context-version") != str(KMS_CONTEXT_VERSION)
    ):
        raise RecoveryKeyUnavailable("Recovery key operation failed")
    _decode_canonical_base64url(context.get("aeterna-binding"), 32)


def _valid_socket_path(value: object) -> bool:
    return value == DEFAULT_PROVISIONER_SOCKET


def _settings():
    from app.core.config import settings

    return settings


def _local_provider() -> InMemoryRecoveryKeyProvider:
    settings = _settings()
    if (
        settings.ENV not in {"development", "test"}
        or settings.AETERNA_RECOVERY_KMS_ENABLED
    ):
        raise RecoveryKeyUnavailable("Recovery key provider is unavailable")
    return InMemoryRecoveryKeyProvider(_local_test_key())


def get_recovery_provision_provider() -> RecoveryProvisionProvider:
    settings = _settings()
    if settings.AETERNA_RECOVERY_KEY_PROVIDER == "local-test":
        return _local_provider()
    if (
        settings.AETERNA_RECOVERY_KEY_PROVIDER != "aws-kms"
        or not settings.AETERNA_RECOVERY_KMS_ENABLED
        or settings.ENV not in {"production", "preview"}
    ):
        raise RecoveryKeyUnavailable("Recovery key provider is unavailable")
    return UnixSocketRecoveryProvisionProvider(
        socket_path=settings.AETERNA_RECOVERY_PROVISIONER_SOCKET,
        key_arn=settings.AETERNA_RECOVERY_KMS_KEY_ARN,
    )


def get_recovery_claim_provider() -> RecoveryClaimProvider:
    settings = _settings()
    if settings.AETERNA_RECOVERY_KEY_PROVIDER == "local-test":
        return _local_provider()
    if (
        settings.AETERNA_RECOVERY_KEY_PROVIDER != "aws-kms"
        or not settings.AETERNA_RECOVERY_KMS_ENABLED
        or settings.ENV not in {"production", "preview"}
    ):
        raise RecoveryKeyUnavailable("Recovery key provider is unavailable")
    return AwsKmsRecoveryKeyProvider(
        region=settings.AETERNA_RECOVERY_KMS_REGION,
        key_arn=settings.AETERNA_RECOVERY_KMS_KEY_ARN,
    )


def get_recovery_key_provider() -> RecoveryKeyProvider:
    settings = _settings()
    if settings.AETERNA_RECOVERY_KEY_PROVIDER == "local-test":
        return _local_provider()
    raise RecoveryKeyUnavailable("Combined recovery key provider is unavailable")


def _local_test_key() -> bytes:
    settings = _settings()
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
    settings = _settings()
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
        or settings.ENV not in {"production", "preview"}
        or settings.AETERNA_RECOVERY_KMS_REGION != "ap-southeast-1"
        or SINGLE_REGION_KEY_ARN.fullmatch(settings.AETERNA_RECOVERY_KMS_KEY_ARN)
        is None
        or not _valid_socket_path(settings.AETERNA_RECOVERY_PROVISIONER_SOCKET)
    ):
        raise RecoveryKeyUnavailable("Recovery key configuration is invalid")
