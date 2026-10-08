"""Cryptographic boundary for Aeterna account identity protocol v1."""

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import threading
import unicodedata
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from email_validator import EmailNotValidError, validate_email

from app.core.config import settings
from app.services.common.aeterna_identity_key import (
    IdentityKeyProviderUnavailable,
    get_identity_key_provider,
)

_identity_key_cache_lock = threading.Lock()


class IdentityKeyUnavailable(RuntimeError):
    """Raised without secret material when the identity key provider is unavailable."""


class InvalidEmail(ValueError):
    """Raised when an email cannot be normalized within the public bound."""


@dataclass(frozen=True, slots=True)
class AeternaIdentityKeys:
    pii_key: bytes = field(repr=False)
    lookup_key: bytes = field(repr=False)
    otp_key: bytes = field(repr=False)
    version: int = 1


def _decode_key(value: str) -> bytes:
    if len(value) != 43 or "=" in value:
        raise IdentityKeyUnavailable("A required identity key is unavailable")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        raise IdentityKeyUnavailable("A required identity key is unavailable") from None
    if (
        len(decoded) != 32
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value
    ):
        raise IdentityKeyUnavailable("A required identity key is unavailable")
    return decoded


def get_identity_keys() -> AeternaIdentityKeys:
    """Load stable application keys without a production plaintext fallback."""
    configured_values = (
        settings.AETERNA_PII_KEY_V1,
        settings.AETERNA_LOOKUP_KEY_V1,
        settings.AETERNA_OTP_KEY_V1,
    )
    if settings.ENV in {"production", "preview"}:
        if (
            settings.AETERNA_IDENTITY_KEY_PROVIDER != "aws-kms"
            or not settings.AETERNA_IDENTITY_KMS_ENABLED
            or any(configured_values)
        ):
            raise IdentityKeyUnavailable(
                "Production and preview identity require a configured KMS/HSM "
                "provider without plaintext environment keys"
            )
        try:
            # Startup loads once; request handlers do not make blocking KMS calls.
            # Prefork children must load their own complete keyset.
            with _identity_key_cache_lock:
                return _load_kms_identity_keys(
                    settings.ENV,
                    settings.AETERNA_IDENTITY_KMS_REGION,
                    settings.AETERNA_IDENTITY_KMS_KEY_ARN,
                    settings.AETERNA_IDENTITY_KMS_ENVELOPE_PATH,
                    settings.AETERNA_RECOVERY_KMS_KEY_ARN,
                    os.getpid(),
                )
        except IdentityKeyProviderUnavailable:
            raise IdentityKeyUnavailable("Identity KMS key loading failed") from None
    if (
        settings.ENV not in {"development", "test"}
        or settings.AETERNA_IDENTITY_KEY_PROVIDER != "environment"
        or settings.AETERNA_IDENTITY_KMS_ENABLED
    ):
        raise IdentityKeyUnavailable(
            "Identity key provider configuration is unavailable"
        )
    return AeternaIdentityKeys(
        pii_key=_decode_key(settings.AETERNA_PII_KEY_V1),
        lookup_key=_decode_key(settings.AETERNA_LOOKUP_KEY_V1),
        otp_key=_decode_key(settings.AETERNA_OTP_KEY_V1),
    )


@lru_cache(maxsize=1)
def _load_kms_identity_keys(
    environment: str,
    region: str,
    key_arn: str,
    envelope_path: str,
    recovery_key_arn: str,
    process_id: int,
) -> AeternaIdentityKeys:
    """Cache a complete successful keyset under its non-secret configuration."""
    material = get_identity_key_provider().load_keys(envelope_path)
    return AeternaIdentityKeys(
        pii_key=material.pii_key,
        lookup_key=material.lookup_key,
        otp_key=material.otp_key,
        version=material.version,
    )


def clear_identity_key_cache() -> None:
    """Drop cached key references when the application shuts down."""
    with _identity_key_cache_lock:
        _load_kms_identity_keys.cache_clear()


def _reset_identity_key_cache_after_fork() -> None:
    """Discard parent keys and a potentially held parent lock in a child."""
    global _identity_key_cache_lock
    _identity_key_cache_lock = threading.Lock()
    _load_kms_identity_keys.cache_clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_identity_key_cache_after_fork)


def validate_identity_key_configuration() -> None:
    """Validate identity keys before serving traffic; fail closed on KMS errors."""
    configured_values = (
        settings.AETERNA_PII_KEY_V1,
        settings.AETERNA_LOOKUP_KEY_V1,
        settings.AETERNA_OTP_KEY_V1,
    )
    if (
        settings.ENV not in {"development", "test"}
        or settings.AETERNA_IDENTITY_KEY_PROVIDER != "environment"
        or settings.AETERNA_IDENTITY_KMS_ENABLED
        or any(configured_values)
    ):
        get_identity_keys()


def normalize_email(value: str) -> str:
    try:
        normalized = validate_email(value, check_deliverability=False).normalized
    except EmailNotValidError:
        raise InvalidEmail from None
    if len(normalized.encode("utf-8")) > 254:
        raise InvalidEmail
    return normalized


def validate_device_label(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        value != unicodedata.normalize("NFC", value)
        or not value
        or len(value.encode("utf-8")) > 64
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise ValueError("Invalid device label")
    return value


def email_lookup(keys: AeternaIdentityKeys, normalized_email: str) -> bytes:
    return hmac.new(
        keys.lookup_key,
        b"aeterna:email-lookup:v1\x00" + normalized_email.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def ip_lookup(keys: AeternaIdentityKeys, address: str) -> bytes:
    return hmac.new(
        keys.lookup_key,
        b"aeterna:request-ip:v1\x00" + address.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _email_aad(owner_type: str, owner_id: uuid.UUID, key_version: int) -> bytes:
    return f"aeterna:{owner_type}-email:v1:{key_version}:{owner_id}".encode()


def encrypt_email(
    keys: AeternaIdentityKeys,
    normalized_email: str,
    owner_type: str,
    owner_id: uuid.UUID,
    nonce_factory: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[bytes, bytes, int]:
    nonce = nonce_factory(12)
    if len(nonce) != 12:
        raise ValueError("The nonce source returned an invalid length")
    ciphertext = AESGCM(keys.pii_key).encrypt(
        nonce,
        normalized_email.encode("utf-8"),
        _email_aad(owner_type, owner_id, keys.version),
    )
    return ciphertext, nonce, keys.version


def decrypt_email(
    keys: AeternaIdentityKeys,
    ciphertext: bytes,
    nonce: bytes,
    owner_type: str,
    owner_id: uuid.UUID,
    key_version: int,
) -> str:
    if key_version != keys.version:
        raise IdentityKeyUnavailable("The required identity key version is unavailable")
    plaintext = AESGCM(keys.pii_key).decrypt(
        nonce, ciphertext, _email_aad(owner_type, owner_id, key_version)
    )
    return plaintext.decode("utf-8", errors="strict")


def _private_text_aad(purpose: str, owner_id: uuid.UUID, key_version: int) -> bytes:
    return f"aeterna:private-text:v1:{purpose}:{key_version}:{owner_id}".encode()


def encrypt_private_text(
    keys: AeternaIdentityKeys,
    plaintext: str,
    purpose: str,
    owner_id: uuid.UUID,
    nonce_factory: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[bytes, bytes, int]:
    """Encrypt a bounded text field under purpose-bound authenticated data."""

    nonce = nonce_factory(12)
    if len(nonce) != 12:
        raise ValueError("The nonce source returned an invalid length")
    ciphertext = AESGCM(keys.pii_key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        _private_text_aad(purpose, owner_id, keys.version),
    )
    return ciphertext, nonce, keys.version


def decrypt_private_text(
    keys: AeternaIdentityKeys,
    ciphertext: bytes,
    nonce: bytes,
    purpose: str,
    owner_id: uuid.UUID,
    key_version: int,
) -> str:
    """Decrypt a purpose-bound text field without logging its plaintext."""

    if key_version != keys.version:
        raise IdentityKeyUnavailable("The required identity key version is unavailable")
    plaintext = AESGCM(keys.pii_key).decrypt(
        nonce,
        ciphertext,
        _private_text_aad(purpose, owner_id, key_version),
    )
    return plaintext.decode("utf-8", errors="strict")


def derive_invitation_token(
    keys: AeternaIdentityKeys,
    invitation_id: uuid.UUID,
    key_version: int | None = None,
) -> str:
    """Derive a secret invitation token while storing only its verifier."""

    selected_version = key_version or keys.version
    if selected_version != keys.version:
        raise IdentityKeyUnavailable("The required identity key version is unavailable")
    raw = hmac.new(
        keys.otp_key,
        f"aeterna:contact-invitation:v1:{selected_version}:{invitation_id}".encode(),
        hashlib.sha256,
    ).digest()
    return encode_base64url(raw)


def derive_recovery_link_token(
    keys: AeternaIdentityKeys,
    link_id: uuid.UUID,
    key_version: int | None = None,
) -> str:
    """Derive a secret fragment token while storing only its verifier."""

    selected_version = key_version or keys.version
    if selected_version != keys.version:
        raise IdentityKeyUnavailable("The required identity key version is unavailable")
    raw = hmac.new(
        keys.otp_key,
        f"aeterna:recovery-claim-link:v1:{selected_version}:{link_id}".encode(),
        hashlib.sha256,
    ).digest()
    return encode_base64url(raw)


def derive_recovery_otp(
    keys: AeternaIdentityKeys,
    challenge_id: uuid.UUID,
    key_version: int | None = None,
) -> str:
    """Derive a bounded challenge code so no plaintext OTP is persisted."""

    selected_version = key_version or keys.version
    if selected_version != keys.version:
        raise IdentityKeyUnavailable("The required identity key version is unavailable")
    digest = hmac.new(
        keys.otp_key,
        f"aeterna:recovery-otp-code:v1:{selected_version}:{challenge_id}".encode(),
        hashlib.sha256,
    ).digest()
    return f"{int.from_bytes(digest[:8], 'big') % 100_000_000:08d}"


def otp_verifier(
    keys: AeternaIdentityKeys, challenge_id: uuid.UUID, purpose: str, code: str
) -> bytes:
    message = f"aeterna:otp:v1:{challenge_id}:{purpose}:{code}".encode()
    return hmac.new(keys.otp_key, message, hashlib.sha256).digest()


def verify_otp(
    keys: AeternaIdentityKeys,
    challenge_id: uuid.UUID,
    purpose: str,
    code: str,
    expected: bytes,
) -> bool:
    return hmac.compare_digest(
        otp_verifier(keys, challenge_id, purpose, code), expected
    )


def make_otp() -> str:
    return f"{secrets.randbelow(100_000_000):08d}"


def make_token() -> tuple[str, bytes]:
    raw = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return encoded, hashlib.sha256(raw).digest()


def token_digest(encoded: str) -> bytes:
    raw = decode_base64url(encoded, 32)
    return hashlib.sha256(raw).digest()


def decode_base64url(value: str, expected_length: int) -> bytes:
    expected_encoded_length = (expected_length * 8 + 5) // 6
    if len(value) != expected_encoded_length or "=" in value:
        raise ValueError("Invalid base64url encoding")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error):
        raise ValueError("Invalid base64url encoding") from None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode()
    if len(decoded) != expected_length or canonical != value:
        raise ValueError("Invalid base64url encoding")
    return decoded


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def canonicalize(document: object) -> bytes:
    return rfc8785.dumps(document)


def request_digest(document: object) -> bytes:
    return hashlib.sha256(canonicalize(document)).digest()


def private_request_digest(keys: AeternaIdentityKeys, document: object) -> bytes:
    """Digest a request containing PII without creating an offline lookup oracle."""
    return hmac.new(
        keys.lookup_key,
        b"aeterna:private-request:v1\x00" + canonicalize(document),
        hashlib.sha256,
    ).digest()


def verify_signature(public_key: bytes, signed: dict, signature: str) -> bool:
    try:
        signature_bytes = decode_base64url(signature, 64)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, canonicalize(signed)
        )
    except (InvalidSignature, ValueError):
        return False
    return True
