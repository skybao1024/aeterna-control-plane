"""AWS KMS envelope boundary for persistent Aeterna identity key material."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

import boto3
from botocore.config import Config

from app.core.config import settings

IDENTITY_SCHEMA_VERSION = 1
IDENTITY_CONTEXT_VERSION = 1
IDENTITY_KEY_VERSION = 1
IDENTITY_KEY_BYTES = 32
MAX_IDENTITY_CIPHERTEXT_BYTES = 6144
MAX_IDENTITY_ENVELOPE_BYTES = 32768
IDENTITY_PURPOSES = ("pii", "lookup", "otp")
IDENTITY_KEY_ERROR = "Identity KMS key material is unavailable"
IDENTITY_SINGLE_REGION_KEY_ARN = re.compile(
    r"arn:aws:kms:(?P<region>[a-z]{2}-[a-z]+-[0-9]+):[0-9]{12}:key/"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class IdentityKeyProviderUnavailable(RuntimeError):
    """Raised without AWS diagnostics, ciphertext, or plaintext key material."""


@dataclass(frozen=True, slots=True)
class IdentityKeyMaterial:
    """Three independent application keys whose representation hides plaintext."""

    pii_key: bytes = field(repr=False)
    lookup_key: bytes = field(repr=False)
    otp_key: bytes = field(repr=False)
    version: int = IDENTITY_KEY_VERSION


def identity_encryption_context(*, environment: str, purpose: str) -> dict[str, str]:
    """Bind ciphertext to one environment, purpose, and supported key version."""
    if (
        not isinstance(environment, str)
        or environment not in {"production", "preview"}
        or purpose not in IDENTITY_PURPOSES
    ):
        raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
    return {
        "aeterna-purpose": f"identity-{purpose}",
        "aeterna-environment": environment,
        "aeterna-context-version": str(IDENTITY_CONTEXT_VERSION),
        "aeterna-key-version": str(IDENTITY_KEY_VERSION),
    }


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
        result[name] = value
    return result


def _decode_ciphertext(value: object) -> bytes:
    if not isinstance(value, str) or not 0 < len(value) <= 8192:
        raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
    try:
        ciphertext = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR) from None
    if (
        not 0 < len(ciphertext) <= MAX_IDENTITY_CIPHERTEXT_BYTES
        or base64.b64encode(ciphertext).decode("ascii") != value
    ):
        raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
    return ciphertext


class AwsKmsIdentityKeyProvider:
    """Decrypt a stable ciphertext-only envelope using one exact AWS KMS key."""

    def __init__(
        self,
        *,
        region: str,
        key_arn: str,
        environment: str,
        recovery_key_arn: str = "",
        client=None,
    ):
        match = (
            IDENTITY_SINGLE_REGION_KEY_ARN.fullmatch(key_arn)
            if isinstance(key_arn, str)
            else None
        )
        if (
            match is None
            or match.group("region") != region
            or not isinstance(environment, str)
            or environment not in {"production", "preview"}
            or not isinstance(recovery_key_arn, str)
            or key_arn.lower() == recovery_key_arn.lower()
        ):
            raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
        self.region = region
        self.key_arn = key_arn
        self.environment = environment
        try:
            self.client = (
                client
                if client is not None
                else boto3.client(
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
            )
        except Exception:
            raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR) from None

    def generate_envelope(self) -> dict:
        """Provision encrypted data keys once without receiving plaintext keys."""
        keys = {}
        ciphertexts = set()
        for purpose in IDENTITY_PURPOSES:
            context = identity_encryption_context(
                environment=self.environment, purpose=purpose
            )
            try:
                response = self.client.generate_data_key_without_plaintext(
                    KeyId=self.key_arn,
                    KeySpec="AES_256",
                    EncryptionContext=context,
                )
                ciphertext = response["CiphertextBlob"]
                valid_response = (
                    response["KeyId"] == self.key_arn
                    and "Plaintext" not in response
                    and isinstance(ciphertext, (bytes, bytearray))
                    and 0 < len(ciphertext) <= MAX_IDENTITY_CIPHERTEXT_BYTES
                )
            except Exception:
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR) from None
            if not valid_response or bytes(ciphertext) in ciphertexts:
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
            ciphertexts.add(bytes(ciphertext))
            keys[purpose] = {
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "encryption_context": context,
            }
        return {
            "schema_version": IDENTITY_SCHEMA_VERSION,
            "context_version": IDENTITY_CONTEXT_VERSION,
            "key_version": IDENTITY_KEY_VERSION,
            "environment": self.environment,
            "key_arn": self.key_arn,
            "keys": keys,
        }

    def load_keys(self, envelope_path: str | Path) -> IdentityKeyMaterial:
        """Validate the complete envelope before asking KMS to decrypt any key."""
        ciphertexts = self._read_envelope(envelope_path)
        plaintexts = []
        for purpose, ciphertext in zip(IDENTITY_PURPOSES, ciphertexts, strict=True):
            context = identity_encryption_context(
                environment=self.environment, purpose=purpose
            )
            try:
                response = self.client.decrypt(
                    CiphertextBlob=ciphertext,
                    KeyId=self.key_arn,
                    EncryptionAlgorithm="SYMMETRIC_DEFAULT",
                    EncryptionContext=context,
                )
                plaintext = response["Plaintext"]
                valid_response = (
                    response["KeyId"] == self.key_arn
                    and response["EncryptionAlgorithm"] == "SYMMETRIC_DEFAULT"
                    and isinstance(plaintext, (bytes, bytearray))
                    and len(plaintext) == IDENTITY_KEY_BYTES
                )
            except Exception:
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR) from None
            if not valid_response or bytes(plaintext) in plaintexts:
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
            plaintexts.append(bytes(plaintext))
        return IdentityKeyMaterial(
            pii_key=plaintexts[0],
            lookup_key=plaintexts[1],
            otp_key=plaintexts[2],
        )

    def _read_envelope(self, envelope_path: str | Path) -> tuple[bytes, ...]:
        try:
            descriptor = os.open(envelope_path, os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
                raw = handle.read(MAX_IDENTITY_ENVELOPE_BYTES + 1)
            if not 0 < len(raw) <= MAX_IDENTITY_ENVELOPE_BYTES:
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
            envelope = json.loads(raw, object_pairs_hook=_unique_json_object)
            return self._validate_envelope(envelope)
        except Exception:
            raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR) from None

    def _validate_envelope(self, envelope: object) -> tuple[bytes, ...]:
        expected_fields = {
            "schema_version",
            "context_version",
            "key_version",
            "environment",
            "key_arn",
            "keys",
        }
        if not isinstance(envelope, dict) or set(envelope) != expected_fields:
            raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
        for name, expected in (
            ("schema_version", IDENTITY_SCHEMA_VERSION),
            ("context_version", IDENTITY_CONTEXT_VERSION),
            ("key_version", IDENTITY_KEY_VERSION),
        ):
            if type(envelope[name]) is not int or envelope[name] != expected:
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
        if (
            envelope["environment"] != self.environment
            or envelope["key_arn"] != self.key_arn
            or not isinstance(envelope["keys"], dict)
            or set(envelope["keys"]) != set(IDENTITY_PURPOSES)
        ):
            raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
        ciphertexts = []
        for purpose in IDENTITY_PURPOSES:
            entry = envelope["keys"][purpose]
            if (
                not isinstance(entry, dict)
                or set(entry) != {"ciphertext", "encryption_context"}
                or entry["encryption_context"]
                != identity_encryption_context(
                    environment=self.environment, purpose=purpose
                )
            ):
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
            ciphertext = _decode_ciphertext(entry["ciphertext"])
            if ciphertext in ciphertexts:
                raise IdentityKeyProviderUnavailable(IDENTITY_KEY_ERROR)
            ciphertexts.append(ciphertext)
        return tuple(ciphertexts)


def get_identity_key_provider() -> AwsKmsIdentityKeyProvider:
    """Assemble the provider after the caller validates its selection policy."""
    return AwsKmsIdentityKeyProvider(
        region=settings.AETERNA_IDENTITY_KMS_REGION,
        key_arn=settings.AETERNA_IDENTITY_KMS_KEY_ARN,
        environment=settings.ENV,
        recovery_key_arn=settings.AETERNA_RECOVERY_KMS_KEY_ARN,
    )
