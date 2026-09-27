"""Unit evidence for the single-Region recovery KMS boundary."""

import uuid

import pytest

from app.core.config import settings
from app.services.common.aeterna_recovery_key import (
    AwsKmsRecoveryKeyProvider,
    InMemoryRecoveryKeyProvider,
    RecoveryKeyUnavailable,
    recovery_encryption_context,
    validate_recovery_key_configuration,
)

KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-4000-8000-000000000099"
)


class FakeKmsClient:
    def __init__(self):
        self.generate_calls = []
        self.decrypt_calls = []
        self.plaintext = bytes([0x55]) * 32
        self.ciphertext = bytes([0x66]) * 96
        self.key_id = KEY_ARN

    def generate_data_key(self, **kwargs):
        self.generate_calls.append(kwargs)
        return {
            "Plaintext": self.plaintext,
            "CiphertextBlob": self.ciphertext,
            "KeyId": self.key_id,
        }

    def decrypt(self, **kwargs):
        self.decrypt_calls.append(kwargs)
        return {"Plaintext": self.plaintext, "KeyId": self.key_id}


def context():
    return recovery_encryption_context(
        environment="test",
        protocol_version=1,
        account_id=uuid.UUID("00000000-0000-4000-8000-000000000020"),
        device_id=uuid.UUID("00000000-0000-4000-8000-000000000003"),
        vault_id=uuid.UUID("00000000-0000-4000-8000-000000000042"),
        recovery_id=uuid.UUID("00000000-0000-4000-8000-000000000041"),
    )


def test_aws_adapter_uses_exact_key_region_algorithm_and_encryption_context():
    client = FakeKmsClient()
    provider = AwsKmsRecoveryKeyProvider(
        region="ap-southeast-1", key_arn=KEY_ARN, client=client
    )
    expected_context = context()

    generated = provider.generate_srs(expected_context)
    assert generated.plaintext == bytearray(bytes([0x55]) * 32)
    assert generated.ciphertext == client.ciphertext
    assert generated.key_arn == KEY_ARN
    assert client.generate_calls == [
        {
            "KeyId": KEY_ARN,
            "KeySpec": "AES_256",
            "EncryptionContext": expected_context,
        }
    ]

    decrypted = provider.decrypt_srs(client.ciphertext, KEY_ARN, expected_context)
    assert decrypted == bytearray(bytes([0x55]) * 32)
    assert client.decrypt_calls == [
        {
            "CiphertextBlob": client.ciphertext,
            "KeyId": KEY_ARN,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "EncryptionContext": expected_context,
        }
    ]


def test_key_and_context_substitution_and_malformed_provider_results_fail_closed():
    local = InMemoryRecoveryKeyProvider(
        bytes([0x11]) * 32,
        random_bytes=lambda length: bytes([length]) * length,
    )
    envelope = local.generate_srs(context())
    wrong_context = {**context(), "aeterna-binding": "A" * 43}
    with pytest.raises(RecoveryKeyUnavailable):
        local.decrypt_srs(envelope.ciphertext, envelope.key_arn, wrong_context)
    with pytest.raises(RecoveryKeyUnavailable):
        local.decrypt_srs(envelope.ciphertext, "wrong-key", context())

    client = FakeKmsClient()
    client.plaintext = b"short"
    provider = AwsKmsRecoveryKeyProvider(
        region="ap-southeast-1", key_arn=KEY_ARN, client=client
    )
    with pytest.raises(RecoveryKeyUnavailable):
        provider.generate_srs(context())


def test_configuration_accepts_only_the_approved_disabled_or_singapore_boundary(
    monkeypatch,
):
    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KEY_PROVIDER", "disabled")
    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KMS_ENABLED", False)
    validate_recovery_key_configuration()

    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KEY_PROVIDER", "aws-kms")
    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KMS_ENABLED", True)
    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KMS_REGION", "ap-southeast-1")
    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KMS_KEY_ARN", KEY_ARN)
    validate_recovery_key_configuration()

    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KMS_REGION", "ap-southeast-2")
    with pytest.raises(RecoveryKeyUnavailable):
        validate_recovery_key_configuration()

    monkeypatch.setattr(settings, "AETERNA_RECOVERY_KMS_REGION", "ap-southeast-1")
    monkeypatch.setattr(
        settings,
        "AETERNA_RECOVERY_KMS_KEY_ARN",
        "arn:aws:kms:ap-southeast-1:111122223333:key/mrk-example",
    )
    with pytest.raises(RecoveryKeyUnavailable):
        validate_recovery_key_configuration()
