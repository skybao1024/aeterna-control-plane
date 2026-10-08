"""Configuration, cache, and compatibility evidence for identity KMS loading."""

import uuid

import pytest

from app.core.config import settings
from app.services.common import aeterna_security as security
from app.services.common.aeterna_identity_key import (
    IdentityKeyMaterial,
    IdentityKeyProviderUnavailable,
)

KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-4000-8000-000000000001"
)
MATERIAL = IdentityKeyMaterial(b"A" * 32, b"B" * 32, b"C" * 32)


@pytest.fixture
def kms_configuration(monkeypatch):
    fields = {
        "ENV": "production",
        "AETERNA_IDENTITY_KEY_PROVIDER": "aws-kms",
        "AETERNA_IDENTITY_KMS_ENABLED": True,
        "AETERNA_IDENTITY_KMS_REGION": "ap-southeast-1",
        "AETERNA_IDENTITY_KMS_KEY_ARN": KEY_ARN,
        "AETERNA_IDENTITY_KMS_ENVELOPE_PATH": "/synthetic/envelope.json",
        "AETERNA_RECOVERY_KMS_KEY_ARN": "",
        "AETERNA_PII_KEY_V1": "",
        "AETERNA_LOOKUP_KEY_V1": "",
        "AETERNA_OTP_KEY_V1": "",
    }
    for name, value in fields.items():
        monkeypatch.setattr(settings, name, value)
    calls = []

    class FakeProvider:
        def load_keys(self, path):
            calls.append(path)
            return MATERIAL

    monkeypatch.setattr(security, "get_identity_key_provider", FakeProvider)
    security.clear_identity_key_cache()
    yield calls
    security.clear_identity_key_cache()


def test_startup_and_requests_share_only_a_complete_successful_keyset(
    kms_configuration,
):
    security.validate_identity_key_configuration()
    keys = security.get_identity_keys()
    assert keys.pii_key == MATERIAL.pii_key
    assert keys.lookup_key == MATERIAL.lookup_key
    assert keys.otp_key == MATERIAL.otp_key
    assert security.get_identity_keys() is keys
    assert kms_configuration == ["/synthetic/envelope.json"]
    assert "AAAAAAAA" not in repr(keys)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("AETERNA_IDENTITY_KEY_PROVIDER", "environment"),
        ("AETERNA_IDENTITY_KMS_ENABLED", False),
        ("AETERNA_PII_KEY_V1", "synthetic-plaintext"),
        ("AETERNA_LOOKUP_KEY_V1", "synthetic-plaintext"),
        ("AETERNA_OTP_KEY_V1", "synthetic-plaintext"),
    ],
)
def test_bad_configuration_is_not_hidden_by_cached_keys(
    kms_configuration, monkeypatch, field, value
):
    security.get_identity_keys()
    monkeypatch.setattr(settings, field, value)
    with pytest.raises(security.IdentityKeyUnavailable):
        security.validate_identity_key_configuration()
    assert len(kms_configuration) == 1


def test_process_identity_prevents_prefork_cache_reuse(kms_configuration, monkeypatch):
    monkeypatch.setattr(security.os, "getpid", lambda: 1000)
    security.get_identity_keys()
    monkeypatch.setattr(security.os, "getpid", lambda: 1001)
    security.get_identity_keys()
    assert len(kms_configuration) == 2


def test_failed_loading_after_cache_clear_never_uses_old_keys_or_caches_failures(
    kms_configuration, monkeypatch
):
    security.get_identity_keys()
    security.clear_identity_key_cache()

    class UnavailableProvider:
        def load_keys(self, path):
            raise IdentityKeyProviderUnavailable("synthetic-private-provider-detail")

    monkeypatch.setattr(security, "get_identity_key_provider", UnavailableProvider)
    for _ in range(2):
        with pytest.raises(security.IdentityKeyUnavailable) as raised:
            security.get_identity_keys()
        assert "synthetic-private-provider-detail" not in str(raised.value)

    class RecoveredProvider:
        def load_keys(self, path):
            return MATERIAL

    monkeypatch.setattr(security, "get_identity_key_provider", RecoveredProvider)
    assert security.get_identity_keys().pii_key == MATERIAL.pii_key


def test_preview_requires_kms_and_rejects_plaintext(kms_configuration, monkeypatch):
    monkeypatch.setattr(settings, "ENV", "preview")
    security.validate_identity_key_configuration()
    monkeypatch.setattr(settings, "AETERNA_PII_KEY_V1", "synthetic-plaintext")
    with pytest.raises(security.IdentityKeyUnavailable):
        security.get_identity_keys()


def test_fork_reset_drops_parent_keys_and_replaces_a_held_lock(kms_configuration):
    security.get_identity_keys()
    parent_lock = security._identity_key_cache_lock
    with parent_lock:
        security._reset_identity_key_cache_after_fork()
        security.get_identity_keys()
    assert security._identity_key_cache_lock is not parent_lock
    assert len(kms_configuration) == 2


def test_restart_preserves_pii_lookup_and_token_crypto(kms_configuration):
    keys = security.get_identity_keys()
    owner_id = uuid.UUID("00000000-0000-4000-8000-000000000010")
    email = "synthetic@example.com"
    encrypted, nonce, version = security.encrypt_email(keys, email, "account", owner_id)
    lookup = security.email_lookup(keys, email)
    token = security.derive_invitation_token(keys, owner_id)
    security.clear_identity_key_cache()
    restarted = security.get_identity_keys()
    assert (
        security.decrypt_email(
            restarted, encrypted, nonce, "account", owner_id, version
        )
        == email
    )
    assert security.email_lookup(restarted, email) == lookup
    assert security.derive_invitation_token(restarted, owner_id) == token
    assert len(kms_configuration) == 2


@pytest.mark.parametrize("environment", ["development", "test"])
def test_empty_development_configuration_remains_allowed(
    kms_configuration, monkeypatch, environment
):
    monkeypatch.setattr(settings, "ENV", environment)
    monkeypatch.setattr(settings, "AETERNA_IDENTITY_KEY_PROVIDER", "environment")
    monkeypatch.setattr(settings, "AETERNA_IDENTITY_KMS_ENABLED", False)
    security.validate_identity_key_configuration()
    assert not kms_configuration
