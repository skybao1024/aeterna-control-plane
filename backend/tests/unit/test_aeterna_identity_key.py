"""Security-boundary evidence for persistent AWS KMS identity key envelopes."""

import base64
import json

import pytest

from app.services.common.aeterna_identity_key import (
    IDENTITY_KEY_ERROR,
    IDENTITY_PURPOSES,
    MAX_IDENTITY_CIPHERTEXT_BYTES,
    MAX_IDENTITY_ENVELOPE_BYTES,
    AwsKmsIdentityKeyProvider,
    IdentityKeyProviderUnavailable,
    identity_encryption_context,
)

KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-4000-8000-000000000001"
)
OTHER_KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/00000000-0000-4000-8000-000000000002"
)


class FakeKmsClient:
    """A context-checking fake that has no plaintext-generating operation."""

    def __init__(self):
        self.generate_calls = []
        self.decrypt_calls = []
        self.generated_response_changes = {}
        self.decrypted_response_changes = {}
        self.generate_error = None
        self.decrypt_error = None
        self.plaintexts = {
            purpose: bytes([index + 1]) * 32
            for index, purpose in enumerate(IDENTITY_PURPOSES)
        }

    def generate_data_key_without_plaintext(self, **kwargs):
        self.generate_calls.append(kwargs)
        if self.generate_error is not None:
            raise self.generate_error
        purpose = kwargs["EncryptionContext"]["aeterna-purpose"].removeprefix(
            "identity-"
        )
        return {
            "KeyId": KEY_ARN,
            "CiphertextBlob": self.ciphertext(
                purpose, kwargs["EncryptionContext"]["aeterna-environment"]
            ),
            **self.generated_response_changes,
        }

    def decrypt(self, **kwargs):
        self.decrypt_calls.append(kwargs)
        if self.decrypt_error is not None:
            raise self.decrypt_error
        purpose = kwargs["EncryptionContext"]["aeterna-purpose"].removeprefix(
            "identity-"
        )
        assert kwargs["CiphertextBlob"] == self.ciphertext(
            purpose, kwargs["EncryptionContext"]["aeterna-environment"]
        )
        return {
            "KeyId": KEY_ARN,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "Plaintext": self.plaintexts[purpose],
            **self.decrypted_response_changes,
        }

    def ciphertext(self, purpose, environment="production"):
        return f"synthetic-{environment}-wrapped-{purpose}".encode("ascii")


def make_provider(client=None, **changes):
    return AwsKmsIdentityKeyProvider(
        **{
            "region": "ap-southeast-1",
            "key_arn": KEY_ARN,
            "environment": "production",
            "recovery_key_arn": OTHER_KEY_ARN,
            "client": client if client is not None else FakeKmsClient(),
            **changes,
        }
    )


def write_envelope(tmp_path, envelope):
    path = tmp_path / "envelope.json"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return path


def test_provisioning_receives_only_ciphertext_and_binds_each_purpose():
    client = FakeKmsClient()
    envelope = make_provider(client).generate_envelope()

    assert set(envelope["keys"]) == set(IDENTITY_PURPOSES)
    assert client.decrypt_calls == []
    assert client.generate_calls == [
        {
            "KeyId": KEY_ARN,
            "KeySpec": "AES_256",
            "EncryptionContext": identity_encryption_context(
                environment="production", purpose=purpose
            ),
        }
        for purpose in IDENTITY_PURPOSES
    ]
    serialized = json.dumps(envelope)
    assert "Plaintext" not in serialized
    for plaintext in client.plaintexts.values():
        assert base64.b64encode(plaintext).decode("ascii") not in serialized


def test_restart_decrypts_the_same_independent_keys_without_generation(tmp_path):
    provisioner = FakeKmsClient()
    path = write_envelope(tmp_path, make_provider(provisioner).generate_envelope())
    first_client = FakeKmsClient()
    restarted_client = FakeKmsClient()

    first = make_provider(first_client).load_keys(path)
    restarted = make_provider(restarted_client).load_keys(path)

    assert first == restarted
    assert first.pii_key == provisioner.plaintexts["pii"]
    assert first.lookup_key == provisioner.plaintexts["lookup"]
    assert first.otp_key == provisioner.plaintexts["otp"]
    assert first.version == 1
    assert len({first.pii_key, first.lookup_key, first.otp_key}) == 3
    assert first_client.generate_calls == restarted_client.generate_calls == []
    assert first_client.decrypt_calls == restarted_client.decrypt_calls
    assert first_client.decrypt_calls == [
        {
            "CiphertextBlob": provisioner.ciphertext(purpose),
            "KeyId": KEY_ARN,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "EncryptionContext": identity_encryption_context(
                environment="production", purpose=purpose
            ),
        }
        for purpose in IDENTITY_PURPOSES
    ]
    assert "pii_key" not in repr(first)
    assert repr(first.pii_key) not in repr(first)


@pytest.mark.parametrize(
    "field,value",
    [
        ("environment", "preview"),
        ("key_arn", OTHER_KEY_ARN),
        ("key_version", 2),
        ("key_version", True),
        ("context_version", 2),
        ("context_version", "1"),
        ("schema_version", 2),
        ("schema_version", True),
        ("keys", []),
    ],
)
def test_envelope_metadata_substitution_is_rejected_before_decrypt(
    tmp_path, field, value
):
    client = FakeKmsClient()
    provider = make_provider(client)
    envelope = provider.generate_envelope()
    envelope[field] = value

    with pytest.raises(IdentityKeyProviderUnavailable, match=IDENTITY_KEY_ERROR):
        provider.load_keys(write_envelope(tmp_path, envelope))
    assert client.decrypt_calls == []


@pytest.mark.parametrize(
    "change",
    [
        "wrong-purpose",
        "wrong-environment",
        "context-extra-field",
        "entry-extra-field",
        "duplicate-ciphertext",
        "missing-purpose",
        "extra-purpose",
        "top-extra-field",
        "invalid-base64",
        "noncanonical-base64",
        "empty-ciphertext",
        "oversized-ciphertext",
    ],
)
def test_complete_envelope_validation_precedes_any_kms_request(tmp_path, change):
    client = FakeKmsClient()
    provider = make_provider(client)
    envelope = provider.generate_envelope()
    entry = envelope["keys"]["otp"]
    if change == "wrong-purpose":
        entry["encryption_context"]["aeterna-purpose"] = "identity-pii"
    elif change == "wrong-environment":
        entry["encryption_context"]["aeterna-environment"] = "preview"
    elif change == "context-extra-field":
        entry["encryption_context"]["extra"] = "unexpected"
    elif change == "entry-extra-field":
        entry["plaintext"] = "unexpected"
    elif change == "duplicate-ciphertext":
        entry["ciphertext"] = envelope["keys"]["pii"]["ciphertext"]
    elif change == "missing-purpose":
        del envelope["keys"]["pii"]
    elif change == "extra-purpose":
        envelope["keys"]["other"] = entry
    elif change == "top-extra-field":
        envelope["unexpected"] = "extra"
    elif change == "invalid-base64":
        entry["ciphertext"] = "!"
    elif change == "noncanonical-base64":
        entry["ciphertext"] = "Zh=="
    elif change == "empty-ciphertext":
        entry["ciphertext"] = ""
    elif change == "oversized-ciphertext":
        entry["ciphertext"] = base64.b64encode(
            b"A" * (MAX_IDENTITY_CIPHERTEXT_BYTES + 1)
        ).decode("ascii")

    with pytest.raises(IdentityKeyProviderUnavailable):
        provider.load_keys(write_envelope(tmp_path, envelope))
    assert client.decrypt_calls == []


@pytest.mark.parametrize(
    "raw", [b"", b"not-json", b'{"key_version":1,"key_version":1}']
)
def test_invalid_or_duplicate_member_json_never_reaches_kms(tmp_path, raw):
    client = FakeKmsClient()
    path = tmp_path / "envelope.json"
    path.write_bytes(raw)

    with pytest.raises(IdentityKeyProviderUnavailable):
        make_provider(client).load_keys(path)
    assert client.decrypt_calls == []


def test_missing_oversized_and_nonregular_files_fail_closed(tmp_path):
    client = FakeKmsClient()
    provider = make_provider(client)
    with pytest.raises(IdentityKeyProviderUnavailable):
        provider.load_keys(tmp_path / "missing.json")
    with pytest.raises(IdentityKeyProviderUnavailable):
        provider.load_keys(tmp_path)
    path = tmp_path / "envelope.json"
    path.write_bytes(b" " * (MAX_IDENTITY_ENVELOPE_BYTES + 1))
    with pytest.raises(IdentityKeyProviderUnavailable):
        provider.load_keys(path)
    assert client.decrypt_calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"region": "ap-southeast-2"},
        {"environment": "development"},
        {"environment": "test"},
        {"key_arn": "alias/aeterna-identity"},
        {"key_arn": KEY_ARN.replace("key/", "key/mrk-")},
        {"key_arn": KEY_ARN.replace("arn:aws:", "arn:aws-cn:")},
        {"recovery_key_arn": KEY_ARN},
        {"recovery_key_arn": KEY_ARN.upper()},
    ],
)
def test_provider_rejects_region_key_alias_environment_or_recovery_reuse(changes):
    with pytest.raises(IdentityKeyProviderUnavailable):
        make_provider(**changes)


def test_preview_uses_its_own_context_and_rejects_a_production_envelope(tmp_path):
    client = FakeKmsClient()
    production = make_provider(client).generate_envelope()
    preview_provider = make_provider(client, environment="preview")
    preview = preview_provider.generate_envelope()
    assert preview["environment"] == "preview"
    assert all(
        entry["encryption_context"]["aeterna-environment"] == "preview"
        for entry in preview["keys"].values()
    )
    with pytest.raises(IdentityKeyProviderUnavailable):
        preview_provider.load_keys(write_envelope(tmp_path, production))
    assert client.decrypt_calls == []


def test_rewritten_environment_metadata_cannot_change_ciphertext_binding(tmp_path):
    client = FakeKmsClient()
    envelope = make_provider(client).generate_envelope()
    envelope["environment"] = "preview"
    for entry in envelope["keys"].values():
        entry["encryption_context"]["aeterna-environment"] = "preview"

    with pytest.raises(IdentityKeyProviderUnavailable):
        make_provider(client, environment="preview").load_keys(
            write_envelope(tmp_path, envelope)
        )
    assert len(client.decrypt_calls) == 1


def test_swapped_ciphertexts_cannot_change_their_purpose_binding(tmp_path):
    client = FakeKmsClient()
    provider = make_provider(client)
    envelope = provider.generate_envelope()
    pii = envelope["keys"]["pii"]
    otp = envelope["keys"]["otp"]
    pii["ciphertext"], otp["ciphertext"] = otp["ciphertext"], pii["ciphertext"]

    with pytest.raises(IdentityKeyProviderUnavailable):
        provider.load_keys(write_envelope(tmp_path, envelope))
    assert len(client.decrypt_calls) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"KeyId": OTHER_KEY_ARN},
        {"Plaintext": b"unexpected-plaintext"},
        {"CiphertextBlob": b""},
        {"CiphertextBlob": "invalid-type"},
        {"CiphertextBlob": b"A" * (MAX_IDENTITY_CIPHERTEXT_BYTES + 1)},
        {"CiphertextBlob": b"repeated-for-every-purpose"},
    ],
)
def test_bad_provisioning_response_never_creates_an_envelope(changes):
    client = FakeKmsClient()
    client.generated_response_changes = changes
    with pytest.raises(IdentityKeyProviderUnavailable):
        make_provider(client).generate_envelope()
    assert client.decrypt_calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"KeyId": OTHER_KEY_ARN},
        {"EncryptionAlgorithm": "RSAES_OAEP_SHA_256"},
        {"Plaintext": b"short"},
        {"Plaintext": "A" * 32},
        {"Plaintext": bytes([0x7F]) * 32},
    ],
)
def test_bad_decryption_response_never_exposes_key_material(tmp_path, changes):
    client = FakeKmsClient()
    provider = make_provider(client)
    path = write_envelope(tmp_path, provider.generate_envelope())
    client.decrypted_response_changes = changes
    with pytest.raises(IdentityKeyProviderUnavailable):
        provider.load_keys(path)


@pytest.mark.parametrize("operation", ["generate", "decrypt"])
def test_provider_diagnostics_are_sanitized(tmp_path, operation):
    client = FakeKmsClient()
    provider = make_provider(client)
    sensitive_diagnostic = "synthetic-sensitive-sdk-diagnostic"
    if operation == "generate":
        client.generate_error = RuntimeError(sensitive_diagnostic)
        call = provider.generate_envelope
    else:
        path = write_envelope(tmp_path, provider.generate_envelope())
        client.decrypt_error = RuntimeError(sensitive_diagnostic)
        call = lambda: provider.load_keys(path)
    with pytest.raises(IdentityKeyProviderUnavailable) as caught:
        call()
    assert str(caught.value) == IDENTITY_KEY_ERROR
    assert sensitive_diagnostic not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_sdk_uses_bounded_timeouts_and_official_regional_endpoint(monkeypatch):
    client = FakeKmsClient()
    calls = []

    def create_client(service, **kwargs):
        calls.append((service, kwargs))
        return client

    monkeypatch.setattr(
        "app.services.common.aeterna_identity_key.boto3.client", create_client
    )
    provider = AwsKmsIdentityKeyProvider(
        region="ap-southeast-1", key_arn=KEY_ARN, environment="production"
    )
    assert provider.client is client
    service, options = calls[0]
    assert service == "kms"
    assert options["region_name"] == "ap-southeast-1"
    assert options["endpoint_url"] == "https://kms.ap-southeast-1.amazonaws.com"
    config = options["config"]
    assert config.connect_timeout == 3
    assert config.read_timeout == 5
    assert config.retries["total_max_attempts"] == 2
    assert config.ignore_configured_endpoint_urls


def test_falsey_injected_client_does_not_trigger_credential_discovery(monkeypatch):
    class FalseyClient(FakeKmsClient):
        def __bool__(self):
            return False

    def create_client(*args, **kwargs):
        raise AssertionError("The injected client must be preserved")

    monkeypatch.setattr(
        "app.services.common.aeterna_identity_key.boto3.client", create_client
    )
    client = FalseyClient()
    assert make_provider(client).client is client
