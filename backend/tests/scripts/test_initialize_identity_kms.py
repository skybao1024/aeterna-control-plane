"""Evidence for safe one-time identity envelope provisioning without AWS calls."""

import json
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from scripts import initialize_identity_kms as initializer

KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/"
    "00000000-0000-4000-8000-000000000099"
)
RECOVERY_KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/"
    "00000000-0000-4000-8000-000000000098"
)
CONFIGURATION = {
    "region": "ap-southeast-1",
    "key_arn": KEY_ARN,
    "environment": "production",
    "recovery_key_arn": RECOVERY_KEY_ARN,
}
SYNTHETIC_ENVELOPE = {"ciphertext": "synthetic-ciphertext-only"}
SENSITIVE_DIAGNOSTIC = "synthetic-provider-diagnostic-must-not-be-printed"


class FakeProvider:
    def __init__(self, envelope: dict | None = None):
        self.envelope = envelope if envelope is not None else SYNTHETIC_ENVELOPE
        self.generate_calls = 0
        self.load_calls = []

    def generate_envelope(self) -> dict:
        self.generate_calls += 1
        return self.envelope

    def load_keys(self, envelope_path: str | Path) -> object:
        self.load_calls.append(envelope_path)
        return object()


def arguments(output: Path) -> list[str]:
    return [
        "--region",
        CONFIGURATION["region"],
        "--key-arn",
        KEY_ARN,
        "--environment",
        CONFIGURATION["environment"],
        "--recovery-key-arn",
        RECOVERY_KEY_ARN,
        "--output",
        str(output),
    ]


def test_initialization_persists_only_provider_ciphertext_with_private_permissions(
    tmp_path, capsys
):
    output = tmp_path / "envelope.json"
    provider = FakeProvider()
    configurations = []

    def factory(**configuration):
        configurations.append(configuration)
        return provider

    assert initializer.main(arguments(output), provider_factory=factory) == 0
    assert configurations == [CONFIGURATION]
    assert provider.generate_calls == 1
    assert provider.load_calls == []
    assert json.loads(output.read_text()) == SYNTHETIC_ENVELOPE
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [output]
    captured = capsys.readouterr()
    assert captured.out == "Identity KMS envelope initialized.\n"
    assert captured.err == ""


@pytest.mark.parametrize("existing_type", ["file", "directory", "symlink", "broken"])
def test_existing_output_is_refused_before_provider_construction(
    tmp_path, capsys, existing_type
):
    output = tmp_path / "envelope.json"
    target = tmp_path / "target.json"
    if existing_type == "file":
        output.write_text("existing persistent envelope")
    elif existing_type == "directory":
        output.mkdir()
    else:
        if existing_type == "symlink":
            target.write_text("existing linked envelope")
        output.symlink_to(target)
    existing_inode = output.lstat().st_ino
    calls = []

    def factory(**configuration):
        calls.append(configuration)
        raise AssertionError("Provider must not be constructed")

    assert initializer.main(arguments(output), provider_factory=factory) == 1
    assert calls == []
    assert output.lstat().st_ino == existing_inode
    if existing_type == "file":
        assert output.read_text() == "existing persistent envelope"
    elif existing_type == "symlink":
        assert target.read_text() == "existing linked envelope"
        assert output.is_symlink()
    elif existing_type == "broken":
        assert output.is_symlink()
        assert not target.exists()
    else:
        assert output.is_dir()
    assert not list(tmp_path.glob(".identity-kms-*.tmp"))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Identity KMS initialization failed.\n"


def test_missing_parent_is_refused_before_provider_construction(tmp_path, capsys):
    output = tmp_path / "missing" / "envelope.json"
    calls = []

    def factory(**configuration):
        calls.append(configuration)
        return FakeProvider()

    assert initializer.main(arguments(output), provider_factory=factory) == 1
    assert calls == []
    assert not output.parent.exists()
    assert list(tmp_path.iterdir()) == []
    assert capsys.readouterr().err == "Identity KMS initialization failed.\n"


def test_concurrent_initializers_atomically_publish_only_one_envelope(tmp_path):
    output = tmp_path / "envelope.json"
    barrier = threading.Barrier(2)
    envelopes = [{"ciphertext": "candidate-one"}, {"ciphertext": "candidate-two"}]

    class ConcurrentProvider(FakeProvider):
        def generate_envelope(self):
            barrier.wait(timeout=5)
            return super().generate_envelope()

    def provision(envelope):
        try:
            initializer.initialize_envelope(
                output=output,
                configuration=CONFIGURATION,
                provider_factory=lambda **configuration: ConcurrentProvider(envelope),
            )
        except FileExistsError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(provision, envelopes))

    assert sorted(results) == [False, True]
    assert json.loads(output.read_text()) == envelopes[results.index(True)]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [output]


def test_symlink_created_during_kms_call_is_never_overwritten(tmp_path, capsys):
    output = tmp_path / "envelope.json"
    target = tmp_path / "existing.json"
    target.write_text("persistent competing envelope")

    class RacedProvider(FakeProvider):
        def generate_envelope(self):
            output.symlink_to(target)
            return super().generate_envelope()

    assert (
        initializer.main(
            arguments(output), provider_factory=lambda **configuration: RacedProvider()
        )
        == 1
    )
    assert output.is_symlink()
    assert target.read_text() == "persistent competing envelope"
    assert not list(tmp_path.glob(".identity-kms-*.tmp"))
    assert capsys.readouterr().err == "Identity KMS initialization failed.\n"


@pytest.mark.parametrize("failure_stage", ["construct", "generate", "link", "fsync"])
def test_provider_and_filesystem_failures_leave_no_output_or_diagnostics(
    tmp_path, capsys, monkeypatch, failure_stage
):
    output = tmp_path / "envelope.json"

    def fail(*args, **kwargs):
        raise RuntimeError(SENSITIVE_DIAGNOSTIC)

    provider = FakeProvider()
    if failure_stage == "construct":
        factory = fail
    else:
        factory = lambda **configuration: provider
        if failure_stage == "generate":
            monkeypatch.setattr(provider, "generate_envelope", fail)
        elif failure_stage == "link":
            monkeypatch.setattr(initializer.os, "link", fail)
        else:
            monkeypatch.setattr(initializer.os, "fsync", fail)

    assert initializer.main(arguments(output), provider_factory=factory) == 1
    assert list(tmp_path.iterdir()) == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Identity KMS initialization failed.\n"


def test_existing_temporary_file_is_never_deleted_or_reused(
    tmp_path, capsys, monkeypatch
):
    output = tmp_path / "envelope.json"
    temporary = tmp_path / ".identity-kms-fixed-name.tmp"
    temporary.write_text("another initializer owns this file")

    class FixedUuid:
        hex = "fixed-name"

    monkeypatch.setattr(initializer.uuid, "uuid4", FixedUuid)
    assert (
        initializer.main(
            arguments(output), provider_factory=lambda **configuration: FakeProvider()
        )
        == 1
    )
    assert not output.exists()
    assert temporary.read_text() == "another initializer owns this file"
    assert capsys.readouterr().err == "Identity KMS initialization failed.\n"


def test_directory_sync_failure_preserves_already_published_envelope(
    tmp_path, capsys, monkeypatch
):
    output = tmp_path / "envelope.json"
    original_fsync = initializer.os.fsync
    sync_calls = 0

    def fail_publication_sync(descriptor):
        nonlocal sync_calls
        sync_calls += 1
        if sync_calls == 2:
            raise OSError(SENSITIVE_DIAGNOSTIC)
        original_fsync(descriptor)

    monkeypatch.setattr(initializer.os, "fsync", fail_publication_sync)
    assert (
        initializer.main(
            arguments(output), provider_factory=lambda **configuration: FakeProvider()
        )
        == 1
    )
    assert json.loads(output.read_text()) == SYNTHETIC_ENVELOPE
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [output]
    assert capsys.readouterr().err == "Identity KMS initialization failed.\n"


def test_check_loads_existing_keys_without_generation_or_file_changes(tmp_path, capsys):
    output = tmp_path / "envelope.json"
    output.write_text("existing synthetic encrypted envelope")
    previous = output.stat()
    provider = FakeProvider()

    assert (
        initializer.main(
            arguments(output) + ["--check"],
            provider_factory=lambda **configuration: provider,
        )
        == 0
    )
    assert provider.load_calls == [output]
    assert provider.generate_calls == 0
    assert output.read_text() == "existing synthetic encrypted envelope"
    assert output.stat().st_ino == previous.st_ino
    assert output.stat().st_mtime_ns == previous.st_mtime_ns
    assert list(tmp_path.iterdir()) == [output]
    captured = capsys.readouterr()
    assert captured.out == "Identity KMS check succeeded.\n"
    assert captured.err == ""


def test_check_failure_is_generic_and_preserves_existing_envelope(tmp_path, capsys):
    output = tmp_path / "envelope.json"
    output.write_text("existing persistent envelope")

    class FailedProvider(FakeProvider):
        def load_keys(self, envelope_path):
            raise RuntimeError(SENSITIVE_DIAGNOSTIC)

    assert (
        initializer.main(
            arguments(output) + ["--check"],
            provider_factory=lambda **configuration: FailedProvider(),
        )
        == 1
    )
    assert output.read_text() == "existing persistent envelope"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Identity KMS check failed.\n"


@pytest.mark.parametrize(
    "argv", [[], ["--environment", SENSITIVE_DIAGNOSTIC], [SENSITIVE_DIAGNOSTIC]]
)
def test_invalid_arguments_are_sanitized_without_constructing_provider(argv, capsys):
    calls = []

    def factory(**configuration):
        calls.append(configuration)
        return FakeProvider()

    assert initializer.main(argv, provider_factory=factory) == 1
    assert calls == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Identity KMS configuration is invalid.\n"
