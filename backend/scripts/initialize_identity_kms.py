"""Create or check the persistent ciphertext-only identity key envelope.

Working directory: ``/app`` inside the backend container.
Execution: ``python -m scripts.initialize_identity_kms`` in that container.
Arguments: ``--region``, ``--key-arn``, and ``--environment`` are required;
``--output`` defaults to ``/app/identity-keys/envelope.json``. Supply
``--recovery-key-arn`` to enforce separation from the recovery KMS key.
``--check`` decrypts the existing envelope without printing any key material.

Initialize once before identity records are written, then preserve and back up
the envelope. Never recreate it for a database with existing identity records:
new application keys would make those records unreadable. The output parent
directory must already exist. Existing files, directories, and symlinks are
never overwritten. This script does not create or modify AWS resources.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Protocol, Sequence

DEFAULT_OUTPUT = "/app/identity-keys/envelope.json"


class IdentityKeyProvider(Protocol):
    """Expose only the two provider operations required by initialization."""

    def generate_envelope(self) -> dict: ...

    def load_keys(self, envelope_path: str | Path) -> object: ...


class IdentityKeyInitializationError(RuntimeError):
    """Signal invalid initialization input without exposing diagnostics."""


class IdentityKeyArgumentParser(argparse.ArgumentParser):
    """Avoid echoing invalid arguments into operational logs."""

    def error(self, message: str) -> None:
        raise IdentityKeyInitializationError() from None


def _default_provider_factory(**configuration: str) -> IdentityKeyProvider:
    # Import only after initialization has confirmed that output is absent.
    from app.services.common.aeterna_identity_key import AwsKmsIdentityKeyProvider

    return AwsKmsIdentityKeyProvider(**configuration)


@contextmanager
def _output_directory(output: Path) -> Iterator[int]:
    if not output.name or output.name in {".", ".."}:
        raise IdentityKeyInitializationError()
    descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _require_absent_output(directory: int, filename: str) -> None:
    try:
        os.stat(filename, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise IdentityKeyInitializationError()


def _create_envelope_exclusively(directory: int, filename: str, envelope: dict) -> None:
    serialized = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary_name = f".identity-kms-{uuid.uuid4().hex}.tmp"
    temporary_created = False
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory,
        )
        temporary_created = True
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        # Linking is atomic and fails if any competing output already exists.
        os.link(
            temporary_name,
            filename,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.fsync(directory)
    finally:
        if temporary_created:
            os.unlink(temporary_name, dir_fd=directory)
            os.fsync(directory)


def initialize_envelope(
    *,
    output: Path,
    configuration: dict[str, str],
    provider_factory: Callable[..., IdentityKeyProvider],
) -> None:
    """Generate ciphertext only after the destination passes local checks."""
    with _output_directory(output) as directory:
        _require_absent_output(directory, output.name)
        provider = provider_factory(**configuration)
        envelope = provider.generate_envelope()
        _create_envelope_exclusively(directory, output.name, envelope)


def _argument_parser() -> IdentityKeyArgumentParser:
    parser = IdentityKeyArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True)
    parser.add_argument("--key-arn", required=True)
    parser.add_argument(
        "--environment", required=True, choices=("production", "preview")
    )
    parser.add_argument("--recovery-key-arn", default="")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    provider_factory: Callable[..., IdentityKeyProvider] | None = None,
) -> int:
    """Return a concise, sanitized operational result without a traceback."""
    try:
        arguments = _argument_parser().parse_args(argv)
    except IdentityKeyInitializationError:
        print("Identity KMS configuration is invalid.", file=sys.stderr)
        return 1

    configuration = {
        "region": arguments.region,
        "key_arn": arguments.key_arn,
        "environment": arguments.environment,
        "recovery_key_arn": arguments.recovery_key_arn,
    }
    factory = provider_factory or _default_provider_factory
    try:
        output = Path(arguments.output)
        if arguments.check:
            factory(**configuration).load_keys(output)
        else:
            initialize_envelope(
                output=output,
                configuration=configuration,
                provider_factory=factory,
            )
    except Exception:
        operation = "check" if arguments.check else "initialization"
        print(f"Identity KMS {operation} failed.", file=sys.stderr)
        return 1

    result = "check succeeded" if arguments.check else "envelope initialized"
    print(f"Identity KMS {result}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
