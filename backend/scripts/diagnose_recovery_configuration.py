"""Print sanitized recovery configuration evidence inside the backend container.

Working directory: /app. Run python -m scripts.diagnose_recovery_configuration.
Reads only named process-environment controls and packaged schema contracts.
Does not open environment files, import application settings, call AWS, query
storage, generate secrets, or change configuration. Output uses fixed status
labels, booleans and schema counts only.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

SINGLE_REGION_KEY_ARN = re.compile(
    r"arn:aws:kms:ap-southeast-1:[0-9]{12}:key/"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
RECOVERY_CONTROLS = (
    "AETERNA_RECOVERY_KEY_PROVIDER",
    "AETERNA_RECOVERY_KMS_ENABLED",
    "AETERNA_RECOVERY_KMS_REGION",
    "AETERNA_RECOVERY_KMS_KEY_ARN",
)


class DiagnosticArgumentError(ValueError):
    """Reject arguments without echoing potentially sensitive input."""


class DiagnosticArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise DiagnosticArgumentError() from None


@dataclass(frozen=True, repr=False)
class RecoveryConfiguration:
    provider: str
    kms_enabled: bool
    enabled_value_valid: bool
    region: str
    key_arn: str
    supplied_controls: frozenset[str]


def configuration_from_environment(
    environment: Mapping[str, str],
) -> RecoveryConfiguration:
    """Read only recovery controls, without loading .env or AWS profiles."""
    enabled = environment.get("AETERNA_RECOVERY_KMS_ENABLED", "false").lower()
    return RecoveryConfiguration(
        provider=environment.get("AETERNA_RECOVERY_KEY_PROVIDER", "disabled"),
        kms_enabled=enabled in {"true", "1", "yes", "on", "t", "y"},
        enabled_value_valid=enabled
        in {"false", "0", "no", "off", "f", "n", "true", "1", "yes", "on", "t", "y"},
        region=environment.get("AETERNA_RECOVERY_KMS_REGION", "ap-southeast-1"),
        key_arn=environment.get("AETERNA_RECOVERY_KMS_KEY_ARN", ""),
        supplied_controls=frozenset(
            name for name in RECOVERY_CONTROLS if name in environment
        ),
    )


def current_contract_features() -> dict[str, bool | int]:
    """Inspect declared schemas without importing routes, settings or services."""
    flags: dict[str, bool | int] = {
        "management_email_required": False,
        "recipient_secret_signed": False,
        "erc_enrollment_supported": False,
        "schema_modules_available": 0,
    }
    try:
        import app.schemas.client.aeterna_notification as notification

        fields = notification.OwnerConfigurationData.model_fields
        flags["management_email_required"] = (
            "management_email" in fields and fields["management_email"].is_required()
        )
        flags["schema_modules_available"] += 1
    except (ImportError, AttributeError):
        pass
    try:
        import app.schemas.client.aeterna_recipient_recovery as recipient

        fields = recipient.RecipientRecoverySecretRequest.model_fields
        flags["recipient_secret_signed"] = all(
            name in fields and fields[name].is_required()
            for name in ("signed", "signature", "claim_token")
        )
        flags["schema_modules_available"] += 1
    except (ImportError, AttributeError):
        pass
    try:
        import app.schemas.client.aeterna_recovery as recovery

        fields = recovery.RecoveryRecordEnrollSigned.model_fields
        flags["erc_enrollment_supported"] = (
            "erc_commitment" in fields and fields["erc_commitment"].is_required()
        )
        flags["schema_modules_available"] += 1
    except (ImportError, AttributeError):
        pass
    return flags


def diagnose(
    configuration: RecoveryConfiguration,
    *,
    contract_features: Mapping[str, bool | int] | None = None,
) -> dict:
    """Return fixed labels and safe checks without constructing an SDK client."""
    checks = {
        "provider_control_supplied": RECOVERY_CONTROLS[0]
        in configuration.supplied_controls,
        "enablement_control_supplied": RECOVERY_CONTROLS[1]
        in configuration.supplied_controls,
        "region_control_supplied": RECOVERY_CONTROLS[2]
        in configuration.supplied_controls,
        "key_control_supplied": RECOVERY_CONTROLS[3] in configuration.supplied_controls,
        "provider_supported": configuration.provider in {"disabled", "aws-kms"},
        "kms_enabled": configuration.kms_enabled,
        "enabled_value_valid": configuration.enabled_value_valid,
        "region_supported": configuration.region == "ap-southeast-1",
        "key_arn_configured": bool(configuration.key_arn),
        "key_arn_valid": SINGLE_REGION_KEY_ARN.fullmatch(configuration.key_arn)
        is not None,
    }
    status = "recovery_configuration_invalid"
    if len(configuration.supplied_controls) != len(RECOVERY_CONTROLS):
        status = "configuration_controls_not_supplied"
    elif checks["enabled_value_valid"]:
        if configuration.provider == "disabled" and not configuration.kms_enabled:
            status = "recovery_provider_disabled"
        elif (
            configuration.provider == "aws-kms"
            and configuration.kms_enabled
            and checks["region_supported"]
            and checks["key_arn_valid"]
        ):
            status = "recovery_configured_not_probed"
    return {
        "diagnostic_version": 1,
        "configuration_controls_supplied": len(configuration.supplied_controls),
        "status": status,
        "checks": checks,
        "contract": dict(
            current_contract_features()
            if contract_features is None
            else contract_features
        ),
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    parser = DiagnosticArgumentParser(description=__doc__)
    previous_logging_level = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        try:
            parser.parse_args(argv)
        except DiagnosticArgumentError:
            print(json.dumps({"diagnostic_version": 1, "status": "invalid_arguments"}))
            return 2
        try:
            report = diagnose(
                configuration_from_environment(
                    os.environ if environment is None else environment
                )
            )
        except Exception:
            report = {"diagnostic_version": 1, "status": "diagnostic_unavailable"}
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "recovery_configured_not_probed" else 1
    finally:
        logging.disable(previous_logging_level)


if __name__ == "__main__":
    sys.exit(main())
