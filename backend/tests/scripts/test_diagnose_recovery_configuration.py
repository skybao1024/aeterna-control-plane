"""Synthetic diagnostics without AWS, application settings or .env reads."""

import json
import logging
from dataclasses import replace

import pytest

from scripts import diagnose_recovery_configuration as diagnostic

KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/"
    "00000000-0000-4000-8000-000000000099"
)
SENSITIVE = "synthetic-sensitive-provider-message-must-not-be-printed"
ENVIRONMENT = {
    "AETERNA_RECOVERY_KEY_PROVIDER": "aws-kms",
    "AETERNA_RECOVERY_KMS_ENABLED": "true",
    "AETERNA_RECOVERY_KMS_REGION": "ap-southeast-1",
    "AETERNA_RECOVERY_KMS_KEY_ARN": KEY_ARN,
}
CONFIGURATION = diagnostic.configuration_from_environment(ENVIRONMENT)
FEATURES = {"management_email_required": True, "schema_modules_available": 3}


def test_absent_controls_cannot_be_treated_as_effective_disabled_configuration():
    report = diagnostic.diagnose(
        diagnostic.configuration_from_environment({}), contract_features=FEATURES
    )
    assert report["status"] == "configuration_controls_not_supplied"
    assert report["configuration_controls_supplied"] == 0
    assert report["checks"]["provider_control_supplied"] is False


@pytest.mark.parametrize("missing", diagnostic.RECOVERY_CONTROLS)
def test_partial_process_controls_do_not_establish_runtime_configuration(missing):
    environment = {
        name: value for name, value in ENVIRONMENT.items() if name != missing
    }
    report = diagnostic.diagnose(
        diagnostic.configuration_from_environment(environment),
        contract_features=FEATURES,
    )
    assert report["status"] == "configuration_controls_not_supplied"
    assert report["configuration_controls_supplied"] == 3


def test_explicit_disabled_configuration_is_reported_without_provider_construction():
    report = diagnostic.diagnose(
        diagnostic.configuration_from_environment(
            {
                **ENVIRONMENT,
                "AETERNA_RECOVERY_KEY_PROVIDER": "disabled",
                "AETERNA_RECOVERY_KMS_ENABLED": "false",
                "AETERNA_RECOVERY_KMS_KEY_ARN": "",
            }
        ),
        contract_features=FEATURES,
    )
    assert report["status"] == "recovery_provider_disabled"
    assert report["configuration_controls_supplied"] == 4
    assert report["checks"]["kms_enabled"] is False


def test_configured_status_does_not_claim_aws_readiness_or_expose_key_identifier():
    report = diagnostic.diagnose(CONFIGURATION, contract_features=FEATURES)
    assert report["status"] == "recovery_configured_not_probed"
    assert report["checks"]["key_arn_valid"] is True
    assert KEY_ARN not in json.dumps(report)
    assert all(isinstance(value, bool) for value in report["checks"].values())


@pytest.mark.parametrize(
    "changes",
    [
        {"provider": "local-test"},
        {"provider": "disabled"},
        {"kms_enabled": False},
        {"enabled_value_valid": False},
        {"region": "ap-southeast-2"},
        {"key_arn": "alias/synthetic-key"},
        {"key_arn": KEY_ARN.replace("00000000-", "mrk-")},
        {"key_arn": ""},
    ],
)
def test_invalid_configuration_returns_only_sanitized_flags(changes):
    report = diagnostic.diagnose(
        replace(CONFIGURATION, **changes), contract_features=FEATURES
    )
    assert report["status"] == "recovery_configuration_invalid"
    assert KEY_ARN not in json.dumps(report)


@pytest.mark.parametrize("value", ["TRUE", "1", "yes", "on", "t", "y"])
def test_enabled_boolean_matches_accepted_environment_values(value):
    configuration = diagnostic.configuration_from_environment(
        {**ENVIRONMENT, "AETERNA_RECOVERY_KMS_ENABLED": value}
    )
    assert diagnostic.diagnose(configuration, contract_features=FEATURES)["status"] == (
        "recovery_configured_not_probed"
    )


def test_invalid_boolean_is_rejected_without_echoing_its_value():
    configuration = diagnostic.configuration_from_environment(
        {**ENVIRONMENT, "AETERNA_RECOVERY_KMS_ENABLED": SENSITIVE}
    )
    report = diagnostic.diagnose(configuration, contract_features=FEATURES)
    assert report["status"] == "recovery_configuration_invalid"
    assert SENSITIVE not in json.dumps(report)
    assert SENSITIVE not in repr(configuration)


def test_contract_check_uses_schemas_without_application_settings(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "app.core.config", None)
    features = diagnostic.current_contract_features()
    assert features == {
        "management_email_required": True,
        "recipient_secret_signed": True,
        "erc_enrollment_supported": True,
        "schema_modules_available": 3,
    }


def test_missing_older_schema_is_a_feature_flag_not_a_raw_import_error(monkeypatch):
    import sys

    monkeypatch.setitem(
        sys.modules, "app.schemas.client.aeterna_recipient_recovery", None
    )
    features = diagnostic.current_contract_features()
    assert features["recipient_secret_signed"] is False
    assert features["schema_modules_available"] == 2


def test_cli_does_not_read_files_or_construct_aws_client(monkeypatch, capsys):
    import builtins

    import boto3

    def forbidden_operation(*args, **kwargs):
        raise AssertionError(
            "Configuration diagnostics must not read files or contact AWS"
        )

    diagnostic.current_contract_features()
    monkeypatch.setattr(builtins, "open", forbidden_operation)
    monkeypatch.setattr(boto3, "client", forbidden_operation)
    assert diagnostic.main([], environment=ENVIRONMENT) == 0
    assert json.loads(capsys.readouterr().out)["status"] == (
        "recovery_configured_not_probed"
    )


def test_cli_ignores_unrelated_secrets_and_invalid_arguments_are_not_echoed(capsys):
    previous_level = logging.root.manager.disable
    assert (
        diagnostic.main(
            [], environment={**ENVIRONMENT, "AWS_SECRET_ACCESS_KEY": SENSITIVE}
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "recovery_configured_not_probed"
    assert SENSITIVE not in json.dumps(report)
    assert diagnostic.main(["--unknown", SENSITIVE], environment={}) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "invalid_arguments"
    assert captured.err == ""
    assert SENSITIVE not in captured.out
    assert logging.root.manager.disable == previous_level


def test_unexpected_configuration_failure_never_prints_exception(monkeypatch, capsys):
    def failing_features():
        raise RuntimeError(SENSITIVE)

    monkeypatch.setattr(diagnostic, "current_contract_features", failing_features)
    assert diagnostic.main([], environment={}) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "diagnostic_unavailable"
    assert captured.err == ""
    assert SENSITIVE not in captured.out
