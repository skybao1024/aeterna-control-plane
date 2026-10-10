"""Cross-language fixture and strict transport tests for public protocol v1."""

import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from app.api.client.protocol import parse_protocol_body
from app.configs.docs_apps import create_client_app
from app.core.config import settings
from app.db.session import get_db
from app.exceptions.aeterna_protocol import AeternaProtocolException
from app.route.router_registry import get_client_routes
from app.schemas.client.aeterna_protocol import (
    AccountChallengeRequest,
    DeviceBindingApprovalRequest,
    DeviceBindingRequest,
    DeviceBindingStatusRequest,
    DeviceBindingStatusResponse,
    DeviceStatusChangeRequest,
    DeviceStatusChangeResponse,
    HeartbeatRequest,
    HeartbeatResponse,
)
from app.schemas.client.aeterna_recipient_recovery import (
    RecipientRecoveryAbandonRequest,
    RecipientRecoveryAbandonResponse,
    RecipientRecoveryClaimResponse,
    RecipientRecoveryConfirmRequest,
    RecipientRecoveryPrepareRequest,
    RecipientRecoveryProvisionRequest,
    RecipientRecoveryProvisionResponse,
    RecipientRecoveryResponse,
    RecipientRecoverySecretRequest,
    RecipientRecoverySecretResponse,
    RecoveryCustodyChallengeRequest,
    RecoveryCustodyChallengeResponse,
    RecoveryCustodyVerifyRequest,
    RecoveryCustodyVerifyResponse,
)
from app.schemas.client.aeterna_recovery import (
    OwnerRecoveryActionRequest,
    OwnerRecoveryResponse,
    OwnerRecoverySecretResponse,
    OwnerRecoveryStartRequest,
    OwnerRecoveryVerifyRequest,
    RecoveryClaimStartRequest,
    RecoveryClaimVerifyRequest,
    RecoveryRecordActionRequest,
    RecoveryRecordEnrollRequest,
    RecoveryRecordProvisionRequest,
    RecoveryRotationConfirmRequest,
    RecoveryRotationProvisionRequest,
    RecoveryRotationProvisionResponse,
    RecoveryRotationResponse,
    RecoverySecretRequest,
    RecoverySecretResponse,
)
from app.schemas.client.aeterna_setup import (
    PolicyConfigureRequest,
    PolicyConfigureResponse,
    SetupStatusRequest,
    SetupStatusResponse,
)
from app.services.client.aeterna_recovery import (
    AeternaRecoveryService,
    get_aeterna_recovery_service,
)
from app.services.common.aeterna_security import (
    IdentityKeyUnavailable,
    decode_base64url,
    get_identity_keys,
    validate_identity_key_configuration,
    verify_signature,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "aeterna-protocol-v1"
EXPECTED_PUBLIC_RELEASE_DIGEST = (
    "3b5f4a167279d3efe3ecde641ee8daa92fe7b21ab71c3e8d3843469daf63917c"
)


def load_json(path: str) -> dict:
    return json.loads((FIXTURE_ROOT / path).read_text(encoding="utf-8"))


def make_request(body: bytes, content_type: str = "application/json") -> Request:
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/test",
            "headers": [(b"content-type", content_type.encode("ascii"))],
        },
        receive,
    )


def test_vendored_public_release_digest_and_every_file_hash_match():
    manifest = load_json("manifest.json")
    assert manifest["release_tag"] == "protocol-v1.9.0"
    assert manifest["release_digest"] == EXPECTED_PUBLIC_RELEASE_DIGEST
    for entry in manifest["files"]:
        content = (FIXTURE_ROOT / entry["path"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == entry["sha256"]

    unsigned = {
        key: value for key, value in manifest.items() if key != "release_digest"
    }
    assert (
        hashlib.sha256(rfc8785.dumps(unsigned)).hexdigest()
        == manifest["release_digest"]
    )


def test_python_jcs_and_ed25519_match_published_request_and_approval_vectors():
    for fixture_path, model in [
        ("fixtures/signatures/device-binding-request.json", DeviceBindingRequest),
        (
            "fixtures/signatures/device-binding-approval.json",
            DeviceBindingApprovalRequest,
        ),
        (
            "fixtures/signatures/device-binding-status.json",
            DeviceBindingStatusRequest,
        ),
        ("fixtures/signatures/heartbeat-request.json", HeartbeatRequest),
        ("fixtures/signatures/policy-configure.json", PolicyConfigureRequest),
        ("fixtures/signatures/setup-status.json", SetupStatusRequest),
        (
            "fixtures/signatures/recovery-record-enroll.json",
            RecoveryRecordEnrollRequest,
        ),
        (
            "fixtures/signatures/device-status-change.json",
            DeviceStatusChangeRequest,
        ),
        (
            "fixtures/signatures/recovery-record-provision.json",
            RecoveryRecordProvisionRequest,
        ),
        (
            "fixtures/signatures/recovery-record-confirm.json",
            RecoveryRecordActionRequest,
        ),
        (
            "fixtures/signatures/owner-recovery-start.json",
            OwnerRecoveryStartRequest,
        ),
        (
            "fixtures/signatures/owner-recovery-action.json",
            OwnerRecoveryActionRequest,
        ),
        (
            "fixtures/signatures/recovery-rotation-provision.json",
            RecoveryRotationProvisionRequest,
        ),
        (
            "fixtures/signatures/recovery-rotation-confirm.json",
            RecoveryRotationConfirmRequest,
        ),
    ]:
        fixture = load_json(fixture_path)
        envelope = {
            "protocol_version": 1,
            "signed": fixture["document"],
            "signature": fixture["signature"],
        }
        model.model_validate(envelope)
        assert rfc8785.dumps(fixture["document"]) == decode_base64url(
            fixture["canonical_bytes"], len(rfc8785.dumps(fixture["document"]))
        )
        assert verify_signature(
            decode_base64url(fixture["public_key"], 32),
            fixture["document"],
            fixture["signature"],
        )


def test_published_signature_failure_vectors_fail_closed():
    for fixture_path in [
        "fixtures/signatures/device-binding-request-wrong-key.json",
        "fixtures/signatures/device-binding-request-modified-signature.json",
        "fixtures/signatures/device-binding-cross-domain-replay.json",
        "fixtures/signatures/heartbeat-modified-payload.json",
        "fixtures/signatures/heartbeat-cross-domain-replay.json",
    ]:
        fixture = load_json(fixture_path)
        envelope = fixture["envelope"]
        assert fixture["expected"] == "device.proof_invalid"
        assert not verify_signature(
            decode_base64url(fixture["verification_public_key"], 32),
            envelope["signed"],
            envelope["signature"],
        )


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("recipient-recovery-secret", RecipientRecoverySecretRequest),
        ("recipient-recovery-provision", RecipientRecoveryProvisionRequest),
        ("recipient-recovery-prepare", RecipientRecoveryPrepareRequest),
        ("recipient-recovery-confirm", RecipientRecoveryConfirmRequest),
        ("recipient-recovery-abandon", RecipientRecoveryAbandonRequest),
        ("recovery-custody-challenge", RecoveryCustodyChallengeRequest),
        ("recovery-custody-verify", RecoveryCustodyVerifyRequest),
    ],
)
def test_recipient_and_custody_signature_vectors_match_closed_runtime_models(
    name, model
):
    fixture = load_json(f"fixtures/signatures/{name}.json")
    request = load_json(f"fixtures/valid/{name}-request.json")
    model.model_validate(request)
    assert rfc8785.dumps(request["signed"]) == decode_base64url(
        fixture["canonical_bytes"], len(rfc8785.dumps(request["signed"]))
    )
    assert verify_signature(
        decode_base64url(fixture["public_key"], 32),
        request["signed"],
        request["signature"],
    )
    invalid = load_json(f"fixtures/signatures/{name}-cross-domain.json")
    assert not verify_signature(
        decode_base64url(invalid["verification_public_key"], 32),
        invalid["envelope"]["signed"],
        invalid["envelope"]["signature"],
    )


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("recipient-recovery-secret", RecipientRecoverySecretRequest),
        ("recipient-recovery-provision", RecipientRecoveryProvisionRequest),
        ("recipient-recovery-prepare", RecipientRecoveryPrepareRequest),
        ("recipient-recovery-confirm", RecipientRecoveryConfirmRequest),
        ("recipient-recovery-abandon", RecipientRecoveryAbandonRequest),
        ("recovery-custody-challenge", RecoveryCustodyChallengeRequest),
        ("recovery-custody-verify", RecoveryCustodyVerifyRequest),
    ],
)
@pytest.mark.asyncio
async def test_recipient_and_custody_extra_fields_fail_closed(name, model):
    with pytest.raises(AeternaProtocolException) as invalid:
        await parse_protocol_body(
            make_request(
                (
                    FIXTURE_ROOT / f"fixtures/invalid/{name}-extra-field.json"
                ).read_bytes()
            ),
            model,
        )
    assert invalid.value.code == "protocol.invalid_request"


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("recipient-recovery-secret", RecipientRecoverySecretResponse),
        ("recipient-recovery-provision", RecipientRecoveryProvisionResponse),
        ("recipient-recovery-rotation", RecipientRecoveryResponse),
        ("recipient-recovery-abandon", RecipientRecoveryAbandonResponse),
        ("recipient-recovery-claim", RecipientRecoveryClaimResponse),
        ("recovery-custody-challenge", RecoveryCustodyChallengeResponse),
        ("recovery-custody-verify", RecoveryCustodyVerifyResponse),
    ],
)
def test_recipient_and_custody_success_fixtures_match_runtime_models(name, model):
    model.model_validate(load_json(f"fixtures/valid/{name}-response.json"))


def test_python_jcs_matches_unicode_property_order_and_escaping_vector():
    fixture = load_json("fixtures/signatures/jcs-unicode-and-escaping.json")
    canonical = rfc8785.dumps(fixture["document"])
    assert canonical == decode_base64url(fixture["canonical_bytes"], len(canonical))


def test_i10_published_success_responses_match_runtime_models():
    PolicyConfigureResponse.model_validate(
        load_json("fixtures/valid/policy-configure-response.json")
    )
    SetupStatusResponse.model_validate(
        load_json("fixtures/valid/setup-status-response.json")
    )
    DeviceBindingStatusResponse.model_validate(
        load_json("fixtures/valid/device-binding-status-response.json")
    )
    HeartbeatResponse.model_validate(
        load_json("fixtures/valid/heartbeat-response.json")
    )
    DeviceStatusChangeResponse.model_validate(
        load_json("fixtures/valid/device-status-change-response.json")
    )
    RecoverySecretResponse.model_validate(
        load_json("fixtures/valid/recovery-secret-response.json")
    )
    OwnerRecoveryResponse.model_validate(
        load_json("fixtures/valid/owner-recovery-response.json")
    )
    OwnerRecoverySecretResponse.model_validate(
        load_json("fixtures/valid/owner-recovery-secret-response.json")
    )
    OwnerRecoveryVerifyRequest.model_validate(
        load_json("fixtures/valid/owner-recovery-verify-request.json")
    )
    RecoveryRotationProvisionResponse.model_validate(
        load_json("fixtures/valid/recovery-rotation-provision-response.json")
    )
    RecoveryRotationResponse.model_validate(
        load_json("fixtures/valid/recovery-rotation-response.json")
    )


@pytest.mark.asyncio
async def test_strict_parser_accepts_valid_fixture():
    body = (FIXTURE_ROOT / "fixtures/valid/account-challenge-request.json").read_bytes()
    payload, document = await parse_protocol_body(
        make_request(body), AccountChallengeRequest
    )
    assert payload.request_id == document["request_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "model", "expected_code"),
    [
        (
            "fixtures/invalid/account-challenge-duplicate-member.json",
            AccountChallengeRequest,
            "protocol.invalid_json",
        ),
        (
            "fixtures/invalid/device-binding-request-extra-field.json",
            DeviceBindingRequest,
            "protocol.invalid_request",
        ),
        (
            "fixtures/invalid/device-binding-request-forbidden-data.json",
            DeviceBindingRequest,
            "protocol.invalid_request",
        ),
        (
            "fixtures/invalid/device-binding-request-signature-padding.json",
            DeviceBindingRequest,
            "protocol.invalid_request",
        ),
        (
            "fixtures/invalid/heartbeat-request-forbidden-data.json",
            HeartbeatRequest,
            "protocol.invalid_request",
        ),
        (
            "fixtures/invalid/recovery-record-provision-forbidden-data.json",
            RecoveryRecordProvisionRequest,
            "protocol.invalid_request",
        ),
        (
            "fixtures/invalid/owner-recovery-start-forbidden-data.json",
            OwnerRecoveryStartRequest,
            "protocol.invalid_request",
        ),
    ],
)
async def test_strict_parser_rejects_published_invalid_fixtures(
    path, model, expected_code
):
    with pytest.raises(AeternaProtocolException) as raised:
        await parse_protocol_body(
            make_request((FIXTURE_ROOT / path).read_bytes()), model
        )
    assert raised.value.code == expected_code


@pytest.mark.asyncio
async def test_strict_parser_rejects_media_type_bom_size_and_unknown_version():
    valid = load_json("fixtures/valid/account-challenge-request.json")
    cases = [
        (
            make_request(json.dumps(valid).encode(), "application/json; charset=utf-8"),
            "protocol.unsupported_media_type",
        ),
        (
            make_request(b"\xef\xbb\xbf" + json.dumps(valid).encode()),
            "protocol.invalid_json",
        ),
        (make_request(b" " * 16_385), "protocol.payload_too_large"),
        (
            make_request(json.dumps({**valid, "protocol_version": 2}).encode()),
            "protocol.unsupported_version",
        ),
        (
            make_request(json.dumps({**valid, "binding_id": None}).encode()),
            "protocol.invalid_request",
        ),
        (
            make_request(
                b'{"protocol_version":1,"request_id":"00000000-0000-4000-8000-000000000010",'
                b'"email":"owner\\ud800@example.com","purpose":"account_onboarding"}'
            ),
            "protocol.invalid_json",
        ),
    ]
    for request, expected_code in cases:
        with pytest.raises(AeternaProtocolException) as raised:
            await parse_protocol_body(request, AccountChallengeRequest)
        assert raised.value.code == expected_code


def test_client_registry_exposes_only_v1_protocol_and_safe_config_routes():
    configured_modules = {route.module_path for route in get_client_routes()}
    assert "app.api.client.v1.auth" not in configured_modules
    assert "app.api.client.v1.aeterna_identity" in configured_modules
    assert "app.api.client.v1.aeterna_heartbeat" in configured_modules
    assert "app.api.client.v1.aeterna_recovery" in configured_modules
    assert "app.api.client.v1.aeterna_setup" in configured_modules

    client_app = create_client_app()
    paths = set(client_app.openapi()["paths"])
    assert "/api/v1/account-challenges" in paths
    assert "/api/v1/device-bindings" in paths
    assert "/api/v1/heartbeats" in paths
    assert "/api/v1/policy" in paths
    assert "/api/v1/setup/status" in paths
    assert "/api/v1/device-status-changes" in paths
    assert "/api/v1/recovery/records/provision" in paths
    assert "/api/v1/recovery/records/enroll" in paths
    assert "/api/v1/recovery/records/{recovery_id}/confirm" in paths
    assert "/api/v1/recovery/records/{recovery_id}/abandon" in paths
    assert "/api/v1/recovery/claim/start" in paths
    assert "/api/v1/recovery/claim/verify" in paths
    for retired in (
        "/api/v1/recovery/claim/start",
        "/api/v1/recovery/claim/verify",
        "/api/v1/recovery/{recovery_id}/release-secret",
    ):
        operation = client_app.openapi()["paths"][retired]["post"]
        assert operation["deprecated"] is True
        assert "200" not in operation["responses"]
        assert "201" not in operation["responses"]
        assert operation["responses"]["400"]["content"]["application/json"][
            "schema"
        ] == {"$ref": "#/components/schemas/ProtocolErrorResponse"}
    assert "/api/v1/recovery/recipient/claim/start" in paths
    assert "/api/v1/recovery/recipient/claim/verify" in paths
    assert "/api/v1/recovery/recipient/secret" in paths
    for operation in ("provision", "prepare", "confirm", "abandon"):
        assert (
            f"/api/v1/recovery/recipient/rotations/{{rotation_id}}/{operation}" in paths
        )
    assert "/api/v1/recovery/custody/challenge" in paths
    assert "/api/v1/recovery/custody/verify" in paths
    assert "/api/v1/recovery/{recovery_id}/release-secret" in paths
    assert "/api/v1/recovery/owner/start" in paths
    assert "/api/v1/recovery/owner/verify" in paths
    assert "/api/v1/recovery/owner/{owner_recovery_id}/action" in paths
    assert "/api/v1/recovery/rotations/provision" in paths
    assert "/api/v1/recovery/rotations/{rotation_id}/confirm" in paths
    assert "/api/v1/auth/register" not in paths
    assert "/api/v1/auth/login" not in paths


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ("start", "verify", "secret"))
async def test_retired_unsigned_recovery_http_is_error_only_without_database(operation):
    def forbidden_database():
        raise AssertionError("Retired recovery must not open a database session")

    def forbidden_provider():
        raise AssertionError("Retired recovery must not obtain a KMS provider")

    app = create_client_app()
    app.dependency_overrides[get_db] = forbidden_database
    app.dependency_overrides[get_aeterna_recovery_service] = (
        lambda: AeternaRecoveryService(
            claim_provider=forbidden_provider,
            identity_key_provider=forbidden_provider,
        )
    )
    request_id = "00000000-0000-4000-8000-000000000001"
    recovery_id = "00000000-0000-4000-8000-000000000002"
    body = {"protocol_version": 1, "request_id": request_id}
    if operation == "secret":
        path = f"/api/v1/recovery/{recovery_id}/release-secret"
        body.update(
            claim_token="A" * 43,
            device_id="00000000-0000-4000-8000-000000000003",
            recovery_id=recovery_id,
            vault_id="00000000-0000-4000-8000-000000000004",
            wrapper_digest="A" * 43,
        )
    else:
        path = f"/api/v1/recovery/claim/{operation}"
        body["claim_link_token"] = "A" * 43
        if operation == "verify":
            body.update(challenge_id=recovery_id, code="12345678")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://synthetic.test"
    ) as client:
        response = await client.post(path, json=body)
    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "protocol_version": 1,
        "request_id": request_id,
        "error": {"code": "recovery.claim_unavailable"},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    ("start_claim", "verify_claim", "release_secret", "_start_claim", "_verify_claim"),
)
async def test_retired_recovery_service_cannot_use_database_or_provider(operation):
    class ForbiddenDatabase:
        def __getattr__(self, name):
            raise AssertionError("Retired scope must not read or mutate database state")

    def forbidden_provider():
        raise AssertionError("Retired scope must not obtain recovery or identity keys")

    service = AeternaRecoveryService(
        claim_provider=forbidden_provider, identity_key_provider=forbidden_provider
    )
    common = {
        "protocol_version": 1,
        "request_id": "00000000-0000-4000-8000-000000000001",
    }
    if "start" in operation:
        payload = RecoveryClaimStartRequest(**common, claim_link_token="A" * 43)
    elif "verify" in operation:
        payload = RecoveryClaimVerifyRequest(
            **common,
            claim_link_token="A" * 43,
            challenge_id="00000000-0000-4000-8000-000000000002",
            code="12345678",
        )
    else:
        payload = RecoverySecretRequest(
            **common,
            claim_token="A" * 43,
            device_id="00000000-0000-4000-8000-000000000002",
            recovery_id="00000000-0000-4000-8000-000000000003",
            vault_id="00000000-0000-4000-8000-000000000004",
            wrapper_digest="A" * 43,
        )
    kwargs = {"scope": "recovery.srs.read"} if operation.startswith("_") else {}
    with pytest.raises(AeternaProtocolException) as denied:
        await getattr(service, operation)(ForbiddenDatabase(), payload, **kwargs)
    assert denied.value.status_code == 400
    assert denied.value.code == "recovery.claim_unavailable"


def test_environment_key_provider_fails_closed_in_production(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    with pytest.raises(IdentityKeyUnavailable, match="KMS/HSM"):
        get_identity_keys()


def test_development_startup_allows_unconfigured_but_rejects_partial_keys(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "development")
    for field in (
        "AETERNA_PII_KEY_V1",
        "AETERNA_LOOKUP_KEY_V1",
        "AETERNA_OTP_KEY_V1",
    ):
        monkeypatch.setattr(settings, field, "")
    validate_identity_key_configuration()
    monkeypatch.setattr(settings, "AETERNA_PII_KEY_V1", "invalid")
    with pytest.raises(IdentityKeyUnavailable):
        validate_identity_key_configuration()


@pytest.mark.parametrize(
    "name,model",
    [
        ("owner-configuration-read", "OwnerConfigurationRequest"),
        ("notification-template-read", "NotificationTemplateReadRequest"),
        ("notification-template-edit", "NotificationTemplateEditRequest"),
    ],
)
def test_configuration_public_vectors_closed_schemas_and_cross_domain(name, model):
    from pydantic import ValidationError

    from app.schemas.client import aeterna_notification

    request_model = getattr(aeterna_notification, model)
    fixture = load_json(f"fixtures/signatures/{name}.json")
    document = load_json(f"fixtures/valid/{name}-request.json")
    request_model.model_validate(document)
    assert verify_signature(
        decode_base64url(fixture["public_key"], 32),
        fixture["document"],
        fixture["signature"],
    )
    cross = load_json(f"fixtures/signatures/{name}-cross-domain.json")["envelope"]
    assert not verify_signature(
        decode_base64url(fixture["public_key"], 32), cross["signed"], cross["signature"]
    )
    with pytest.raises(ValidationError):
        request_model.model_validate(
            load_json(f"fixtures/invalid/{name}-extra-field.json")
        )
