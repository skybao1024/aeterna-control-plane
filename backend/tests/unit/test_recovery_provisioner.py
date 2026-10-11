"""Unit evidence for the isolated recovery provisioner process."""

import base64

import httpx
import pytest

from app.services.common.aeterna_recovery_key import (
    GeneratedSrsEnvelope,
    RecoveryKeyUnavailable,
)
from app.services.internal.aeterna_recovery_provisioner import (
    RecoveryProvisionerConfiguration,
    configuration_from_environment,
    create_recovery_provisioner_app,
)

KEY_ARN = (
    "arn:aws:kms:ap-southeast-1:111122223333:key/"
    "00000000-0000-4000-8000-000000000099"
)


def recovery_context() -> dict[str, str]:
    return {
        "aeterna-purpose": "recovery-srs",
        "aeterna-environment": "production",
        "aeterna-context-version": "1",
        "aeterna-binding": "A" * 43,
    }


class FakeProvisionProvider:
    def __init__(
        self,
        *,
        plaintext: bytes = bytes([0x55]) * 32,
        ciphertext: bytes = bytes([0x66]) * 96,
        key_arn: str = KEY_ARN,
    ):
        self.context = None
        self.plaintext = bytearray(plaintext)
        self.ciphertext = ciphertext
        self.key_arn = key_arn

    def generate_srs(self, received_context):
        self.context = received_context
        return GeneratedSrsEnvelope(
            plaintext=self.plaintext,
            ciphertext=self.ciphertext,
            key_arn=self.key_arn,
            key_material_id=self.key_arn,
        )


def configuration() -> RecoveryProvisionerConfiguration:
    return RecoveryProvisionerConfiguration(
        environment="production",
        region="ap-southeast-1",
        key_arn=KEY_ARN,
        socket_path="/app/recovery-provisioner/provisioner.sock",
    )


def test_configuration_requires_the_complete_production_boundary():
    environment = {
        "ENV": "production",
        "AETERNA_RECOVERY_KEY_PROVIDER": "aws-kms",
        "AETERNA_RECOVERY_KMS_ENABLED": "true",
        "AETERNA_RECOVERY_KMS_REGION": "ap-southeast-1",
        "AETERNA_RECOVERY_KMS_KEY_ARN": KEY_ARN,
        "AETERNA_RECOVERY_PROVISIONER_SOCKET": (
            "/app/recovery-provisioner/provisioner.sock"
        ),
    }
    assert configuration_from_environment(environment) == configuration()
    for key in environment:
        invalid = {**environment}
        invalid.pop(key)
        with pytest.raises(RecoveryKeyUnavailable):
            configuration_from_environment(invalid)
    with pytest.raises(RecoveryKeyUnavailable):
        configuration_from_environment(
            {
                **environment,
                "AETERNA_RECOVERY_PROVISIONER_SOCKET": (
                    "/app/recovery-provisioner/alternate.sock"
                ),
            }
        )


@pytest.mark.asyncio
async def test_provisioner_returns_only_validated_material_and_zeroes_plaintext():
    provider = FakeProvisionProvider()
    app = create_recovery_provisioner_app(configuration(), provider=provider)
    production_context = recovery_context()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://provisioner"
    ) as client:
        health = await client.get("/health")
        response = await client.post(
            "/v1/generate", json={"context": production_context}
        )
    assert health.json() == {"status": "healthy"}
    assert response.status_code == 200
    assert response.json() == {
        "plaintext": base64.urlsafe_b64encode(bytes([0x55]) * 32)
        .rstrip(b"=")
        .decode("ascii"),
        "ciphertext": base64.b64encode(bytes([0x66]) * 96).decode("ascii"),
        "key_arn": KEY_ARN,
        "key_material_id": KEY_ARN,
    }
    assert provider.context == production_context
    assert provider.plaintext == bytearray(bytes(32))


@pytest.mark.asyncio
async def test_provisioner_rejects_wrong_context_without_calling_provider():
    provider = FakeProvisionProvider()
    app = create_recovery_provisioner_app(configuration(), provider=provider)
    invalid_context = {**recovery_context(), "aeterna-environment": "preview"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://provisioner"
    ) as client:
        response = await client.post("/v1/generate", json={"context": invalid_context})
    assert response.status_code == 503
    assert response.json() == {"detail": "Provisioning unavailable"}
    assert provider.context is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider",
    [
        FakeProvisionProvider(plaintext=bytes(31)),
        FakeProvisionProvider(ciphertext=b""),
        FakeProvisionProvider(key_arn=KEY_ARN.replace("00000000", "10000000", 1)),
    ],
)
async def test_provisioner_rejects_invalid_provider_material_and_zeroes_plaintext(
    provider,
):
    app = create_recovery_provisioner_app(configuration(), provider=provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://provisioner"
    ) as client:
        response = await client.post(
            "/v1/generate", json={"context": recovery_context()}
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "Provisioning unavailable"}
    assert provider.plaintext == bytearray(len(provider.plaintext))
