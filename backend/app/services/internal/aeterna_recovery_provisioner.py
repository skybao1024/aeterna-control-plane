"""Isolated KMS GenerateDataKey workload for recovery provisioning."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from app.services.common.aeterna_recovery_key import (
    DEFAULT_PROVISIONER_SOCKET,
    MAX_CIPHERTEXT_BYTES,
    SINGLE_REGION_KEY_ARN,
    SRS_BYTES,
    AwsKmsRecoveryKeyProvider,
    RecoveryKeyUnavailable,
    RecoveryProvisionProvider,
    validate_recovery_encryption_context,
)


@dataclass(frozen=True, repr=False)
class RecoveryProvisionerConfiguration:
    environment: str
    region: str
    key_arn: str
    socket_path: str


class RecoveryProvisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    context: dict[str, str]


class RecoveryProvisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    plaintext: str
    ciphertext: str
    key_arn: str
    key_material_id: str


def configuration_from_environment(
    environment: Mapping[str, str],
) -> RecoveryProvisionerConfiguration:
    enabled = environment.get("AETERNA_RECOVERY_KMS_ENABLED", "false").lower()
    region = environment.get("AETERNA_RECOVERY_KMS_REGION", "")
    key_arn = environment.get("AETERNA_RECOVERY_KMS_KEY_ARN", "")
    deployment_environment = environment.get("ENV", "")
    socket_path = environment.get("AETERNA_RECOVERY_PROVISIONER_SOCKET", "")
    if (
        environment.get("AETERNA_RECOVERY_KEY_PROVIDER") != "aws-kms"
        or enabled not in {"true", "1", "yes", "on", "t", "y"}
        or deployment_environment not in {"production", "preview"}
        or region != "ap-southeast-1"
        or SINGLE_REGION_KEY_ARN.fullmatch(key_arn) is None
        or socket_path != DEFAULT_PROVISIONER_SOCKET
    ):
        raise RecoveryKeyUnavailable("Recovery provisioner configuration is invalid")
    return RecoveryProvisionerConfiguration(
        environment=deployment_environment,
        region=region,
        key_arn=key_arn,
        socket_path=socket_path,
    )


def create_recovery_provisioner_app(
    configuration: RecoveryProvisionerConfiguration,
    *,
    provider: RecoveryProvisionProvider | None = None,
) -> FastAPI:
    provision_provider = provider or AwsKmsRecoveryKeyProvider(
        region=configuration.region,
        key_arn=configuration.key_arn,
    )
    app = FastAPI(
        title="Aeterna Recovery Provisioner",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.post("/v1/generate", response_model=RecoveryProvisionResponse)
    def generate(request: RecoveryProvisionRequest) -> RecoveryProvisionResponse:
        try:
            validate_recovery_encryption_context(
                request.context, environment=configuration.environment
            )
            envelope = provision_provider.generate_srs(request.context)
        except RecoveryKeyUnavailable:
            raise HTTPException(
                status_code=503, detail="Provisioning unavailable"
            ) from None
        try:
            if (
                not isinstance(envelope.plaintext, bytearray)
                or len(envelope.plaintext) != SRS_BYTES
                or not isinstance(envelope.ciphertext, bytes)
                or not envelope.ciphertext
                or len(envelope.ciphertext) > MAX_CIPHERTEXT_BYTES
                or envelope.key_arn != configuration.key_arn
                or envelope.key_material_id != configuration.key_arn
            ):
                raise HTTPException(status_code=503, detail="Provisioning unavailable")
            return RecoveryProvisionResponse(
                plaintext=base64.urlsafe_b64encode(bytes(envelope.plaintext))
                .rstrip(b"=")
                .decode("ascii"),
                ciphertext=base64.b64encode(envelope.ciphertext).decode("ascii"),
                key_arn=envelope.key_arn,
                key_material_id=envelope.key_material_id,
            )
        finally:
            if isinstance(envelope.plaintext, bytearray):
                envelope.plaintext[:] = b"\x00" * len(envelope.plaintext)

    return app
