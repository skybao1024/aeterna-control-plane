"""Strict transport parsing and responses for Aeterna public protocol v1."""

import json
import math
import re
from typing import Any, Optional, TypeVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from app.exceptions.aeterna_protocol import AeternaProtocolException

MAX_BODY_BYTES = 16_384
PROTOCOL_VERSION = 1
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
T = TypeVar("T", bound=BaseModel)


class _DuplicateMember(ValueError):
    pass


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateMember
        result[key] = value
    return result


def _i_json_integer(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > 9_007_199_254_740_991:
        raise ValueError("integer is outside the I-JSON exact range")
    return parsed


def _i_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("number is not finite")
    return parsed


def _reject_constant(_: str) -> None:
    raise ValueError("non-I-JSON numeric constant")


def _validate_i_json_strings(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("unpaired Unicode surrogate")
        return
    if isinstance(value, list):
        for item in value:
            _validate_i_json_strings(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_i_json_strings(key)
            _validate_i_json_strings(item)


def request_id_from_document(document: Any) -> Optional[str]:
    if not isinstance(document, dict):
        return None
    candidate = document.get("request_id")
    if candidate is None and isinstance(document.get("signed"), dict):
        candidate = document["signed"].get("request_id")
    return (
        candidate
        if isinstance(candidate, str) and UUID_PATTERN.fullmatch(candidate)
        else None
    )


async def parse_protocol_body(
    request: Request, model: type[T]
) -> tuple[T, dict[str, Any]]:
    """Parse a bounded exact-JSON request before Pydantic business validation."""
    if request.headers.get("content-type") != "application/json":
        raise AeternaProtocolException(415, "protocol.unsupported_media_type")

    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > MAX_BODY_BYTES:
            raise AeternaProtocolException(413, "protocol.payload_too_large")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise AeternaProtocolException(400, "protocol.invalid_json")

    try:
        text = bytes(raw).decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_closed_object,
            parse_int=_i_json_integer,
            parse_float=_i_json_float,
            parse_constant=_reject_constant,
        )
        _validate_i_json_strings(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, _DuplicateMember):
        raise AeternaProtocolException(400, "protocol.invalid_json") from None

    request_id = request_id_from_document(document)
    if not isinstance(document, dict):
        raise AeternaProtocolException(400, "protocol.invalid_request", request_id)
    if document.get("protocol_version") != PROTOCOL_VERSION:
        raise AeternaProtocolException(
            400,
            "protocol.unsupported_version",
            request_id,
            supported_protocol_versions=[PROTOCOL_VERSION],
        )
    signed = document.get("signed")
    if isinstance(signed, dict) and (
        signed.get("protocol_version") != PROTOCOL_VERSION
        or signed.get("signature_version") != 1
        or signed.get("canonicalization") != "jcs-rfc8785"
    ):
        raise AeternaProtocolException(
            400,
            "protocol.unsupported_version",
            request_id,
            supported_protocol_versions=[PROTOCOL_VERSION],
        )

    try:
        return model.model_validate(document), document
    except ValidationError:
        raise AeternaProtocolException(
            400, "protocol.invalid_request", request_id
        ) from None


def protocol_response(
    request_id: str,
    data: dict[str, Any],
    status_code: int = 200,
    *,
    no_store: bool = False,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        headers={"Cache-Control": "no-store"} if no_store else None,
        content={
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "data": data,
        },
    )


def protocol_error_response(exc: AeternaProtocolException) -> JSONResponse:
    error: dict[str, Any] = {"code": exc.code}
    if exc.retry_after_seconds is not None:
        error["retry_after_seconds"] = exc.retry_after_seconds
    if exc.supported_protocol_versions is not None:
        error["supported_protocol_versions"] = exc.supported_protocol_versions
    content: dict[str, Any] = {"protocol_version": PROTOCOL_VERSION, "error": error}
    if exc.request_id is not None:
        content["request_id"] = exc.request_id
    return JSONResponse(status_code=exc.status_code, content=content)


def install_protocol_exception_handler(app: FastAPI) -> None:
    async def handler(_request: Request, exc: AeternaProtocolException) -> JSONResponse:
        return protocol_error_response(exc)

    app.add_exception_handler(AeternaProtocolException, handler)


def openapi_request(model: type[BaseModel]) -> dict[str, Any]:
    """Document a manually parsed body without delegating parsing to FastAPI."""
    return {
        "requestBody": {
            "content": {"application/json": {"schema": model.model_json_schema()}},
            "required": True,
        }
    }
