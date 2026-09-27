"""Stable public errors for Aeterna protocol v1."""

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class AeternaProtocolException(Exception):
    """An expected public failure with a stable nonlocalized error code."""

    status_code: int
    code: str
    request_id: Optional[str] = None
    retry_after_seconds: Optional[int] = None
    supported_protocol_versions: Optional[list[int]] = None
