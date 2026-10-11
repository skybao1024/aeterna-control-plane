"""Constrain test notice links to an explicitly configured service origin."""

from urllib.parse import urlsplit


def validated_test_notice_origin(value: str, environment: str) -> str:
    if (
        not value
        or len(value) > 2048
        or any(ord(character) <= 32 for character in value)
    ):
        return ""
    try:
        parsed = urlsplit(value)
        if (
            parsed.hostname is None
            or parsed.port is not None
            and not 1 <= parsed.port <= 65535
        ):
            return ""
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            return ""
        if parsed.scheme == "https":
            return value.rstrip("/")
        if (
            environment == "development"
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            return value.rstrip("/")
    except ValueError:
        return ""
    return ""
