"""Test notice origin configuration stays disjoint from normal frontend routing."""

import pytest

from app.services.common.aeterna_trigger_test_origin import validated_test_notice_origin


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://user@example.test",
        "https://example.test/path",
        "https://example.test?token=anything",
        "https://example.test#token",
        "http://remote.example.test",
        "https://example.test:99999",
        "https://example.test\n",
    ],
)
def test_invalid_or_missing_origins_disable_capability(value):
    assert validated_test_notice_origin(value, "production") == ""


def test_https_origin_is_canonical_and_local_http_is_development_only():
    assert (
        validated_test_notice_origin("https://service.example.test/", "production")
        == "https://service.example.test"
    )
    assert (
        validated_test_notice_origin("http://127.0.0.1:61835", "development")
        == "http://127.0.0.1:61835"
    )
    assert validated_test_notice_origin("http://127.0.0.1:61835", "production") == ""


@pytest.mark.asyncio
async def test_notice_landing_is_static_and_never_consumes_get_tokens():
    from httpx import ASGITransport, AsyncClient

    from app.route import create_app

    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://synthetic.invalid"
    ) as client:
        response = await client.get(
            "/trigger-tests/notice?token=synthetic-ignored-query"
        )
    assert response.status_code == 200
    assert (
        "<script" not in response.text
        and "synthetic-ignored-query" not in response.text
    )
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    assert response.headers["cache-control"] == "no-store"
