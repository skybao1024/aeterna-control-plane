"""Unit tests for the project PostgreSQL MCP safeguards."""

import datetime as dt

import pytest

from scripts.postgres_mcp import (
    MAX_CELL_CHARACTERS,
    REDACTED_VALUE,
    PostgresMCPError,
    _is_sensitive_column,
    _serialize_value,
    _validate_query,
)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "WITH values_cte AS (SELECT 1) SELECT * FROM values_cte",
        "EXPLAIN SELECT * FROM users",
        "SHOW transaction_read_only",
        "TABLE users",
        "VALUES (1), (2)",
        "-- validation query\nSELECT 1;",
        "SELECT ';' AS punctuation",
        "SELECT $$value;still-one-statement$$",
    ],
)
def test_validate_query_accepts_read_oriented_single_statements(sql: str) -> None:
    assert _validate_query(sql) == sql.strip()


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM users",
        "INSERT INTO users (id) VALUES (1)",
        "UPDATE users SET email = 'changed@example.com'",
        "CREATE TABLE unexpected (id integer)",
        "SELECT 1; DROP TABLE users",
        "",
    ],
)
def test_validate_query_rejects_writes_and_stacked_statements(sql: str) -> None:
    with pytest.raises(PostgresMCPError):
        _validate_query(sql)


@pytest.mark.parametrize(
    "column_name",
    [
        "password_hash",
        "refresh_token",
        "api_key",
        "client_secret",
        "authorization_header",
        "session_cookie",
    ],
)
def test_sensitive_column_detection(column_name: str) -> None:
    assert _is_sensitive_column(column_name)


def test_serialize_value_redacts_sensitive_nested_keys() -> None:
    value = {
        "profile": {"display_name": "Ada"},
        "credentials": {"access_token": "do-not-return"},
    }

    assert _serialize_value(value) == {
        "profile": {"display_name": "Ada"},
        "credentials": REDACTED_VALUE,
    }


def test_serialize_value_bounds_large_and_binary_values() -> None:
    assert _serialize_value(b"binary") == "<binary 6 bytes>"
    assert _serialize_value(dt.date(2026, 9, 11)) == "2026-09-11"
    serialized = _serialize_value("x" * (MAX_CELL_CHARACTERS + 12))
    assert serialized.startswith("x" * MAX_CELL_CHARACTERS)
    assert serialized.endswith("[12 characters omitted]")
