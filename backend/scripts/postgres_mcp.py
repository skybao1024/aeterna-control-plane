"""Serve the project PostgreSQL MCP over stdio.

Working directory: ``/app`` inside the backend development container.
Arguments: none.
Execution: ``docker compose exec -T backend python scripts/postgres_mcp.py``.

The process reads the existing PostgreSQL environment variables without printing
them. Every tool call switches to a dedicated NOLOGIN reader role and runs inside
a PostgreSQL read-only transaction.
"""

from __future__ import annotations

import datetime as dt
import decimal
import math
import os
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Annotated, Any, TypeVar

import asyncpg
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

SERVER_INSTRUCTIONS = """Use this server only for read-only development database
inspection and validation. Inspect tables and columns before composing queries.
Never request credential, password, secret, or token values. All queries are bounded
by a statement timeout and row limit, run as a restricted PostgreSQL role in a READ
ONLY transaction, and redact sensitive-looking result columns."""
DEFAULT_ROLE = "ai_mcp_reader"
DEFAULT_ALLOWED_SCHEMAS = ("public",)
DEFAULT_STATEMENT_TIMEOUT_MS = 5_000
DEFAULT_LOCK_TIMEOUT_MS = 1_000
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5
DEFAULT_ROW_LIMIT = 200
MAX_ROW_LIMIT = 1_000
MAX_SQL_LENGTH = 50_000
MAX_CELL_CHARACTERS = 4_000
REDACTED_VALUE = "[REDACTED]"
ALLOWED_QUERY_KEYWORDS = {"EXPLAIN", "SELECT", "SHOW", "TABLE", "VALUES", "WITH"}
SENSITIVE_COLUMN_PATTERN = re.compile(
    r"(?:^|_)(?:api_?key|authorization|cookie|credentials?|pass(?:word|wd)?|"
    r"private_?key|secret|token)(?:_|$)",
    re.IGNORECASE,
)

READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    open_world_hint=False,
)

mcp = MCPServer(
    "project_postgresql",
    version="1.0.0",
    instructions=SERVER_INSTRUCTIONS,
    log_level="WARNING",
)

ResultT = TypeVar("ResultT")


class PostgresMCPError(ToolError):
    """Return a safe, actionable database error to the MCP client."""


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or not value.strip():
        raise PostgresMCPError(
            f"Required environment variable {name} is not configured."
        )
    return value.strip()


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    try:
        value = int(raw_value)
    except ValueError as exc:
        raise PostgresMCPError(f"{name} must be an integer.") from exc

    if not minimum <= value <= maximum:
        raise PostgresMCPError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _quote_identifier(value: str) -> str:
    if not value or "\x00" in value or len(value.encode("utf-8")) > 63:
        raise PostgresMCPError("PostgreSQL identifier is invalid or too long.")
    return '"' + value.replace('"', '""') + '"'


def _reader_role() -> str:
    return _env("POSTGRES_MCP_ROLE", DEFAULT_ROLE)


def _allowed_schemas() -> tuple[str, ...]:
    raw_value = os.getenv(
        "POSTGRES_MCP_ALLOWED_SCHEMAS", ",".join(DEFAULT_ALLOWED_SCHEMAS)
    )
    schemas = tuple(item.strip() for item in raw_value.split(",") if item.strip())
    if not schemas:
        raise PostgresMCPError(
            "POSTGRES_MCP_ALLOWED_SCHEMAS must contain at least one schema."
        )
    for schema in schemas:
        _quote_identifier(schema)
    return schemas


def _database_options() -> dict[str, Any]:
    ssl_required = os.getenv("POSTGRES_SSL_REQUIRE", "false").lower() in {
        "1",
        "true",
        "yes",
    }
    return {
        "user": _env("POSTGRES_USER"),
        "password": _env("POSTGRES_PASSWORD"),
        "database": _env("POSTGRES_DB"),
        "host": _env("POSTGRES_HOST", "postgres"),
        "port": _bounded_int("POSTGRES_PORT", 5432, 1, 65_535),
        "ssl": "require" if ssl_required else False,
        "timeout": _bounded_int(
            "POSTGRES_MCP_CONNECT_TIMEOUT_SECONDS",
            DEFAULT_CONNECT_TIMEOUT_SECONDS,
            1,
            30,
        ),
    }


def _strip_leading_comments(sql: str) -> str:
    remaining = sql.lstrip()
    while remaining:
        if remaining.startswith("--"):
            newline_index = remaining.find("\n")
            if newline_index == -1:
                return ""
            remaining = remaining[newline_index + 1 :].lstrip()
            continue

        if remaining.startswith("/*"):
            end_index = remaining.find("*/", 2)
            if end_index == -1:
                raise PostgresMCPError("SQL contains an unterminated block comment.")
            remaining = remaining[end_index + 2 :].lstrip()
            continue

        break
    return remaining


def _contains_multiple_statements(sql: str) -> bool:
    index = 0
    length = len(sql)
    state = "normal"
    block_depth = 0
    dollar_delimiter = ""

    while index < length:
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < length else ""

        if state == "line_comment":
            if char == "\n":
                state = "normal"
            index += 1
            continue

        if state == "block_comment":
            if char == "/" and next_char == "*":
                block_depth += 1
                index += 2
                continue
            if char == "*" and next_char == "/":
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
                continue
            index += 1
            continue

        if state == "single_quote":
            if char == "'" and next_char == "'":
                index += 2
                continue
            if char == "'":
                state = "normal"
            index += 1
            continue

        if state == "double_quote":
            if char == '"' and next_char == '"':
                index += 2
                continue
            if char == '"':
                state = "normal"
            index += 1
            continue

        if state == "dollar_quote":
            if sql.startswith(dollar_delimiter, index):
                index += len(dollar_delimiter)
                state = "normal"
                continue
            index += 1
            continue

        if char == "-" and next_char == "-":
            state = "line_comment"
            index += 2
            continue
        if char == "/" and next_char == "*":
            state = "block_comment"
            block_depth = 1
            index += 2
            continue
        if char == "'":
            state = "single_quote"
            index += 1
            continue
        if char == '"':
            state = "double_quote"
            index += 1
            continue
        if char == "$":
            match = re.match(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$", sql[index:])
            if match:
                dollar_delimiter = match.group(0)
                state = "dollar_quote"
                index += len(dollar_delimiter)
                continue
        if char == ";":
            trailing_sql = _strip_leading_comments(sql[index + 1 :]).strip()
            return bool(trailing_sql)
        index += 1

    return False


def _validate_query(sql: str) -> str:
    if not sql or not sql.strip():
        raise PostgresMCPError("SQL query cannot be empty.")
    if "\x00" in sql:
        raise PostgresMCPError("SQL query contains an invalid null byte.")
    if len(sql) > MAX_SQL_LENGTH:
        raise PostgresMCPError(
            f"SQL query exceeds the {MAX_SQL_LENGTH}-character limit."
        )
    if _contains_multiple_statements(sql):
        raise PostgresMCPError("Only one SQL statement is allowed per tool call.")

    leading_sql = _strip_leading_comments(sql)
    keyword_match = re.match(r"([A-Za-z]+)", leading_sql)
    keyword = keyword_match.group(1).upper() if keyword_match else ""
    if keyword not in ALLOWED_QUERY_KEYWORDS:
        allowed = ", ".join(sorted(ALLOWED_QUERY_KEYWORDS))
        raise PostgresMCPError(
            f"Only read-oriented statements are accepted. Allowed starters: {allowed}."
        )
    return sql.strip()


def _is_sensitive_column(column_name: str) -> bool:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", column_name).strip("_")
    return bool(SENSITIVE_COLUMN_PATTERN.search(normalized))


def _serialize_value(value: Any, key_hint: str | None = None) -> Any:
    if key_hint and _is_sensitive_column(key_hint) and value is not None:
        return REDACTED_VALUE
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        if len(value) <= MAX_CELL_CHARACTERS:
            return value
        omitted = len(value) - MAX_CELL_CHARACTERS
        return f"{value[:MAX_CELL_CHARACTERS]}... [{omitted} characters omitted]"
    if isinstance(value, bytes):
        return f"<binary {len(value)} bytes>"
    if isinstance(value, (dt.date, dt.time, dt.datetime)):
        return value.isoformat()
    if isinstance(value, (decimal.Decimal, uuid.UUID)):
        return str(value)
    if isinstance(value, Mapping):
        return {
            str(key): _serialize_value(nested_value, str(key))
            for key, nested_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_serialize_value(item) for item in value]
    return str(value)


def _record_to_dict(record: asyncpg.Record) -> dict[str, Any]:
    return {key: _serialize_value(value, key) for key, value in dict(record).items()}


async def _connect() -> asyncpg.Connection:
    try:
        return await asyncpg.connect(**_database_options())
    except (OSError, TimeoutError, asyncpg.PostgresError) as exc:
        raise PostgresMCPError(
            "Unable to connect to PostgreSQL. Start the development stack and verify "
            "the configured PostgreSQL environment variable names."
        ) from exc


async def _prepare_readonly_session(connection: asyncpg.Connection) -> None:
    role = _reader_role()
    schemas = _allowed_schemas()
    statement_timeout_ms = _bounded_int(
        "POSTGRES_MCP_STATEMENT_TIMEOUT_MS",
        DEFAULT_STATEMENT_TIMEOUT_MS,
        100,
        60_000,
    )
    lock_timeout_ms = _bounded_int(
        "POSTGRES_MCP_LOCK_TIMEOUT_MS",
        DEFAULT_LOCK_TIMEOUT_MS,
        100,
        10_000,
    )

    try:
        await connection.execute(f"SET LOCAL ROLE {_quote_identifier(role)}")
    except asyncpg.PostgresError as exc:
        raise PostgresMCPError(
            "The restricted PostgreSQL MCP role is unavailable. Run "
            "`./deploy.sh mcp-setup` from the repository root."
        ) from exc

    search_path = ", ".join(_quote_identifier(schema) for schema in schemas)
    await connection.fetchval(
        "SELECT set_config('search_path', $1, true)", f"{search_path}, pg_catalog"
    )
    await connection.fetchval(
        "SELECT set_config('statement_timeout', $1, true)",
        f"{statement_timeout_ms}ms",
    )
    await connection.fetchval(
        "SELECT set_config('lock_timeout', $1, true)", f"{lock_timeout_ms}ms"
    )
    await connection.fetchval(
        "SELECT set_config('idle_in_transaction_session_timeout', $1, true)",
        f"{statement_timeout_ms + 1_000}ms",
    )

    active_role = await connection.fetchval("SELECT current_user")
    read_only = await connection.fetchval(
        "SELECT current_setting('transaction_read_only')::boolean"
    )
    if active_role != role or not read_only:
        raise PostgresMCPError(
            "PostgreSQL MCP read-only isolation could not be verified."
        )


async def _run_readonly(
    operation: Callable[[asyncpg.Connection], Awaitable[ResultT]],
) -> ResultT:
    connection = await _connect()
    try:
        async with connection.transaction(readonly=True):
            await _prepare_readonly_session(connection)
            return await operation(connection)
    except PostgresMCPError:
        raise
    except asyncpg.QueryCanceledError as exc:
        raise PostgresMCPError(
            "PostgreSQL canceled the query because it exceeded the configured timeout."
        ) from exc
    except asyncpg.PostgresError as exc:
        message = str(exc).strip() or "PostgreSQL rejected the read-only query."
        raise PostgresMCPError(message) from exc
    finally:
        await connection.close()


def _require_allowed_schema(schema: str) -> str:
    if schema not in _allowed_schemas():
        allowed = ", ".join(_allowed_schemas())
        raise PostgresMCPError(
            f"Schema {schema!r} is not allowed. Configured schemas: {allowed}."
        )
    _quote_identifier(schema)
    return schema


@mcp.tool(
    title="PostgreSQL connection and isolation status",
    annotations=READ_ONLY_ANNOTATIONS,
)
async def postgres_database_info() -> dict[str, Any]:
    """Verify connectivity, server identity, and the active read-only role."""

    async def operation(connection: asyncpg.Connection) -> dict[str, Any]:
        record = await connection.fetchrow(
            """
            SELECT
                current_database() AS database_name,
                current_user AS active_role,
                current_setting('server_version') AS server_version,
                current_setting('transaction_read_only')::boolean AS read_only
            """
        )
        if record is None:
            raise PostgresMCPError("PostgreSQL did not return connection metadata.")
        return {
            **_record_to_dict(record),
            "allowed_schemas": list(_allowed_schemas()),
        }

    return await _run_readonly(operation)


@mcp.tool(
    title="List PostgreSQL tables and views",
    annotations=READ_ONLY_ANNOTATIONS,
)
async def postgres_list_tables(
    schema: Annotated[
        str,
        Field(description="Allowed PostgreSQL schema to inspect."),
    ] = "public",
) -> dict[str, Any]:
    """List tables, views, estimated row counts, and storage sizes in a schema."""

    schema = _require_allowed_schema(schema)

    async def operation(connection: asyncpg.Connection) -> dict[str, Any]:
        records = await connection.fetch(
            """
            SELECT
                c.relname AS name,
                CASE c.relkind
                    WHEN 'r' THEN 'table'
                    WHEN 'p' THEN 'partitioned-table'
                    WHEN 'v' THEN 'view'
                    WHEN 'm' THEN 'materialized-view'
                    WHEN 'f' THEN 'foreign-table'
                END AS kind,
                CASE
                    WHEN c.relkind IN ('r', 'p', 'm') THEN c.reltuples::bigint
                    ELSE NULL
                END AS estimated_rows,
                CASE
                    WHEN c.relkind IN ('r', 'p', 'm')
                        THEN pg_total_relation_size(c.oid)
                    ELSE NULL
                END AS total_bytes
            FROM pg_catalog.pg_class AS c
            JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = $1
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
            ORDER BY c.relname
            """,
            schema,
        )
        return {
            "schema": schema,
            "object_count": len(records),
            "objects": [_record_to_dict(record) for record in records],
        }

    return await _run_readonly(operation)


@mcp.tool(
    title="Describe a PostgreSQL table",
    annotations=READ_ONLY_ANNOTATIONS,
)
async def postgres_describe_table(
    table: Annotated[str, Field(description="Table or view name to inspect.")],
    schema: Annotated[
        str,
        Field(description="Allowed PostgreSQL schema containing the object."),
    ] = "public",
) -> dict[str, Any]:
    """Describe columns, constraints, indexes, row estimate, and storage size."""

    schema = _require_allowed_schema(schema)
    _quote_identifier(table)

    async def operation(connection: asyncpg.Connection) -> dict[str, Any]:
        relation = await connection.fetchrow(
            """
            SELECT
                c.oid,
                CASE c.relkind
                    WHEN 'r' THEN 'table'
                    WHEN 'p' THEN 'partitioned-table'
                    WHEN 'v' THEN 'view'
                    WHEN 'm' THEN 'materialized-view'
                    WHEN 'f' THEN 'foreign-table'
                END AS kind,
                CASE
                    WHEN c.relkind IN ('r', 'p', 'm') THEN c.reltuples::bigint
                    ELSE NULL
                END AS estimated_rows,
                CASE
                    WHEN c.relkind IN ('r', 'p', 'm')
                        THEN pg_total_relation_size(c.oid)
                    ELSE NULL
                END AS total_bytes
            FROM pg_catalog.pg_class AS c
            JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = $1
              AND c.relname = $2
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
            """,
            schema,
            table,
        )
        if relation is None:
            raise PostgresMCPError(f"Relation {schema}.{table} was not found.")

        columns = await connection.fetch(
            """
            SELECT
                column_name,
                data_type,
                udt_name,
                is_nullable = 'YES' AS nullable,
                CASE
                    WHEN column_name ~* '(password|secret|token|credential|api.?key)'
                        THEN '[REDACTED]'
                    ELSE column_default
                END AS column_default,
                character_maximum_length,
                numeric_precision,
                numeric_scale
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2
            ORDER BY ordinal_position
            """,
            schema,
            table,
        )
        constraints = await connection.fetch(
            """
            SELECT
                con.conname AS name,
                CASE con.contype
                    WHEN 'p' THEN 'primary-key'
                    WHEN 'f' THEN 'foreign-key'
                    WHEN 'u' THEN 'unique'
                    WHEN 'c' THEN 'check'
                    WHEN 'x' THEN 'exclusion'
                END AS kind,
                pg_get_constraintdef(con.oid, true) AS definition
            FROM pg_catalog.pg_constraint AS con
            WHERE con.conrelid = $1::oid
            ORDER BY con.conname
            """,
            relation["oid"],
        )
        indexes = await connection.fetch(
            """
            SELECT indexname AS name, indexdef AS definition
            FROM pg_catalog.pg_indexes
            WHERE schemaname = $1 AND tablename = $2
            ORDER BY indexname
            """,
            schema,
            table,
        )
        relation_data = _record_to_dict(relation)
        relation_data.pop("oid", None)
        return {
            "schema": schema,
            "name": table,
            **relation_data,
            "columns": [_record_to_dict(record) for record in columns],
            "constraints": [_record_to_dict(record) for record in constraints],
            "indexes": [_record_to_dict(record) for record in indexes],
        }

    return await _run_readonly(operation)


@mcp.tool(
    title="Run a read-only PostgreSQL query",
    annotations=READ_ONLY_ANNOTATIONS,
)
async def postgres_query(
    sql: Annotated[
        str,
        Field(
            description=(
                "One read-oriented PostgreSQL statement beginning with SELECT, WITH, "
                "EXPLAIN, SHOW, TABLE, or VALUES."
            )
        ),
    ],
    limit: Annotated[
        int,
        Field(
            ge=1,
            le=MAX_ROW_LIMIT,
            description="Maximum rows returned to model context.",
        ),
    ] = DEFAULT_ROW_LIMIT,
) -> dict[str, Any]:
    """Run one bounded query in a read-only transaction and return structured rows."""

    validated_sql = _validate_query(sql)

    async def operation(connection: asyncpg.Connection) -> dict[str, Any]:
        statement = await connection.prepare(validated_sql)
        columns = [attribute.name for attribute in statement.get_attributes()]
        rows: list[list[Any]] = []
        cursor = statement.cursor(prefetch=min(50, limit + 1))
        async for record in cursor:
            rows.append(
                [
                    _serialize_value(record[index], column_name)
                    for index, column_name in enumerate(columns)
                ]
            )
            if len(rows) > limit:
                break

        truncated = len(rows) > limit
        if truncated:
            rows.pop()
        redacted_columns = [
            column_name for column_name in columns if _is_sensitive_column(column_name)
        ]
        return {
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "truncated": truncated,
            "row_limit": limit,
            "redacted_columns": redacted_columns,
        }

    return await _run_readonly(operation)


if __name__ == "__main__":
    mcp.run()
