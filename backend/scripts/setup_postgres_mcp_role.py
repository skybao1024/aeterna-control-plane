"""Provision the restricted PostgreSQL role used by the project MCP.

Working directory: ``/app`` inside the backend development container.
Arguments: none.
Execution: ``docker compose exec -T backend python scripts/setup_postgres_mcp_role.py``.

The script is idempotent. It reads database credentials from the container
environment and never prints them.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import asyncpg

DEFAULT_ROLE = "ai_mcp_reader"
DEFAULT_ALLOWED_SCHEMAS = ("public",)


def _env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or not value.strip():
        raise RuntimeError(f"Required environment variable {name} is not configured.")
    return value.strip()


def _bounded_port() -> int:
    try:
        port = int(_env("POSTGRES_PORT", "5432"))
    except ValueError as exc:
        raise RuntimeError("POSTGRES_PORT must be an integer.") from exc
    if not 1 <= port <= 65_535:
        raise RuntimeError("POSTGRES_PORT must be between 1 and 65535.")
    return port


def _quote_identifier(value: str) -> str:
    if not value or "\x00" in value or len(value.encode("utf-8")) > 63:
        raise RuntimeError("PostgreSQL identifier is invalid or too long.")
    return '"' + value.replace('"', '""') + '"'


def _allowed_schemas() -> tuple[str, ...]:
    raw_value = os.getenv(
        "POSTGRES_MCP_ALLOWED_SCHEMAS", ",".join(DEFAULT_ALLOWED_SCHEMAS)
    )
    schemas = tuple(item.strip() for item in raw_value.split(",") if item.strip())
    if not schemas:
        raise RuntimeError(
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
        "port": _bounded_port(),
        "ssl": "require" if ssl_required else False,
        "timeout": 5,
    }


async def _validate_existing_role(connection: asyncpg.Connection, role: str) -> bool:
    attributes = await connection.fetchrow(
        """
        SELECT
            oid,
            rolcanlogin,
            rolsuper,
            rolcreatedb,
            rolcreaterole,
            rolreplication,
            rolbypassrls
        FROM pg_catalog.pg_roles
        WHERE rolname = $1
        """,
        role,
    )
    if attributes is None:
        return False

    unsafe_attributes = [
        name
        for name in (
            "rolcanlogin",
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        )
        if attributes[name]
    ]
    if unsafe_attributes:
        joined_attributes = ", ".join(unsafe_attributes)
        raise RuntimeError(
            f"Existing MCP role has unsafe attributes: {joined_attributes}. "
            "Choose a new POSTGRES_MCP_ROLE instead of modifying it automatically."
        )

    parent_roles = await connection.fetch(
        """
        SELECT parent.rolname
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS parent ON parent.oid = membership.roleid
        WHERE membership.member = $1
        """,
        attributes["oid"],
    )
    if parent_roles:
        raise RuntimeError(
            "Existing MCP role inherits another role. Choose a new "
            "POSTGRES_MCP_ROLE to preserve least privilege."
        )
    return True


async def setup_role() -> None:
    """Create the NOLOGIN role and grant read-only access to allowed schemas."""

    role = _env("POSTGRES_MCP_ROLE", DEFAULT_ROLE)
    schemas = _allowed_schemas()
    quoted_role = _quote_identifier(role)
    connection = await asyncpg.connect(**_database_options())
    try:
        async with connection.transaction():
            role_exists = await _validate_existing_role(connection, role)
            if not role_exists:
                await connection.execute(
                    f"CREATE ROLE {quoted_role} NOLOGIN NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                )

            session_user = await connection.fetchval("SELECT session_user")
            database_name = await connection.fetchval("SELECT current_database()")
            await connection.execute(
                f"GRANT {quoted_role} TO {_quote_identifier(session_user)}"
            )
            await connection.execute(
                f"GRANT CONNECT ON DATABASE {_quote_identifier(database_name)} "
                f"TO {quoted_role}"
            )

            for schema in schemas:
                schema_exists = await connection.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace "
                    "WHERE nspname = $1)",
                    schema,
                )
                if not schema_exists:
                    raise RuntimeError(f"Configured schema {schema!r} does not exist.")

                quoted_schema = _quote_identifier(schema)
                await connection.execute(
                    f"GRANT USAGE ON SCHEMA {quoted_schema} TO {quoted_role}"
                )
                await connection.execute(
                    f"GRANT SELECT ON ALL TABLES IN SCHEMA {quoted_schema} "
                    f"TO {quoted_role}"
                )
                await connection.execute(
                    f"ALTER DEFAULT PRIVILEGES IN SCHEMA {quoted_schema} "
                    f"GRANT SELECT ON TABLES TO {quoted_role}"
                )
    finally:
        await connection.close()

    print("PostgreSQL MCP reader role is ready for schemas: " + ", ".join(schemas))


if __name__ == "__main__":
    asyncio.run(setup_role())
