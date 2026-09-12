# Project PostgreSQL MCP

The repository includes a project-scoped PostgreSQL MCP server for AI-assisted
development data inspection and validation. It is intentionally read-only and
runs inside the existing backend development container, so database credentials
do not appear in `.codex/config.toml` or command arguments.

## Safety model

The integration uses several independent controls:

- A dedicated `NOLOGIN`, non-superuser PostgreSQL role.
- `SET LOCAL ROLE` before any tool query.
- A PostgreSQL `READ ONLY` transaction for every tool call.
- An allowlist of database schemas, defaulting to `public`.
- A statement timeout, lock timeout, and maximum result row count.
- One-statement validation and a read-oriented statement allowlist.
- Automatic redaction for sensitive-looking result columns and nested keys.
- MCP read-only annotations and a project-level tool allowlist.

These controls make the server appropriate for local development verification.
MCP results become model context, so do not connect this integration to a
production database containing unmasked personal or confidential data.

## Setup

Run all commands from the repository root.

1. Build and start the development stack:

   ```bash
   ./deploy.sh dev
   ```

2. Provision or refresh the restricted reader role and grants:

   ```bash
   ./deploy.sh mcp-setup
   ```

3. Restart the Codex project so it reloads `.codex/config.toml`. The project must
   be trusted for project-scoped configuration to load. Use `/mcp` to confirm
   that `project_postgresql` is connected.

Run `./deploy.sh mcp-setup` again after adding a schema to the allowlist. New
tables created by the normal application database owner receive reader access
through PostgreSQL default privileges.

## Tools

- `postgres_database_info`: verifies the database, server version, active reader
  role, allowed schemas, and read-only transaction state.
- `postgres_list_tables`: lists tables and views with estimated rows and sizes.
- `postgres_describe_table`: returns columns, constraints, indexes, and relation
  metadata.
- `postgres_query`: runs one bounded `SELECT`, `WITH`, `EXPLAIN`, `SHOW`, `TABLE`,
  or `VALUES` statement.

Recommended flow:

1. Call `postgres_database_info` to verify isolation.
2. Inspect available objects with `postgres_list_tables`.
3. Read the relevant contract with `postgres_describe_table`.
4. Use a narrow `postgres_query` to validate the data assumption.

Example requests to an AI assistant:

```text
Use the project PostgreSQL MCP to describe the users table.
Check whether any active users have a null email, and return only the count.
Explain the query plan for the sprint item list query without ANALYZE.
```

## Configuration

The following non-secret environment variables are optional:

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_MCP_ROLE` | `ai_mcp_reader` | Dedicated NOLOGIN role used after connection |
| `POSTGRES_MCP_ALLOWED_SCHEMAS` | `public` | Comma-separated schema allowlist |
| `POSTGRES_MCP_CONNECT_TIMEOUT_SECONDS` | `5` | Connection timeout, from 1 to 30 seconds |
| `POSTGRES_MCP_STATEMENT_TIMEOUT_MS` | `5000` | Per-query timeout, from 100 to 60000 ms |
| `POSTGRES_MCP_LOCK_TIMEOUT_MS` | `1000` | Lock timeout, from 100 to 10000 ms |

The MCP process reuses the backend container's existing `POSTGRES_*` variables.
Never copy their values into `.codex/config.toml`, documentation, or chat.

## Troubleshooting

- **Server unavailable:** run `./deploy.sh status`, then `./deploy.sh dev` if the
  backend is not running.
- **Reader role unavailable:** run `./deploy.sh mcp-setup`.
- **New table is not visible:** run `./deploy.sh mcp-setup` to refresh grants.
- **Query canceled:** narrow the query or, for local development only, raise
  `POSTGRES_MCP_STATEMENT_TIMEOUT_MS` within its allowed range and restart the
  MCP connection.
- **Schema is not allowed:** add it to `POSTGRES_MCP_ALLOWED_SCHEMAS`, restart the
  backend container, run `./deploy.sh mcp-setup`, and reconnect the MCP server.
