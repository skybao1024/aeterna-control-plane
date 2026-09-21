# Aeterna Control Plane Documentation

This directory contains backend-specific documentation. The desktop repository
remains authoritative for product behavior, cryptography, recovery UX, and the
public client protocol.

## Architecture

- [Project architecture](./architecture/project-architecture.md)
- [Docker deployment](./architecture/docker-deployment.md)
- [ADR 0001: Account-policy transaction and outage semantics](./architecture/adr/0001-account-policy-transaction-and-outage-semantics.md)

## API

- [OpenAPI and Swagger](./api/swagger-guide.md)

## Development

- [Development workflow](./development/development-framework.md)
- [Read-only PostgreSQL MCP](./development/postgresql-mcp.md)
- [I03 concurrency prototype results](./development/i03-concurrency-prototype-results.md)

## Security

- [Secret handling and AI isolation](./security/ai-security-isolation.md)

Documents from the original template are not architectural authority. If a
document conflicts with the root `AGENTS.md`, `ARCHITECTURE.md`, or the desktop
design, follow the root guidance and update the stale document.
