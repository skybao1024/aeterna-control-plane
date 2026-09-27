# Aeterna Control Plane

Private hosted-service repository for Aeterna. The control plane coordinates
accounts, registered devices, activity heartbeats, inactivity policies,
notifications, and delayed release of server-held recovery material.

The open-source desktop client is maintained separately. This repository is not
the vault and must never receive vault content, messages, media, attachments,
master passwords, emergency recovery codes, or vault data keys.

## Current status

The repository is a security-bounded application foundation, not a
production-ready control plane. It provides Docker orchestration, FastAPI,
PostgreSQL, Redis, Celery, email adapters, an authenticated backoffice shell,
and the protocol-v1 passwordless account/device binding boundary. Heartbeats,
policy lifecycle, contact delivery, and recovery remain separate later work.

## Quick start

Docker Desktop or Docker Engine with Compose v2 is required.

```bash
./deploy.sh init
./deploy.sh dev
```

Development endpoints:

- Backoffice UI: <http://localhost:3000>
- API: <http://localhost:8001>
- Client API docs: <http://localhost:8001/client/docs>
- Backoffice API docs: <http://localhost:8001/backoffice/docs>
- Health check: <http://localhost:8001/api/v1/config/health>

## Common commands

```bash
./deploy.sh dev
./deploy.sh prod
./deploy.sh stop
./deploy.sh restart dev
./deploy.sh logs backend
./deploy.sh status
./deploy.sh migrate
./deploy.sh mcp-setup
./deploy.sh monitoring
./verify-setup.sh dev
./verify-setup.sh prod
```

Do not run the backend directly on the host. Backend commands, tests, formatting,
and migrations run in the Docker Compose backend service. Frontend package
management uses `pnpm`.

## Configuration

`./deploy.sh init` copies the root `.env.example` to the ignored root `.env`.
Replace every example credential before any non-local deployment. Production
must use TLS, restricted origins, isolated environments, and managed secrets.
The I09 account identity module accepts explicit synthetic environment keys in
development and tests only. Production startup fails closed until a separately
approved KMS/HSM identity-key provider is implemented.

Runtime environment files are confidential. Never commit them or paste their
values into issues, logs, or AI conversations.

## Architecture and boundaries

See [ARCHITECTURE.md](./ARCHITECTURE.md) for service boundaries and the intended
domain layout. Backend documentation is indexed at
[`backend/docs/README.md`](./backend/docs/README.md).

The authoritative product and cryptographic design remains in the desktop
client repository. Control-plane changes that affect protocols, recovery,
retention, or the data boundary must update that design and receive an explicit
security review.

## Database migrations

Migrations run during deployment. Create new migrations inside the running
backend container:

```bash
docker compose exec backend alembic revision --autogenerate -m "describe_change"
./deploy.sh migrate
```

Do not rewrite migrations that may already have been applied.

## Repository status

This service repository is private and has no open-source license. Do not copy
the desktop client's license or describe the hosted control plane as open
source.
