# Aeterna Control Plane Backend

FastAPI backend for Aeterna's private hosted control plane.

Use the repository-root Docker workflow. Do not create a local Python virtual
environment or run the API, tests, formatters, migrations, or scripts directly
on the host.

## Responsibilities

- Authenticate owners, registered devices, recovery claims, and operators.
- Store device public keys, heartbeat receipt times, policies, contacts, and
  notification state.
- Execute the warning, grace, release, and notification state machines.
- Deliver notifications through audited provider adapters.
- Store server-held recovery material only through an approved KMS/HSM design.

The backend must never accept vault content, messages, media, attachments,
master passwords, emergency recovery codes, or vault data keys.

## Development

Run commands from the repository root:

```bash
./deploy.sh init
./deploy.sh dev
./deploy.sh logs backend
./deploy.sh migrate
docker compose exec backend pytest
docker compose exec backend black --check .
docker compose exec backend isort --check-only .
docker compose exec backend flake8 .
```

API documentation is available only in development and preview environments:

- Client API: <http://localhost:8001/client/docs>
- Backoffice API: <http://localhost:8001/backoffice/docs>

## Structure

```text
app/api/          Thin HTTP routes
app/services/     Business logic and transaction boundaries
app/models/       SQLAlchemy persistence models
app/schemas/      Request and response contracts
app/schedule/     Celery task registration
migrations/       Alembic migrations
scripts/          Container-only operational and diagnostic scripts
tests/            Automated tests
docs/             Backend-specific documentation
```

See the root `AGENTS.md`, `ARCHITECTURE.md`, and `README.md` before changing the
service.
