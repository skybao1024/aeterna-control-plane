# Development Workflow

Use the Docker-first commands documented in the root `AGENTS.md` and `README.md`.
Do not create a backend virtual environment or run backend Python tooling on the
host.

```bash
./deploy.sh dev
docker compose exec backend pytest
docker compose exec backend black --check .
docker compose exec backend isort --check-only .
docker compose exec backend flake8 .
```

Frontend work uses `pnpm` from `frontend/`:

```bash
pnpm type-check
pnpm lint
pnpm build
```

Implement each domain vertically: migration and model, schemas, injected
service, thin routes, OpenAPI registration, and tests. Do not add placeholder
production routes or scheduled jobs merely to demonstrate framework behavior.
