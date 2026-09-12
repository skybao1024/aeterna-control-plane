# Sprint Flow Demo Starter

A Docker-first starter for a React/Vite frontend and a FastAPI backend. The root Compose configuration is the canonical way to run the project and includes PostgreSQL, Redis, Celery, and optional Flower monitoring.

The repository intentionally contains framework scaffolding only. Add product-specific routes, models, jobs, and pages inside the existing backend and frontend structures.

## Quick start

Requirements: Docker Desktop (or Docker Engine) with Docker Compose v2.

```bash
./deploy.sh init
./deploy.sh dev
```

The default development endpoints are:

- Frontend: <http://localhost:3000>
- Backend API: <http://localhost:8001>
- Client API docs: <http://localhost:8001/client/docs>
- Health check: <http://localhost:8001/api/v1/config/health>
- PostgreSQL (development only): `localhost:5436`
- Redis (development only): `localhost:6386`

The development profile mounts both source directories into their containers. Vite and Uvicorn reload changes automatically.

## Commands

```bash
./deploy.sh dev                 # Development images and hot reload
./deploy.sh prod                # Production images and Nginx frontend
./deploy.sh stop                # Keep database and Redis volumes
./deploy.sh restart dev
./deploy.sh logs backend
./deploy.sh status
./deploy.sh migrate
./deploy.sh mcp-setup             # Provision the AI read-only PostgreSQL role
./deploy.sh monitoring          # Flower at http://localhost:5556 by default
./verify-setup.sh dev
./verify-setup.sh prod
```

Equivalent raw Compose commands:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

## Configuration

`./deploy.sh init` copies `.env.example` to the ignored root `.env` file. Compose passes that environment to the backend, workers, and infrastructure services. Frontend browser requests use `/api`; Vite in development and Nginx in production proxy that path to the backend container.

Before a real deployment, replace the example PostgreSQL, Redis, Flower, and application secret values, set the public `FRONTEND_URL`, and place the stack behind a TLS reverse proxy. Ports bind to `127.0.0.1` by default; change `BIND_ADDRESS` only when remote access is intentional.

Persistent data is held in named Docker volumes. `./deploy.sh stop` does not delete those volumes.

## Project structure

```text
.
├── backend/                 # FastAPI, SQLAlchemy, Alembic, and Celery
├── frontend/                # React, TypeScript, and Vite
├── docker-compose.yml       # Shared service topology
├── docker-compose.dev.yml   # Development builds, mounts, and exposed ports
├── docker-compose.prod.yml  # Production runtime ports and environment
├── deploy.sh                # Lifecycle commands
└── verify-setup.sh          # Static setup validation
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for service boundaries and extension guidance.

For AI-assisted database inspection, the trusted project config includes a
read-only PostgreSQL MCP server. After starting development, run
`./deploy.sh mcp-setup`, restart the Codex project, and see
[`backend/docs/development/postgresql-mcp.md`](./backend/docs/development/postgresql-mcp.md)
for tools and safeguards.

## Database migrations

Migrations run automatically after `./deploy.sh dev` or `./deploy.sh prod`. Run them manually with:

```bash
./deploy.sh migrate
```

Create a migration inside the running backend container:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec backend \
  alembic revision --autogenerate -m "describe_change"
```

## Monitoring

Flower is isolated behind the `monitoring` profile:

```bash
./deploy.sh monitoring
```

Set non-default `FLOWER_USER` and `FLOWER_PASSWORD` values before using it outside local development.
