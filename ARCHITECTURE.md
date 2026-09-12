# Architecture

The root Docker Compose files define one application network and keep service discovery internal. Browser traffic enters through Vite in development or Nginx in production.

```text
Browser
  |
  +-- development: Vite :3000 -- /api --> FastAPI :8001
  |
  +-- production:  Nginx :8080 -- /api --> FastAPI :8001
                                           |       |
                                           |       +--> Redis
                                           +----------> PostgreSQL

Celery Worker <--> Redis <--> Celery Beat
Flower (optional) --> Celery/Redis
```

## Application modules

### Backend

- `backend/app/route/route.py` creates the FastAPI applications and configures shared middleware and exception handling.
- `backend/app/route/router_registry.py` centralizes client and backoffice route registration.
- `backend/app/api/` contains versioned client and backoffice route handlers; `backend/app/api/docs_export.py` provides OpenAPI document exports.
- `backend/app/services/` contains business logic grouped by client, backoffice, and shared concerns.
- `backend/app/schemas/` contains request, response, pagination, and shared Pydantic schemas.
- `backend/app/models/` contains SQLAlchemy models, while `backend/app/db/` owns engines, sessions, and transaction support.
- `backend/app/core/` contains application settings, security, logging, and Celery configuration.
- `backend/app/configs/` contains the client and backoffice Swagger/OpenAPI metadata and documentation application configuration.
- `backend/app/schedule/` contains Celery scheduling support and job implementations.
- `backend/migrations/` contains Alembic configuration and migration revisions.

### Frontend

- `frontend/src/router/` defines application routes and route guards.
- `frontend/src/pages/` contains route-level React pages, and `frontend/src/components/` contains reusable UI.
- `frontend/src/apis/` contains backend API clients.
- `frontend/src/store/` contains Zustand state stores, while `frontend/src/context/` and `frontend/src/hooks/` contain React context and reusable hooks.
- `frontend/src/utils/` contains HTTP and messaging utilities.
- `frontend/src/theme/` and `frontend/src/assets/` contain Ant Design theme configuration, shared styles, and SVG assets.

## Compose layers

- `docker-compose.yml` contains the shared topology, health checks, private network, and persistent volumes.
- `docker-compose.dev.yml` selects development images, bind-mounts source code, and exposes infrastructure ports on localhost.
- `docker-compose.prod.yml` selects production application settings and exposes the Nginx frontend plus a localhost-only backend diagnostics port.

## Extension points

- Add API routes under `backend/app/api/` and keep business logic in `backend/app/services/`.
- Add database models under `backend/app/models/` and migrations under `backend/migrations/versions/`.
- Add background jobs under `backend/app/schedule/jobs/`.
- Add React pages under `frontend/src/pages/` and reusable UI under `frontend/src/components/`.
- Add external infrastructure by replacing the service host variables and adapting the Compose dependency declarations for the target platform.

Infrastructure credentials remain in the ignored root `.env` file. Only `.env.example` belongs in source control.
