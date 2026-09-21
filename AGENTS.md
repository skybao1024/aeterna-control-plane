# AGENTS.md

Repository-wide instructions for AI coding assistants working in this full-stack project.

## Security: Environment Files and Credentials

### Absolute Prohibition

Never read, display, search, quote, summarize, or expose values from runtime or secret environment files, including:

- Root `.env`
- `.env.local` and `.env.production`
- Any other environment file that may contain real credentials

Never use file-reading tools, shell commands, Compose output, or diagnostics to inspect protected environment files or expose their values, and never ask the user to paste secrets into the conversation. This restriction does not limit normal reading or searching of source code, tests, documentation, or the safe configuration sources below.

### Safe Configuration Sources

- Read `.env.example` files for variable names, structure, and non-secret defaults.
- The committed frontend `.env.dev` and `.env.prod` files may be read only while they remain non-secret client configuration. If there is any doubt, do not read them.
- Reference secrets in code with environment-variable access such as `os.getenv("VARIABLE_NAME")`.
- Use placeholders such as `***REDACTED***`, `<SECRET>`, or `[MASKED]` in examples.
- Never put real credentials in code, tests, logs, documentation, fixtures, or responses.

### External-Service Diagnostics

When debugging AWS, OpenAI, Stripe, email, or another credential-backed service:

1. Work from error messages, stack traces, symptoms, and environment-variable names only.
2. Use `.env.example` to understand the expected configuration.
3. Generate a diagnostic script that references environment variables without printing them.
4. Ask the user to run credential-backed diagnostics locally and share only sanitized output.

If the user pastes a credential, immediately warn that it has been exposed in the conversation, recommend rotating it after the session, and recommend test or sandbox credentials for future debugging.

## Language and Documentation

- All identifiers, code comments, docstrings, internal documentation, API descriptions, response examples, exception messages, log messages, and commit messages must be in English.
- User-facing application text may use any language through the project's localization approach.
- Respond to the user in Chinese when requested; this does not change the English-only rule for repository artifacts.
- Use modern, non-deprecated language and framework syntax.

## Repository Workflow

### Docker-First Development

This repository uses Docker Compose to manage the frontend, backend, PostgreSQL, Redis, Celery worker, Celery beat, and optional Flower monitoring.

Use the repository scripts for normal development:

- `./deploy.sh dev` — build and start the development environment
- `./deploy.sh prod` — build and start the production-like environment
- `./deploy.sh stop` — stop services without deleting persistent data
- `./deploy.sh restart [dev|prod]` — restart an environment
- `./deploy.sh logs [service]` — follow logs
- `./deploy.sh status` — show service status
- `./deploy.sh migrate` — run Alembic migrations in the backend container
- `./deploy.sh monitoring` — start Flower
- `./verify-setup.sh` — verify the repository setup

Do not start the application manually on the host with `python main.py`. Normal application and API testing must use the Docker environment so PostgreSQL, Redis, and background services match the deployed architecture. Docker images and Compose services may invoke `python main.py` internally.

### Tooling Policy

- Do not create or use a local Python virtual environment for backend work.
- Run all backend application commands, tests, linting, formatting, and diagnostics inside the Docker Compose backend service.
- Start the development environment with `./deploy.sh dev` before running focused backend commands with `docker compose exec backend ...`.
- Frontend package management must use `pnpm`, not npm or yarn.
- Follow the Backend Rules and Frontend Rules sections below for language-specific checks.

## Full-Stack Coordination

- Treat the backend API contract and frontend API client as one change boundary.
- When adding or changing a backend endpoint, update the corresponding module under `frontend/src/apis/` when the frontend consumes it.
- When a backend API contract changes, keep its generated Swagger/OpenAPI documentation accurate according to the Backend Rules section below.
- Keep request and response schemas, authentication behavior, status codes, and user-visible error handling aligned across both layers.
- Production frontend traffic under `/api/*` is proxied to the backend; do not introduce environment-specific hard-coded backend URLs.
- Keep database and business transactions in the backend service layer; keep route handlers focused on transport concerns.

## Repository-Level Files and Documentation

- Check for an existing file or implementation before creating a new one.
- Keep root-level scripts limited to repository-wide orchestration that coordinates multiple services, such as `deploy.sh` and `verify-setup.sh`.
- Do not place backend-dependent scripts in a root-level `scripts/` or `shell/` directory. Backend scripts, diagnostics, and documentation follow the explicit paths in the Backend Rules section so their runtime context is unambiguous.
- If frontend-specific scripts or documentation are introduced, keep them under `frontend/` and document their execution context in the relevant component documentation.
- Keep repository-wide system explanations in `ARCHITECTURE.md`, repository setup instructions in `README.md`, and enforceable agent behavior in `AGENTS.md`.
- Create a root `docs/` tree only for genuinely cross-stack documentation. Component-specific documentation belongs inside that component directory.

## Verification

- Verify changes in proportion to their risk and scope.
- Use Docker for integration, API, migration, and service-level verification.
- Use the Backend Rules and Frontend Rules sections for language-specific checks.
- Review generated migrations before applying them, test them in development first, and back up production data before a production migration.
- Never expose secrets while collecting diagnostic or verification output.

## Backend Rules (`backend/**`)

### Python Style and Quality

- Use `snake_case` for functions and variables, `PascalCase` for classes, and hyphenated labels for routes and string-valued labels where appropriate.
- Black is the formatter with an 88-character line length and double-quoted strings.
- isort orders imports as standard library, third-party, then local imports.
- Flake8 must at least catch critical errors `E9`, `F63`, `F7`, and `F82`.
- All comments, docstrings, exceptions, logs, API documentation, and identifiers must be in English.

### Architecture and Placement

- Keep route handlers in `app/api/` thin: validate transport input, inject dependencies, call services, and return the unified response type.
- Put business logic and database-model conversion in `app/services/`.
- Put Pydantic request and response models in `app/schemas/`.
- Put SQLAlchemy models in `app/models/` and migrations in `migrations/`.
- Put transaction boundaries in the service layer so they align with business operations.
- Preserve the client API and backoffice API separation and their existing versioned route structure.

### Service Dependency Injection

All business service classes must use dependency injection.

- Service methods must be instance methods using `self`; do not add `@staticmethod` or `@classmethod` to service classes.
- Each service must expose a `get_xxx_service()` provider function.
- Routes must inject services with `Depends(get_xxx_service)`.
- Do not create module-level singleton service instances.
- Inject service dependencies through the constructor.
- A constructor may create a default dependency only when needed for direct use or testing; the provider must still assemble the normal dependency chain explicitly.

Preferred pattern:

```python
class ExampleService:
    def __init__(self, dependency_service: DependencyService | None = None):
        self.dependency_service = dependency_service or DependencyService()

    async def process_data(self, db: AsyncSession, data: dict):
        return await self.dependency_service.validate(data)


def get_example_service() -> ExampleService:
    return ExampleService(dependency_service=get_dependency_service())
```

Route usage:

```python
@router.post("/example")
async def example_handler(
    service: ExampleService = Depends(get_example_service),
    db: AsyncSession = Depends(get_db),
):
    result = await service.process_data(db, data)
    return ApiResponse.success(data=result)
```

The restriction on static and class methods applies to service classes. Schema helpers, model utilities, and other non-service types may use them when appropriate.

### Database Rules

- Use PostgreSQL through SQLAlchemy's asynchronous application stack.
- Use `asyncpg` for application operations and `psycopg2-binary` only for synchronous Alembic operations.
- Use `TIMESTAMP(timezone=True)` for every persisted time field so PostgreSQL generates `TIMESTAMPTZ`.
- Do not create SQLAlchemy or PostgreSQL enum columns. Persist enum-like values in `String` columns and validate allowed values in Pydantic or business logic.
- Python enums may be used for application-level validation; the database column must remain a string.
- Preserve lazy engine and session creation and the separate scheduler engine architecture.
- Preserve the established production application pool sizing of 20 connections, 10 maximum overflow connections, and a 30-minute recycle unless a measured change justifies updating it.
- Preserve the separate scheduler pool of 5 connections unless a measured change justifies updating it.
- Keep connection and transaction management in the established database/session utilities.

Example:

```python
created_at = Column(TIMESTAMP(timezone=True), nullable=False)
status = Column(String(20), nullable=False)
```

### Responses and Exceptions

- Always use `ApiResponse` from `app.schemas.response`; do not introduce `SuccessResponse`.
- Use `ApiResponse.success(...)` or `ApiResponse.success_without_data()` for successful route responses.
- Use `APIException` from `app.exceptions.http_exceptions` for standardized application errors.
- Use `400 Bad Request` for validation and other user-facing business errors that the frontend should display.
- Use `404 Not Found` for missing resources and `500 Internal Server Error` for system failures; these are not general user-facing message channels.
- Authentication and authorization status codes must follow the existing handlers and API contract.
- Use the pagination utilities in `app/schemas/paginator.py` for paginated responses.

### Swagger and API Documentation

- When an API contract changes, keep its FastAPI route metadata, `response_model`, Pydantic field descriptions, validation constraints, and examples accurate so the generated Swagger/OpenAPI documentation matches runtime behavior.
- Keep client and backoffice routes and documentation separated, and register routes through the existing router registry.
- Update the relevant Swagger configuration only when its API metadata, tags, authentication description, or documentation behavior changes.
- Treat the application factory and documentation-app configuration as the source of truth for documentation URLs; do not hard-code those URLs in this instruction file.
- Update `backend/docs/api/swagger-guide.md` when Swagger usage, authentication, environment behavior, or access instructions change.
- Keep production documentation navigation behavior consistent with the existing environment policy.

### Environment Configuration

Use `.env.example` for names and structure; never read runtime `.env` values.

Expected categories include:

- Project: `PROJECT_NAME`, `ENV`
- Backend: `API_PORT`, `API_V1_STR`
- Database: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`
- Redis: `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`
- JWT: `SECRET_KEY`, `ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES`
- Email: configured mail-server or Brevo variables
- Celery: `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`
- Flower: `FLOWER_USER`, `FLOWER_PASSWORD`, `FLOWER_PORT`

### Commands and Verification

Use Docker from the repository root for normal backend work:

- `./deploy.sh dev`
- `./deploy.sh logs backend`
- `./deploy.sh migrate`
- `docker compose exec backend pytest`
- `docker compose exec backend black --check .`
- `docker compose exec backend isort --check-only .`
- `docker compose exec backend flake8 .`
- `docker compose exec backend alembic revision --autogenerate -m "migration_name"`
- `docker compose exec backend alembic downgrade -1`
- `docker compose logs -f celery-worker`
- `docker compose logs -f celery-beat`

Do not run backend Python, `pip`, pytest, lint, formatting, or diagnostic commands directly on the host.

### Migrations, Tasks, and Operations

- Review every autogenerated Alembic migration before applying it.
- Test migrations in development first and back up production data before production migration work.
- Celery worker and Celery beat normally run as Docker Compose services; do not start duplicate local workers during normal development.
- Use the optional Flower service for Celery monitoring.
- Preserve structured logging, log rotation, Redis-backed aggregation, and master-process detection when modifying logging infrastructure.

### Backend Scripts and Documentation

- Put permanent backend deployment, data import/export, maintenance, backup, migration support, and reusable backend utility scripts in `backend/scripts/`.
- Put temporary backend development scripts, one-off diagnostics, and exploratory checks in `backend/shell/`; keep that directory out of version control.
- Treat `backend/scripts/`, `backend/shell/`, and `backend/docs/` as backend-scoped paths, even when a command is launched from the repository root.
- A backend script must document its required working directory, arguments, and execution environment. Do not assume it can run as a standalone repository-root script.
- Run all backend scripts inside the backend container, for example `docker compose exec backend python scripts/<script_name>.py`.
- Keep backend documentation under `backend/docs/` in purpose-specific subdirectories such as `api/`, `architecture/`, `business/`, `development/`, `deployment/`, and `security/`.
- Do not create loose documents directly in `backend/docs/`; `backend/docs/README.md` is the index and must be updated when documentation is added, moved, or removed.
- Check for an existing backend script or document before creating another one with overlapping responsibility.

## Frontend Rules (`frontend/**`)

### Scope and Stack

- Preserve the established React 19, TypeScript strict mode, Vite, React Router, Zustand, Axios, Ant Design, and SCSS Modules architecture.
- Use `pnpm`, never npm or yarn. The package's `preinstall` script enforces this.

### Commands

Normal application development runs through `./deploy.sh dev` from the repository root.

Use these commands from `frontend/` for focused frontend verification:

- `pnpm install`
- `pnpm dev`
- `pnpm type-check`
- `pnpm lint`
- `pnpm build`

Use focused commands when sufficient; run the production build for changes that affect bundling, routes, environment handling, or deployment.

### Naming and File Organization

- Components and component files use `PascalCase`.
- Utilities, hooks, functions, and variables use `camelCase`.
- Constants use `UPPER_SNAKE_CASE`.
- Component styles use `index.module.scss` in the component directory.
- Prefer the established structure under `src/pages/`, `src/components/`, `src/apis/`, `src/router/`, `src/store/`, `src/hooks/`, `src/context/`, `src/utils/`, `src/types/`, `src/theme/`, and `src/assets/`.
- Use the `@/` alias for imports from `src/`; do not add deep `../../../` imports.
- Keep all identifiers, comments, UI implementation notes, and technical documentation in English.

Example component layout:

```text
src/components/ComponentName/
├── index.tsx
└── index.module.scss
```

### React and Routing Patterns

- Use the existing `useRoutes` route configuration pattern; do not introduce a parallel `<Routes>` tree.
- Route-level pages and large route components must use lazy loading and `Suspense` through the established router helpers.
- Keep authentication and authorization checks in the existing route guard.
- Prefer typed function components and explicit props interfaces.
- Use hooks only according to React's rules; do not hide side effects in render paths.

Representative component shape:

```tsx
interface ComponentProps {
  title: string;
}

const Component: FC<ComponentProps> = ({ title }) => (
  <div className={styles.container}>{title}</div>
);

export default Component;
```

### State Management

- Use Zustand for shared client state and the established persist middleware when state must survive reloads.
- Keep local UI state local; do not add global stores for component-only state.
- Give persisted stores stable, descriptive storage names.
- Keep authentication token handling in the established user store and HTTP client flow.

### Styling and Components

- Use SCSS Modules for component-scoped styles.
- Use the semantic CSS variables defined by the theme for colors and shared visual tokens.
- Prefer the established semantic variables, including `--bg-primary`, `--text-primary`, `--text-secondary`, and `--border-default`.
- Do not hard-code color values such as `#ffffff` or `rgba(...)` when an appropriate theme variable exists.
- Use Ant Design component props, including `Button`'s `size`, instead of overriding component dimensions with ad hoc CSS.
- Use `<SvgIcon name="icon-name" />` for icons registered under `src/assets/svg/`; do not introduce a competing icon-loading pattern.

### API Client and Error Messages

- Put backend request modules in `src/apis/` and use the shared Axios client in `src/utils/https.ts`.
- Do not hard-code service origins. Use `VITE_API_BASE_URL` and the production `/api/*` proxy.
- The request interceptor may attach authentication and client context such as timezone.
- Handle `401` globally in the Axios layer: clear invalid authentication state, redirect as established, and show one friendly session-expired fallback when the backend provides no safe message.
- Do not show non-401 API error toasts in Axios interceptors. They must be surfaced once from the business `catch` path to avoid duplicate API and system messages.
- Business catch blocks must use the shared `getRequestErrorMessage`, `showRequestError`, or `isAuthRequestError` utilities when available. Prefer the backend `response.data.message`, fall back to a frontend-friendly message when Axios has no backend message, and preserve non-Axios business `Error.message` values.
- If these shared request-error utilities are missing in the current branch, add or centralize them when implementing this policy; do not restore generic interceptor toasts as the long-term solution.
- Local validation errors that are not API failures may call `messageClient` directly.
- Use the Ant Design message instance initialized by `MessageBridge` through `messageClient`; do not create an unrelated global message mechanism.
- Do not use `hideMessageModal` as a substitute for correct single-owner error handling in new code.

### Frontend Environment Files

- `frontend/.env.dev` and `frontend/.env.prod` contain committed, non-secret API URL configuration only.
- Preserve `FRONTEND_PORT`, `FRONTEND_DEV_PORT`, and `VITE_API_BASE_URL` as the established frontend environment-variable names.
- Never place credentials or server-only secrets in Vite environment variables; `VITE_*` values are exposed to the browser bundle.
- Use `frontend/.env.example` as the template for frontend configuration.
- If a frontend environment file ever contains or may contain a secret, treat it as protected under the repository security rules and do not read it.

### Full-Stack Contract and Verification

- When a backend endpoint changes, update its frontend API wrapper and affected types in the same change when applicable.
- Prefer backend-provided user-facing messages for HTTP 400 business errors, while retaining a clear frontend fallback.
- Ensure API failures produce at most one toast.
- Run `pnpm type-check` and `pnpm lint` for TypeScript changes; run `pnpm build` when the change can affect compilation or bundling.
- Verify important UI flows against the Docker development environment.
