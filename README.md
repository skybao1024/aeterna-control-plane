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
- Development email inbox: <http://127.0.0.1:8025>

The development Compose override sends account verification email to the local
Mailpit inbox. It exposes only the inbox UI on the loopback interface; SMTP is
available to the backend container on the Compose network. Use the actual API
port printed by `./deploy.sh dev` when it differs from the example above. For
the desktop client, set `AETERNA_API_ORIGIN` to that loopback API origin while
building or launching the native development app.

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
The account identity module accepts explicit synthetic environment keys in
development and tests only. Production and preview require a separately
provisioned AWS KMS identity key and a durable ciphertext envelope. Startup
fails closed when that configuration or KMS access is unavailable. Follow
[`backend/docs/deployment/aws-kms-identity.md`](./backend/docs/deployment/aws-kms-identity.md)
to initialize the envelope once and grant the application decrypt-only access.
For local account binding, set `AETERNA_PII_KEY_V1`,
`AETERNA_LOOKUP_KEY_V1`, and `AETERNA_OTP_KEY_V1` privately in the ignored
runtime configuration. Each must be an independently generated 32-byte value
encoded as unpadded base64url. Restart `./deploy.sh dev` after changing them.
Do not share their values in diagnostics or support messages.

Runtime environment files are confidential. Never commit them or paste their
values into issues, logs, or AI conversations.

## Production CI/CD

The `Verify and deploy` GitHub Actions workflow tests pull requests and every
push to the default `dev` branch. Deployment is an explicit manual run on `dev`
with the `deploy` input enabled; it activates the exact tested commit in the
`production` environment after dedicated CI access is authorized. Actions are
pinned to official release commits. Production environment access is limited
to `dev`; pull requests never receive deployment credentials.

The public ingress is:

- API: <https://api.aeternarelay.com>
- Operations console (administrator sign-in): <https://console.aeternarelay.com>
- Trusted contact portal (public invitations and recovery claims):
  <https://claim.aeternarelay.com>
- The root domain remains the product website.

The contact portal homepage explains how to open a personal email link; it
does not require an administrator account. Its routes exclude the operations
console, and its ingress permits only the public invitation/claim API paths.
Previous console invitation and claim URLs redirect to the contact portal,
preserving browser-held token fragments. Production email links use
`AETERNA_PUBLIC_FRONTEND_URL` (default `https://claim.aeternarelay.com`) through
the production Compose override for the API and both Celery services. Local
development retains both flows, with the portal homepage at `/recipient`.

GitHub builds Linux amd64 images and runs backend tests with PostgreSQL and
Redis, frontend type/lint checks, and release safety checks. A short-lived
artifact contains only the production images and public Compose configuration.
CI uploads it over pinned-host SSH to `/srv/aeterna-control-plane/incoming`;
the host verifies its checksums, loads images, and calls `./deploy.sh release`.
The server does not build source. The small-host overlay uses one API process,
one Celery child, memory limits, bounded Redis memory, and rotated Docker logs.
It preserves the application's established database pool sizes.

The `production` GitHub environment requires:

- Variables `DEPLOY_HOST` and `DEPLOY_USER`.
- Secrets `DEPLOY_SSH_KEY` (a dedicated CI key) and `DEPLOY_KNOWN_HOSTS` (the
  operator-verified SSH host key). Never use the operator's root PEM for CI.

An operator installs Docker Engine and Compose on the Debian host, uploads
`deployment/` plus the CI public key privately, then runs
`deployment/bootstrap.sh <ci-public-key-file> <kms-region> <kms-key-arn>` as
root after the API, console, and claim DNS records point to the host. The
bootstrap preserves existing secrets and unrelated websites. It
creates host ingress, a separate certificate, and fresh random
database/Redis/JWT secrets without displaying them. The restricted CI account
is created only when CI SSH access is explicitly enabled. Runtime
configuration stays in `/etc/aeterna/runtime.env` with mode `0600`. AWS profiles
stay in the two separate `/etc/aeterna/aws-*` directories; neither application
secrets nor AWS credentials enter GitHub, build contexts, or release artifacts.

CI SSH access is opt-in: set `AETERNA_ENABLE_CI_SSH=1` for the bootstrap only
after authorizing the persistent production deployment key. The default
bootstrap prepares the host for an operator's first SSH activation without
adding CI access. Until the environment secrets are authorized and installed,
CI builds and tests releases; the operator can download a successful release
artifact and activate it once over their existing SSH connection.

For an existing host, upload the updated `deployment/` directory and run
`bash deployment/configure-ingress.sh` as root to update only ingress and
expand the project certificate. Existing API/console HTTPS stays active while
the new claim domain completes ACME validation. The helper validates Nginx
before reloading and restores the previous ingress on failure. It does not
modify runtime secrets or CI SSH access. Ingress is maintained by the operator;
manual CD publishes the tested images and Compose configuration.

Every release pauses application traffic and scheduled work, backs up
PostgreSQL, preserves a copy of the encrypted identity envelope, applies
migrations, and waits for all service health checks before updating
`/srv/aeterna-control-plane/current`. The identity envelope is initialized only
for a new database volume. An existing database without its original envelope
fails closed. Releases briefly interrupt service; this single-host deployment
does not provide zero downtime.

Root-only backups and logs are kept under
`/srv/aeterna-control-plane/backups` and `/var/log/aeterna-control-plane`.
Configure encrypted off-host backups and periodically test restoration. Images
and root-owned commit directories are retained for a reviewed rollback. To
redeploy a prior commit, rerun its successful workflow; first review schema
compatibility. Automatic database downgrades and volume deletion are prohibited.
A failed migration or rollout stops the release and requires operator review;
it does not restore old database state automatically.

Production email and delayed-recovery delivery remain disabled until their
separate SES and recovery-key setup is approved. Infrastructure health does
not establish readiness of those external delivery flows.

A cost-controlled shared-key trial can reuse the existing identity KMS key for
recovery by explicitly enabling `AETERNA_KMS_ALLOW_SHARED_KEY` and assigning
the same recovery key ARN. The managed host keeps these public controls in
`/etc/aeterna/deployment.conf`; the updated release wrapper passes them to
production services. Identity and recovery IAM policies must still restrict
their respective encryption contexts. See the
[identity](backend/docs/deployment/aws-kms-identity.md) and
[recovery](backend/docs/deployment/aws-kms-recovery.md) guides for the controls,
policies, and future migration implications.

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
