# Aeterna Control Plane Architecture

## Purpose

The control plane is the private hosted-service component of Aeterna. It
coordinates time, devices, notifications, and delayed recovery. The open-source
desktop client owns the encrypted vault and all user-authored private content.

## Non-negotiable data boundary

The service may store:

- Owner account identifiers and verified contact channels.
- Device identifiers, public keys, revocation state, and heartbeat receipt time.
- Inactivity, warning, grace, and release policy state.
- Contact delivery addresses and constrained notification text.
- Encrypted server release secrets and their KMS metadata.
- Provider delivery identifiers, billing state, and structured audit events.

The service must never receive or store:

- Vault records, messages, media, or attachments.
- Master passwords or derivatives.
- Emergency recovery codes or derivatives that enable offline guessing.
- Vault data keys or plaintext recovery material.
- Raw keystrokes, URLs, window titles, application content, or mouse positions.

No generic file-upload or object-storage route belongs in this service. A new
payload field or endpoint that could cross this boundary requires an explicit
design and security review.

## Runtime topology

```text
Desktop client
    |
    | TLS + signed device requests
    v
FastAPI client API -------- PostgreSQL
    |                           |
    +-------- Redis ------------+
                |
                v
       Celery worker and beat
                |
                v
       Email/SMS provider adapters

Operator browser -> Backoffice UI -> Backoffice API
```

- FastAPI exposes separate client and backoffice OpenAPI applications.
- PostgreSQL is authoritative for state machines, idempotency, and the
  transactional outbox.
- Redis supports bounded ephemeral state, rate limiting, and Celery transport.
- Celery workers perform retries and provider delivery. Celery Beat advances
  time-based workflows through idempotent tasks.
- Production recovery material and sensitive PII require envelope encryption
  backed by KMS/HSM. Application database credentials must not be able to
  decrypt them by themselves.

## Domain modules

Product work should converge on these modules:

1. `accounts`: owner identity, email verification, deletion, and recovery.
2. `devices`: registration, public keys, signed requests, revocation, and
   monotonic sequence validation.
3. `heartbeats`: accepted activity evidence and server receipt time.
4. `policies`: inactivity window, warning window, grace period, and versioning.
5. `contacts`: consent, verification, delivery addresses, and opt-out rules.
6. `notifications`: templates, outbox records, attempts, retries, and receipts.
7. `recovery`: encrypted server release secrets, claim authentication, release,
   and post-release auditing.
8. `billing`: entitlements and provider webhooks, isolated from core release
   correctness.
9. `audit`: append-oriented, redacted security and operator events.

Each domain follows `route -> service -> model/schema`. Routes stay thin;
services own authorization, business rules, transactions, and idempotency.

## State-machine rules

- PostgreSQL server time is authoritative. Client timestamps are diagnostic.
- Heartbeats and release transitions must serialize on the same policy state.
- A valid heartbeat in warning or grace atomically cancels pending release work.
- Workers are at-least-once; every job and provider send must be idempotent.
- Service recovery after downtime must not skip warning or grace periods.
- Release is irreversible from the recipient's perspective and must emit audit
  and owner-notification events in the same durable workflow.

## Deployment

The root Compose files are the only supported local topology:

- `docker-compose.yml` defines shared services, networks, volumes, and health
  checks.
- `docker-compose.dev.yml` selects development images, bind mounts source, and
  exposes localhost ports.
- `docker-compose.prod.yml` selects production settings and frontend routing.

Backend application and tooling commands run inside the backend container. The
React backoffice uses `pnpm`.

## Implementation sequence

The existing account and admin code is transitional scaffolding. Implement and
review device registration and signed heartbeat ingestion before building the
release state machine. Add notification delivery only after transactional outbox
and idempotency behavior are covered by concurrency tests. Implement recovery
release only after the cryptographic protocol and KMS boundary are approved.
