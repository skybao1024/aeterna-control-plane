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
          /             \
         v               v
Email provider adapter   Recovery KMS adapter

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

Production identity uses a separate customer-managed AWS KMS key to wrap three
stable, independently generated application keys for PII encryption, lookup,
and OTP/token derivation. A one-time setup container persists their ciphertext
envelope in the `identity-keys` volume. Runtime containers mount it read-only
and use decrypt-only AWS permissions. No plaintext production environment-key
fallback is allowed. See backend ADR 0005 and the identity deployment guide.

Production deployment uses GitHub-hosted CI to build and test immutable amd64
images. A dedicated environment-scoped SSH identity transfers an image/config
bundle to the host; a root-owned release wrapper serializes activation. Host
Nginx terminates TLS for the API and console while all container ports remain
on loopback. Application/worker traffic is paused before database backup and
migration, and service health gates the active release pointer. Stable database,
Redis, logs, and encrypted identity volumes survive all ordinary releases.
AWS credentials and runtime secrets remain outside the checkout and images.

## Protocol-v1 identity boundary

The registered desktop identity API is passwordless. An eight-digit mailbox
challenge issues a ten-minute, one-use, purpose-bound opaque grant. The database
stores only keyed mailbox lookup values, AES-256-GCM ciphertext, keyed OTP
verifiers, and grant digests. Legacy generic client password/JWT routes are not
registered; backoffice authentication remains independent.

The first device can bind immediately exactly once. Later devices remain
pending until an active device signs the server challenge or until 24 hours
have elapsed and the proposed device supplies a fresh mailbox grant and fresh
Ed25519 proof. PostgreSQL row locks, terminal states, and canonical request
digests serialize approvals, cancellations, expiry, and exact replays.

Signed objects use RFC 8785 JCS and Ed25519. The public desktop repository owns
the versioned schemas, errors, and fixtures; this service vendors the exact
release directory and verifies its digest in CI. I09 endpoints cannot carry
heartbeat, activity, application/window/URL, vault, contact, or recovery data.

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

The I11 implementation binds one policy to an Aeterna account and serializes
signed heartbeat and scheduler mutations in account-then-policy lock order.
Its Celery jobs advance one persisted version at a time and prepare only
provider-neutral notification intents. `queued` and `acknowledged` Outbox
states are internal dispatch evidence, never proof that the Owner received a
warning. See backend ADR 0002 for the closed transition graph, timing bounds,
outage restart, and idempotency rules.

I12 keeps an unverified Notification Target separate from an accepted and
verified Recovery Contact. Confirm-now queues a fixed neutral invitation;
private-until-release cannot materialize that invitation before `RELEASED`.
Encrypted addresses and bounded message text remain outside Outbox and audit
rows. I11 intents materialize into a second provider-neutral email Outbox whose
`provider_accepted`, `delivered`, and `bounced` states describe transport only.
They never set Owner warning proof or imply human reading. Automatic retry is
permitted only through an adapter that honors the persisted idempotency key;
ambiguous SMTP outcomes stop for reconciliation instead of risking a duplicate.
AWS SES is the selected production adapter and signed SNS is the callback
boundary. External delivery remains disabled until the Region, sender identity,
operating jurisdictions, provider use-case acceptance, and live-send matrix are
approved. See backend ADR 0003.

I13 stores one KMS ciphertext and non-secret binding metadata for each sealed
device recovery record. Only authoritative `RELEASED` plus an accepted and
verified Recovery Contact can materialize a contact-scoped grant. Claim links,
OTP verifiers, and five-minute SRS-read capabilities are persisted only as
digests; release re-locks every authoritative row and consumes the grant only
after successful KMS decrypt and commit. The approved personal-project boundary
uses one customer-managed symmetric single-Region key in `ap-southeast-1`, with
no replica, CloudHSM, failover, or plaintext fallback. AWS SES may carry the
recovery link and OTP, but live KMS/SES use remains disabled pending I15. See
backend ADR 0004.

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
