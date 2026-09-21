# Control Plane Project Architecture

The root [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) is the authoritative
service architecture. This backend implements its HTTP, persistence, queue, and
provider-adapter layers.

## Layering

```text
API route -> injected service -> model/schema -> PostgreSQL or provider adapter
```

- Routes parse transport inputs and return the shared `ApiResponse` envelope.
- Services own authorization, validation, idempotency, transactions, and audit
  behavior.
- Models define persistence only; schemas define external contracts.
- Celery tasks call services and must be safe under at-least-once execution.

## API surfaces

- Client API: desktop account, device, heartbeat, policy, contact, notification,
  and recovery-claim operations.
- Backoffice API: authenticated operational workflows with explicit audit.
- Documentation export: development and preview only.

No surface may accept vault content, messages, media, attachments, master
passwords, emergency recovery codes, or vault data keys.

## Time and concurrency

PostgreSQL server receipt time is authoritative. Heartbeat acceptance and
release transitions must serialize on the same policy state. Outbox records,
state transitions, and their audit events are committed atomically.
