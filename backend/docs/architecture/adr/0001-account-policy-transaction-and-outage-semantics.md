# ADR 0001: Account-policy transaction and outage semantics

- Status: Accepted by G0
- Date: 2026-09-21
- Scope: I03 internal concurrency risk prototype
- Approval: Explicit user approval recorded in Aeterna G0 on 2026-09-21

## Context

The control plane must advance account policies through `ACTIVE`,
`PRE_WARNING`, `GRACE_PERIOD`, and `RELEASED` without allowing duplicate
scheduler delivery, partial state/Outbox commits, stale-deadline release after
an outage, or reversal of a completed release. I03 must establish the database
semantics before public heartbeat, notification-provider, recovery, or claim
behavior exists.

The product design requires server receipt time, PostgreSQL transactions,
compare-and-set conditions, a Transactional Outbox, and a complete minimum
grace period after a provable Owner warning. A committed Outbox record proves
that a notification intent exists; it does not prove provider delivery.

## Decision

The prototype uses the following semantics:

1. Every mutation obtains a PostgreSQL `SELECT ... FOR UPDATE` row lock and
   then executes an `UPDATE` compare-and-set on `(id, state, version)`. The
   lock serializes contenders, while the compare-and-set prevents a stale
   state/version from being committed accidentally.
2. The policy mutation and one structural Outbox event are flushed and
   committed in one SQL transaction. Any exception before commit rolls back
   both records.
3. Service methods obtain time only from an injected timezone-aware UTC clock.
   Heartbeats do not accept client event time and recompute `due_at` from the
   server receipt instant.
4. At-least-once operations carry a stable logical identifier. The persisted
   idempotency key binds the policy UUID, operation namespace, and SHA-256 hash
   of that identifier. A database unique constraint is the final enforcement
   boundary. An exact retry returns the already committed event and performs
   no second mutation.
5. One scheduler invocation advances at most one state. Retries of the same
   scheduler run cannot cascade an overdue policy through multiple states.
6. Heartbeat/release races are resolved by PostgreSQL lock acquisition and
   commit order:
   - if the heartbeat locks first, it commits `ACTIVE`, clears warning/grace
     fields, and recomputes `due_at`; the later release evaluation is not due;
   - if release locks first, it commits `RELEASED`; the later heartbeat is
     rejected and never reverses release.
7. `owner_warning_proven_at` is distinct from an Outbox notification intent.
   Release requires this proof and waits the full configured grace duration
   from the later of `grace_started_at` and `owner_warning_proven_at`.
8. Explicit outage recovery for a stale unreleased policy enters or restarts
   `GRACE_PERIOD`, clears prior warning proof, records a new warning-required
   Outbox event, and starts grace from the recovery instant. Repeated recovery
   with the same identifier is idempotent. Outage time can delay release but
   cannot satisfy warning or grace requirements.
9. States and Outbox statuses use checked string columns, not PostgreSQL enum
   types. All persisted instants use `TIMESTAMP(timezone=True)`. Prototype
   durations use positive integer seconds so tests can express boundaries
   exactly; production policy units and limits remain a later decision.
10. Outbox payloads contain only structural policy metadata: policy UUID,
    source state, target state, policy version, and server occurrence time.
    They contain no vault content, SRS, ERC, VDK, contact address, or message
    content.

## Consequences

- The committed race result is deterministic from database serialization,
  even though the application does not predetermine which concurrent request
  acquires the lock first.
- Row-level locking favors correctness over maximum parallelism for mutations
  to the same policy. Different policies remain independently concurrent.
- Warning-delivery proof needs an authenticated provider/audit source in a
  later iteration. I03 only models its persistence boundary and cannot claim
  that email was delivered.
- Outbox dispatch, delivery attempts, Celery registration, public endpoints,
  contacts, and recovery material remain out of scope.
- G0 accepts these transaction and outage semantics as the durable production
  direction. Warning proof, delivery, public endpoints, and recovery remain
  assigned to their later iterations and are not implied by this acceptance.

## Alternatives considered

### Optimistic compare-and-set without row locking

This can be correct with comprehensive retry handling, but it makes the
heartbeat/release winner and Outbox conflict path harder to reason about for
the risk prototype. The prototype keeps the compare-and-set and adds an
explicit row lock.

### Treat committed Outbox intent as warning-delivery proof

Rejected because a database commit cannot prove provider acceptance or Owner
delivery. Conflating the two could allow release after an undelivered warning.

### Release immediately on recovery when an old grace deadline passed

Rejected because service downtime would then count as warning/grace evidence.
Recovery instead restarts warning proof and the complete grace interval.
