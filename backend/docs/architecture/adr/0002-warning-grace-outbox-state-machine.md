# ADR 0002: Warning, grace, and transactional Outbox state machine

- Status: Accepted
- Date: 2026-09-27
- Scope: I11 server policy lifecycle and provider-neutral notification intents
- Governing decisions: [ADR 0001](./0001-account-policy-transaction-and-outage-semantics.md)
- Product authority: Aeterna `docs/DESIGN.md` section 7

## Context

I03 proved the core row-lock, compare-and-set, outage, and atomic-Outbox
semantics before public account and heartbeat persistence existed. I10 then
added signed heartbeat acceptance and account-level activity aggregation. I11
must join those two boundaries without treating a queued notification as
delivery, without allowing worker retries to duplicate effects, and without
allowing service downtime to satisfy warning or grace requirements.

I11 does not own contact consent, provider delivery, recovery material, claims,
or post-release key handling. Those remain I12-I14 responsibilities.

## Decision

1. Each production policy is linked one-to-one to an Aeterna account. A signed
   heartbeat and every scheduler or administrative policy command lock the
   account first and the policy second. Heartbeat acceptance additionally locks
   its device after the policy. This account-first order serializes a valid
   heartbeat against release before either transaction mutates durable state.
2. The lifecycle is closed:
   - `ACTIVE -> PRE_WARNING -> GRACE_PERIOD -> RELEASED` is the normal path;
   - a valid heartbeat moves `PRE_WARNING` or `GRACE_PERIOD` to `ACTIVE`;
   - `ACTIVE`, `PRE_WARNING`, or `GRACE_PERIOD` may become `DISABLED` or
     `DELETED`;
   - `DISABLED` may only become `DELETED`;
   - `RELEASED` and `DELETED` cannot be left.
3. The default persisted windows are 30 days inactivity, 7 days pre-warning,
   and 7 days grace. The enforced range is 14-365 days inactivity, 3-30 days
   pre-warning, and at least 3 days grace. A warning begins at
   `due_at - warning_window`; grace begins at `due_at`; release becomes eligible
   at the later of `grace_started_at` and independently proven warning time,
   plus the complete grace window. Every boundary is inclusive.
4. Time comes only from a replaceable timezone-aware server clock and is
   normalized to UTC. A naive clock value fails before mutation. Client time is
   never accepted as deadline evidence.
5. A valid signed heartbeat updates device evidence, account aggregation,
   policy state/deadline, pending-intent cancellation, and the structural
   Outbox event in one database transaction. A failure at any point rolls the
   entire operation back.
6. Every transition retains the I03 row lock plus compare-and-set on
   `(id, state, version)`. One scheduler sweep advances a policy at most once.
   The stable scheduler identifier is derived from policy ID, source state,
   and source version, so duplicate Celery deliveries converge on one event.
7. Notification intents are optional fields on the same Outbox event committed
   with a transition. Their stable delivery key is derived from policy ID,
   notification type, and policy version. Every prepared retry stores its own
   task idempotency key but reuses that delivery key. Internal callbacks have a
   separate unique idempotency key and an immutable outcome.
8. Outbox states are `pending`, `queued`, `acknowledged`, and `cancelled`.
   `queued` and `acknowledged` describe only the internal dispatch boundary.
   Neither state proves provider acceptance, mailbox delivery, Owner reading,
   or completed warning. Only a separately authenticated warning-proof command
   can set `owner_warning_proven_at`.
9. Heartbeat reset, disable, delete, and outage recovery cancel all still
   actionable notification intents in the same transaction as their state
   change. A worker must re-check the durable status before any later I12
   provider operation.
10. Explicit outage recovery conservatively restarts `GRACE_PERIOD` at the
    recovery instant, clears prior warning proof, queues a new warning-required
    intent, and requires a new proof plus the complete grace interval. Old
    deadlines or Outbox timestamps can delay release but can never authorize an
    immediate release after recovery.

## Security impact

- A heartbeat/release race has one PostgreSQL serialization winner and cannot
  produce both an activity extension and a release authorization.
- `RELEASED` remains irreversible even if a later device presents a valid
  signature.
- Queue retries and callbacks cannot manufacture warning proof.
- Stable database-enforced keys bound duplicate Celery tasks, queue attempts,
  and callbacks without retaining message content, contact data, or recovery
  material.
- Logical deletion preserves the terminal authorization record instead of
  physically erasing evidence that could be needed to reject a later release.

## Consequences

- Policies begin with the first accepted signed heartbeat; account creation or
  device re-verification alone does not manufacture activity.
- The I11 Celery jobs advance policy time and prepare provider-neutral intents.
  They do not send email and cannot claim a notification was delivered.
- I12 must authenticate provider callbacks, apply contact/disclosure rules,
  and decide what evidence can become Owner-warning proof. I13 must separately
  consume `RELEASED` authorization before any SRS or claim operation exists.

## Alternatives rejected

### Lock the device before the policy

Rejected because the scheduler does not need a device lock. Account-first,
policy-second gives heartbeat and release one common serialization boundary and
keeps future multi-device operations from inventing a competing order.

### Treat a queued or acknowledged Outbox record as warning proof

Rejected because it proves only internal dispatch progress. It cannot prove
provider delivery or that the Owner received the warning.

### Re-enable a disabled or released policy

Rejected for I11. `DISABLED` is a fail-closed workflow stop that may only be
logically deleted, while `RELEASED` may already have authorized irreversible
downstream behavior.

### Catch up immediately after downtime

Rejected because elapsed outage time is not warning evidence. Recovery starts
a new warning and full grace interval instead.
