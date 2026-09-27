# I11 warning/grace state machine results

- Date: 2026-09-27
- Baseline: `3f9a357d339fe2dfd62ae3130d9e8b0aaa328f60`
- Repository: `aeterna-control-plane`
- Result: Accepted
- ADR: [Warning, grace, and transactional Outbox state machine](../architecture/adr/0002-warning-grace-outbox-state-machine.md)

## Implemented boundary

I11 connects accepted signed heartbeats to the server-authoritative policy row,
implements all six account policy states, registers the time-based Celery
workflow, and adds provider-neutral Outbox attempt and callback idempotency.
The implementation contains no contact workflow, email send, provider claim,
SRS, ERC, VDK, Vault content, or recovery material.

The two scheduled tasks are:

- `app.schedule.jobs.account_policy.scan`, which derives a stable logical run
  identifier from the policy ID, state, and version and advances no more than
  one transition;
- `app.schedule.jobs.account_policy.prepare_notifications`, which prepares a
  committed intent and stable delivery key but does not contact a provider.

## Persistence and transaction boundary

Migration `6b8f7d4a91c2` binds policies to accounts, adds the complete checked
state and policy-window constraints, extends Outbox lifecycle metadata, and
adds unique attempt and callback records. State and status values remain string
columns, and every persisted instant remains `TIMESTAMPTZ`.

The signed-heartbeat transaction locks account, policy, then device. It commits
the device sequence/receipt time, account aggregation, policy reset/deadline,
notification-intent cancellation, and new Outbox event together. Scheduler,
warning proof, recovery, disable, and delete operations use the same account
then policy order and retain the compare-and-set version guard.

## PostgreSQL evidence

The focused I11/I10 integration matrix passed 23 tests against PostgreSQL. It
covered exact warning, due, and release boundaries; aware UTC enforcement;
normal warning/proof/grace/release ordering; no-proof release refusal; complete
outage restart; both heartbeat/release lock winners; same-account serialization;
atomic cancellation; duplicate scheduler delivery; state/Outbox and full signed
heartbeat rollback; stable delivery keys across retries; idempotent and
conflict-detecting callbacks; disabled/deleted behavior; and irreversible
release.

The complete backend suite passed 65 tests. Migration upgrade, downgrade to
`d0a10e27b5c4`, re-upgrade, `alembic current`, and `alembic check` passed.
Both Celery tasks were observed in the live worker registry. Focused Black,
isort, and Flake8 checks passed, and the repository-wide critical Flake8 set
reported no `E9`, `F63`, `F7`, or `F82` errors.

## Failure evidence

- A naive clock raises before any policy or Outbox mutation.
- One injected failure after a policy state write and one after an Outbox flush
  each roll both records back.
- An injected Outbox failure during a signed heartbeat also rolls back the
  device sequence, device receipt time, account aggregate, newly created policy,
  and event.
- A queued warning becomes `cancelled` in the same transaction as a valid
  heartbeat reset.
- A callback replay returns the persisted outcome; reusing its logical ID with
  a different outcome fails.
- Internal queue acknowledgement leaves `owner_warning_proven_at` unset.
- Recovery clears old proof and old notification intents, then refuses release
  until a new proof and complete grace interval have elapsed.
- `RELEASED`, `DISABLED`, and `DELETED` reject unsafe heartbeat or
  administrative transitions according to ADR 0002.

## Remaining scope

- I12 owns contact disclosure, provider adapters, delivery evidence, retries,
  redacted delivery audit, and the authenticated source of warning proof.
- I13 owns recovery authorization consumption, SRS delivery, and claims.
- I08 remains stopped; I11 uses deterministic signed heartbeat evidence and
  makes no native activity or platform qualification claim.
