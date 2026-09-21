# I03 control-plane concurrency prototype results

- Date: 2026-09-21
- Baseline: `d9dd7cb7e03e6b869d1068e24703d53a817b4b42`
- Repository: `aeterna-control-plane`
- Result: Accepted
- ADR: [Account-policy transaction and outage semantics](../architecture/adr/0001-account-policy-transaction-and-outage-semantics.md)

## Implemented boundary

I03 adds an internal-only account-policy transition service, PostgreSQL models,
an Alembic migration, and deterministic integration tests. No route or Celery
task registers the prototype, so it does not expose heartbeat, recovery,
claim, notification-provider, billing, or frontend behavior.

The prototype contains no SRS, ERC, VDK, vault data, message content, contact
address, or other recovery material. Outbox payloads contain only structural
transition metadata.

## Schema and migration

Migration `3f9e0e028cab` adds:

- `account_policies`, keyed by UUID, with a checked string state, monotonic
  integer version, positive second-based policy windows, server-authoritative
  `TIMESTAMPTZ` activity/deadline/state fields, warning proof, grace start, and
  release time;
- `account_policy_outbox_events`, keyed by UUID, with a foreign key to the
  policy, structural source/target/version data, JSON structural payload,
  `TIMESTAMPTZ` scheduling data, checked status, and a named unique
  idempotency-key constraint;
- an index on the Outbox policy foreign key.

The downgrade drops the Outbox index and table before dropping the policy
table. No SQLAlchemy or PostgreSQL enum type is introduced.

## Transaction boundary and race semantics

Each service operation owns one explicit transaction. It locks the policy row,
checks a stable idempotency key, evaluates injected UTC server time, executes a
compare-and-set update on state and version, inserts the matching Outbox event,
and commits. Failures injected after the state write and after the Outbox flush
both roll back the entire transaction.

The heartbeat/release winner is the transaction that acquires the policy lock
first. A heartbeat winner restores `ACTIVE` before release eligibility is
evaluated. A release winner leaves the row `RELEASED`, and the later heartbeat
is rejected without mutation.

An explicit outage-recovery operation restarts `GRACE_PERIOD` at recovery
time, clears warning proof, and emits a warning-required event. Release remains
blocked until warning proof is recorded and the complete grace duration elapses
from that proof.

## PostgreSQL test matrix

| Evidence | Deterministic mechanism | Expected result |
| --- | --- | --- |
| Heartbeat in `PRE_WARNING` | Injected clock | Atomic `ACTIVE`, new deadline, one Outbox event |
| Heartbeat in `GRACE_PERIOD` | Injected clock | Atomic `ACTIVE`, cleared grace/proof, one Outbox event |
| Release wins heartbeat race | Event-gated hook while row lock is held | `RELEASED`; heartbeat rejected |
| Heartbeat wins release race | Event-gated hook while row lock is held | `ACTIVE`; release evaluation is a no-op |
| Concurrent scheduler retry | Two-party async barrier before lock | One transition, one Outbox event, one duplicate result |
| Normal state path | Mutable injected clock | Ordered pre-warning, grace, warning proof, full grace, release |
| Failure after state write | Injected exception before Outbox insert | State and Outbox both rolled back |
| Failure after Outbox flush | Injected exception before commit | State and Outbox both rolled back |
| Outage recovery retry | Stable recovery identifier | One grace restart and no immediate release |
| Invalid warning proof | Invalid command in `ACTIVE` | Exception, unchanged row, no Outbox event |
| Repeated heartbeat | Stable heartbeat identifier | First mutation only; retry returns duplicate |

Tests use separate PostgreSQL sessions and real row locks. Async events and a
barrier coordinate races; no timing sleeps determine test outcomes.

## Observed failures and resolutions

1. The committed cleanup baseline could not start the backend because the
   documentation app indexed an optional `license_info` field removed by the
   same cleanup. The application now reads the optional field with `dict.get`;
   Docker health then reached `healthy`.
2. The first focused test run produced four passes and seven setup errors
   because pytest-asyncio created a new loop per test while the repository's
   lazy global asyncpg pool survived between tests. The integration module and
   fixture now share a session-scoped event loop; production pool semantics
   were not changed.

## Verification evidence

All backend commands ran inside the Docker development environment against the
Compose PostgreSQL service:

- `./deploy.sh dev`: passed after the documented cleanup-baseline fix; backend,
  PostgreSQL, Redis, Celery worker, Celery beat, and frontend all became
  healthy, and the migration step completed.
- `alembic downgrade e69999560f4f`, `alembic upgrade head`, and
  `alembic current`: passed; the final revision was `3f9e0e028cab (head)`.
- `pytest -q tests/integration/test_account_policy_concurrency.py`: 12 passed.
- `pytest -q`: 35 passed with two existing deprecation warnings.
- Focused `black --check` on all changed Python files: passed (7 files).
- Focused `isort --profile black --check-only` on all changed Python files:
  passed.
- Focused and repository-wide `flake8 --select=E9,F63,F7,F82`: passed.

The raw repository-wide `black --check .`, `isort --check-only .`, and
`flake8 .` commands were also run. They remain nonzero because the committed
cleanup baseline contains formatting/import/lint debt and has no shared
Black-compatible isort or 88-character Flake8 configuration. I03 did not
rewrite unrelated legacy files. The checks scoped to I03 pass, and the
repository-wide critical-error set required by `AGENTS.md` passes.

Every required real-PostgreSQL I03 criterion passed, so the prototype result is
Accepted. ADR 0001 remains Proposed rather than silently freezing the decision
before G0 human review.

## Remaining risks and deferred scope

- ADR 0001 remains Proposed until G0 human approval.
- The source and authentication of `owner_warning_proven_at` are not
  implemented; provider delivery belongs to later notification work.
- No Outbox dispatcher, Celery schedule, provider adapter, delivery attempt,
  public protocol, or API is present.
- Production timing units, defaults, policy limits, retention, and operational
  outage detection remain undecided.
- `DISABLED`, `DELETED`, grant-level claim state, recovery material, and all
  I09-I16 behavior remain out of scope.
