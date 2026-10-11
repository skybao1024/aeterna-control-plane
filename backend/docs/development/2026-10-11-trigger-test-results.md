# Isolated inactivity trigger test implementation and verification

Date: 2026-10-11
Scope: Accepted public ADR 0027 and private ADR 0009. No deployment or real-recipient development email.

## Implementation

Dedicated test-session, purpose-bound challenge and test-mail tables are added by
migration `a74fa3967484`, following the existing contact-locale migration. Strict
signed routes expose the thirteen agreed operations. Read never advances the
clock. A separate ten-second Celery task owns timing, mail dispatch, interrupted
send reconciliation and bounded expiry. The production scheduler shares its
unchanged timing decision helper; production minima, normal storage and release
authority remain unchanged.

The default notice-origin configuration is empty and disables starts. Configured
origins must match native's compiled service origin. The fragment-only notice
has a static safe landing page. Actual provider acceptance, Owner mailbox proof,
recipient mailbox proof, sample protection confirmation and activity stopping
remain separate evidence. Native alone establishes decryption and gates sample
content; service confirmation is a signed report, not hardware attestation.

Public protocol release `1.10.0` is vendored exactly, including the prepared
manifest digest `2997eb49b03235e1e81f4ad55a6a2b0281eed4c1a4613542208328258dc923d9`.
`confirmation_pending` is a native-only safe sample projection; the service does
not emit it or claim local decryption.

## Isolated verification environment

Commands execute inside an independent Docker Compose backend service, with
source mounted, working directory `/tmp`, no `env_file`, and explicit synthetic
settings. PostgreSQL uses tmpfs, Redis has persistence disabled, and Mailpit is
the only email sink. No protected environment file was read; existing development
containers, database, application identity and runtime configuration were left
unchanged. The temporary Compose project is `aeterna-trigger-tests`.

Focused protocol and PostgreSQL tests initially passed 106 tests, including real
signed HTTP through the route and separate warning/recipient email proofs read
from local Mailpit. The complete backend suite then passed 522 tests in 42.82
seconds, with four pre-existing dependency deprecation warnings. The final notice
origin and static landing refinements receive focused verification below.

The shared timing helper and existing policy concurrency suite passed 27 tests.
Tests cover delayed scheduling, late proof and full grace, actual test activity
stopping, exact source/successor retry, completed sample reverification/reopen,
wrong-code lockout, unconfirmed/private recipient rejection, expiry factor
clearing, cross-role/cross-session factor tampering, revoked device rejection,
duplicate workers and the dispatch transaction winning or losing stopping.

## Final verification receipts

All commands below used the independent synthetic Compose backend, without an
`env_file` and with its working directory `/tmp`.

- Final complete `python -m pytest /app/tests -q`: **536 passed**, four existing
  dependency deprecation warnings, 12.80 seconds.
- Final focused protocol, actual SMTP/Mailpit, origin, ordinary policy concurrency
  and timing suite: **144 passed** before the final expiry/capability edge cases;
  those extra regressions are included in the final complete suite.
- Focused `black --check` on all twenty modified Python files: passed.
- Focused `isort --profile black --check-only` on the same files: passed.
- Repository CI command `flake8 app scripts tests --select=E9,F63,F7,F82`
  (absolute container paths): passed.
- `pip check`: passed, no broken requirements.
- Alembic `current`, downgrade to `2ea8c943d6b1`, upgrade to `head`, `current`
  and `check`: passed in the fresh tmpfs database. Final revision is
  `a74fa3967484`; no new upgrade operations were detected.
- Exact recursive comparison of the vendored public protocol package: passed.

Raw repository-wide `black --check`, default `isort --check-only` and default
`flake8` were also run and remain nonzero. Black/default-isort identify the
existing backoffice authentication, database and older migration baseline;
default Flake8 also enforces a 79-column limit inconsistent with the established
Black style and reports existing unused-import/import-order issues. Unrelated
files were not reformatted and configured CI checks were not weakened.

The HTTP integration uses real strict signed routes, actual PostgreSQL
transactions and the local SMTP Mailpit adapter. Server time is injected by the
synthetic test harness to exercise the real timing decisions at boundaries; it
does not assert a three-minute wall-clock or native-to-deployed-service flow.
Mailpit warning proof, opaque notice fragment and separate recipient proof are
validated inside the test process. Only non-secret counts and outcomes are
retained; mail bodies, capabilities, complete addresses and factors are not
exported.

Review fixes include preserving static notice landing `default-src 'none'` and
`no-referrer` through global middleware, committing capability invalidation when
an expired mutation is rejected, and retaining read/stop visibility if new-start
delivery configuration becomes unavailable. Their regression cases passed.

## Deployment boundary

No deployment, shared-database migration, runtime environment edit, real-recipient
email, production KMS/IAM change, Git commit or push occurred. The backend feature
remains disabled without `AETERNA_TRIGGER_TEST_NOTICE_ORIGIN`. Enabling the feature
requires a separately authorized service deployment, additive migration
`a74fa3967484` (after `2ea8c943d6b1`), and backend/worker/beat refresh. The
non-secret configuration must be
`AETERNA_TRIGGER_TEST_NOTICE_ORIGIN=https://api.aeternarelay.com`, matching
native's compiled service origin, together with the existing approved mail
provider configuration. The existing API-origin Nginx root proxy already routes
the static notice landing, so no additional recipient origin or proxy permission
is required. Production
SES delivery callbacks do not route test mail through the normal recovery outbox;
provider acceptance and independent mailbox proof are the available evidence.



After the final read-only cross-boundary review found no additional actionable
service defects, `docker compose -f /tmp/aeterna-trigger-tests.compose.yml down
--remove-orphans` completed successfully. Only the independent synthetic project
was removed, including its ephemeral PostgreSQL, Redis and Mailpit data. Existing
development containers and shared databases were not stopped or changed.


## Hosted update preparation after explicit deployment authorization

The user subsequently authorized updating the hosted service and separately
approved committing/pushing the reviewed service scope. This agent prepared
source only; deployment and Git publication remain owned by the coordinating
agent. The new `deploy.sh` release child defaults only an unset public
`AETERNA_TRIGGER_TEST_NOTICE_ORIGIN` to `https://api.aeternarelay.com`.
It reads only that approved assignment from public deployment configuration as
inert data, preserving explicit empty and quoted custom values even when the
previous installed wrapper did not export the control. Configuration shell
syntax is rejected. The production Compose shared map retains an empty default
and passes the exported control into backend, worker and beat. No protected
runtime-file read or write is needed. Core service settings and IAM are unchanged.

The release workflow pauses only its synthetic worker and beat before database
fixture tests, after successful environment/initializer startup. It retains every
test case and production scheduler behavior. The release command additionally
checks exact image equality and health for backend/worker/beat, packaged-versus-
database Alembic head, registration on the exact worker, and the packaged
trigger-test task's ten-second beat configuration. The configuration check does
not establish observed scheduler cadence or mailbox delivery. A separate bounded
`<full-SHA>-trigger.json` receipt contains only fixed booleans and status values;
the existing recovery receipt and restricted CI permissions remain unchanged.
Explicit empty origin is a valid `disabled` result. No business task, email,
provider probe or secret-provider access is performed by the diagnosis.

Final source preparation receipts:

- Complete isolated Docker backend `python -m pytest /app/tests -q`: **598 passed**,
  four existing dependency deprecation warnings, 11.84 seconds. No background
  worker or beat ran against these fixtures.
- Focused release-diagnostic Docker suite: **62 passed**; focused Black,
  `isort --profile black` and configured critical Flake8 checks passed.
- Actual diagnostic CLI against fresh synthetic PostgreSQL/Redis returned a
  bounded failure JSON with matching database head and beat configuration,
  correctly identifying that no test worker was running. No hostname, origin
  value or dependency error text was emitted.
- `bash tests/deployment/test_release.sh`: **13 release safety checks passed**,
  including exact-image mismatch, failed diagnostic and explicitly disabled
  capability rollout cases.
- `bash tests/deployment/test_trigger_test_configuration.sh`: **five first-upgrade
  configurations and injection rejection passed**. Unset, explicit empty,
  quoted empty and both quoted custom values were resolved through actual
  synthetic production/AWS/small/release Compose overlays for all three services.
- `bash -n` on release and test shell scripts, workflow YAML parsing, and
  `git diff --check`: passed.

These receipts cover source preparation. They do not constitute a production
rollout, observed scheduler cadence or real-recipient email acceptance.
