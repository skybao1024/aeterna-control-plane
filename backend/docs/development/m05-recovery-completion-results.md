# M05 recovery completion checkpoint

Updated: 2026-10-01. M05 remains In Progress pending real desktop acceptance.

## Approved contract and implementation

The desktop repository is authoritative for ADR 0019, approved by the Owner on
2026-10-01, and protocol package 1.6.0. Rotation confirmation can carry an
optional signed target ERC commitment. Accounts using managed M02 enrollment
must supply it. The first successful confirmation atomically installs the new
account commitment and target record; subsequent devices and duplicate
confirmations must match the exact Vault, wrapper, and commitment. Existing
nullable columns support this change; no migration or encryption format change
was introduced. Historical released grants and epochs remain immutable.

The public recipient route /recovery-claim keeps its link and claim bearer only
in memory, removes the URL fragment, clears OTP fields, and produces a bounded
handoff for the local desktop. It never requests or displays SRS. Requests omit
Owner credentials, use the existing same-origin API proxy, validate response
bindings, limit response bodies to 16 KiB, and time out after 20 seconds.
Navigation or replacement links invalidate asynchronous replies so cleared
bearers cannot reappear.

## Executed verification

All backend checks used Docker with a separate m05_checks database and the
injected local-test key provider. Focused recovery/protocol checks passed
29 tests; the complete backend suite passed 113 tests with four existing
deprecation warnings. Changed Python files passed Black, Black-compatible
isort, and Flake8's critical E9/F63/F7/F82 checks.

Repository-wide Black, default isort, and default Flake8 still report existing
formatting/import debt and a default 79-column Flake8 policy that conflicts
with the mandated 88-column Black style. These broad checks are
not claimed as passing. The debt was not repaired by unrelated formatting.
Frontend type checking, lint, and production build passed after the final
navigation-race and bounded-response changes. Exact duplicate confirmation
regressions reject a wrong Vault or commitment while preserving immutable
replay after a record is revoked.

## Acceptance boundary

The disposable aeterna-m05-isolated Docker project uses Mailpit, separate data
volumes, a smoke database distinct from m05_checks, and local-test KMS. Runtime
secret environment values were never read or printed. Versioned fixture scripts
`scripts/m05_acceptance_runtime.py` and `scripts/m05_acceptance_control.py`
replace the initial disposable helpers. They inject a bounded clock through
dependency providers and operate the existing scheduler and Outbox; they expose
no HTTP control endpoint. Injected warning proof is explicitly synthetic and
requires provider-accepted local SMTP evidence bound to the current warning
cycle's structural Outbox event. It is not human acknowledgement.

Both isolated native apps completed mailbox OTP, device approval, and Vault
creation. The first ERC was subsequently confirmed without being retained;
the second device was not enrolled. The Owner authorized autonomous synthetic
credential/material management and disposal of test data. Both native apps
were stopped before clock control, and the new Rust acceptance scenario uses
fresh synthetic accounts and Vaults instead of that incomplete fixture.

The opt-in desktop test
`ipc::emergency::live_acceptance::two_device_live_recovery_and_rekey` drives
actual signed HTTP requests, local SMTP, PostgreSQL policy/recovery services,
SQLite encryption and transfer, and native Rust gate/journal helpers. Passwords,
ERCs, OTPs, and link/claim factors are generated or received by the test, without
human entry. Only its generated MP/ERC values are retained in a unique mode-0700
temporary directory's mode-0600 `test-material.json`; no values are emitted or
committed. The production journal remains free of secret factors.

The fixture entry point fails closed unless development uses exactly
`m05_smoke`, `local-test` recovery keys, disabled production email/KMS, and
`mailpit:1025`. A deliberate `POSTGRES_DB=m05_checks` guard invocation was
rejected before fixture actions. The fixed test addresses loopback ports
8001/8027 and container `aeterna-m05-isolated-backend-1`. Stop isolated
worker/beat and native heartbeat producers before running it. For the existing
isolated Compose environment, pass its private file by both `--env-file` and
`ENV_FILE`; do not inspect or dump its values. Use the runtime command:

```sh
python -m uvicorn scripts.m05_acceptance_runtime:app --host 0.0.0.0 --port 8001
```

The controller must run inside that backend container from `/app`; it accepts
only the documented fixed actions and an account UUID. `begin-run` advances past
existing challenge resend deadlines without disabling limits, and `reset-clock`
is used after success and assertion failure. The desktop ledger records the
explicit Cargo command and exact passing run evidence. Native credential/dialog
and WebView interaction acceptance remains separate. No production AWS, real
mail recipient, staging qualification, protocol tag, push, or deployment was
used.

## Passing self-managed live run

The explicit desktop live acceptance test passed on 2026-10-01: 1 passed,
0 failed, 213.67 seconds. It used two synthetic signing identities and separate
Vaults on one Mac against the real isolated HTTP/SMTP/PostgreSQL services. It
verified shared-ERC enrollment, mismatch refusal without SRS, confirmed/private
recipient authority, valid-heartbeat warning cancellation, controlled
warning/grace/release, both one-shot claims, wrong OTP/ERC/bindings, durable
native Rust release gating, full rekey, password reuse/cancellation/interruption
refusal, restart with pending confirmation, exact confirmation replay and
commitment conflict, and successor account commitment continuity. B remains
pending in rotation and not enrolled in successor setup. Historical released
copies remain decryptable. Two independent A exports and one B export restored
exact note/attachment bytes; wrong passwords, existing destinations, and a
tampered package were refused. The fixture clock was reset after the run.

Final changed-script Docker Black, Black-profile isort, and critical Flake8
checks passed. These results do not change the existing repository-wide lint
debt described above. The desktop ledger retains the exact test log and private
artifact directory; it does not contain credentials. M05 remains In Progress
while native interaction evidence is incomplete.

## Autonomous interface evidence (2026-10-01)

The actual recipient page processed two unused links for the live fixture's
verified synthetic private recipient. Wrong OTP entry was rejected; separate
fresh mailbox codes produced handoffs for the same account and distinct device
and Vault IDs. The scope was recovery.srs.read; no ERC or SRS was displayed.
URL fragments were removed and refreshing cleared the bearer.

Through M05a's actual native file dialogs, two separately created UI exports
were each restored into empty targets, unlocked with existing generated
passwords, and inspected for exact synthetic note and attachment content.
An incorrect password and tampered package were refused. The native transfer
dialog initially hid its detailed localized error behind the overlay; that
defect was fixed and rechecked in English and Simplified Chinese after a
rebuild. The original encrypted Vault was restored with an identical SHA-256,
and both updated native apps retained active bindings and locked original
Vaults. This transfer evidence does not establish a coupled native
release/factor/rekey journey; source Vault lineage was preserved.

The guarded fixture runtime now disables development SQL echo and hides bound
parameters before database actions. A real controller pump emitted only its
bounded result. Docker Black, Black-profile isort, critical Flake8, the
wrong-database rejection, and boolean logging/clock checks passed. The isolated
API was restarted with the fix and its clock remained reset. Production
database logging and application entry points were not changed.

The desktop ledger records exact export/candidate hashes, private artifact
paths, native screenshots, the failing-before/passing-after UI regression,
and a passing final npm run check plus unsigned and configured native builds.
M05 still requires shared ERC entry/confirmation, release observation, local
factor entry, mandatory rekey, protection confirmation, and coupled interruption
feedback on native-bound Vaults. UI creation/change of authentication
credentials requires human entry/confirmation/submission under the computer-use
tool policy; this does not require a broad user rerun of autonomous tests.
