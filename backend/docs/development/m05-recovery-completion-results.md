# M05 recovery completion checkpoint

Updated: 2026-10-02. M05 is Accepted for its declared development scope.
The internal MVP is feature-complete; staging and release qualification remain open.
Desktop acceptance checkpoint: `cf4568d` on `main`.

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

At the initial checkpoint, both isolated native apps completed mailbox OTP,
device approval, and Vault creation. The first ERC was confirmed without being retained;
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
artifact directory; it does not contain credentials. At that checkpoint M05
remained In Progress while native interaction evidence was incomplete.

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

## Original native fixture preparation and recipient regression (2026-10-01)

Both original M05 native Vaults were unlocked by the Owner. Their original
shared ERC had not been retained, so the second device could not enroll. Under
the existing authorization to reset disposable development data, both Vaults
were exported through their real native dialogs and the isolated m05_smoke
PostgreSQL database was dumped privately. pg_restore --list parsed the dump
successfully before any reset.

A temporary ignored Docker-only script reused the guarded M05 runtime and
required the fixed original native account, exactly the two named synthetic
active devices, an ACTIVE epoch/generation-1 policy, exactly A's original
sealed record, and no grants, Owner recovery requests, or rotations. A locked
transaction retained the original record as revoked and cleared only its test
account ERC commitment. No local Vault, MP, OS key, device identity, binding,
policy timing, or production service changed; both encrypted database hashes
remained identical. Preview, execution, Docker Black, and critical Flake8 checks
passed. No reset API or production capability was introduced.

The refreshed native interfaces enabled new enrollment. The Owner generated
A's new native ERC, which was retained privately in the desktop artifact
directory with mode 0600. Its value was not emitted. The Owner subsequently
completed B's same-code entry and both native confirmations. Fresh native
reads confirmed recovery protection on every eligible device. The coupled
claim/rekey journey remains incomplete; enrollment alone is not Accepted
evidence.

A synthetic confirm-now contact was created in native B and its invitation
was delivered only to local Mailpit. A fresh recipient page incorrectly
reported the valid link as invalid: StrictMode replayed the initialization
effect after the hash was removed and replaced the captured token with null.
ContactInvitation now preserves the captured token during effect replay;
genuine hash changes still consume the new link and replace or clear it. The
same invitation in a fresh page then displayed Accept and verify, completed
submission, and native B confirmed accepted/verified status and local provider
acceptance. A later invalid hash showed the error state. Before/after screenshots
are retained privately in the desktop ledger's artifact directory.

Frontend pnpm type-check, pnpm lint, and pnpm build passed. No test framework,
production dependency, API contract, authentication condition, or English UI
copy was changed. These checks do not substitute for the remaining native
credential handoff and coupled journey.


## Original native account warning and release checkpoint (2026-10-01)

A's actual native policy controls accepted 14-day inactivity, 3-day warning,
and 3-day grace. Both native applications were quit through their menus and
subsequently verified stopped before controlled time advancement. The guarded
Docker controller ran the existing scheduler, delivered the current-cycle
Owner warning to local Mailpit, recorded explicitly synthetic warning proof,
and advanced through GRACE_PERIOD to RELEASED. Read-only proof then confirmed
two available grants and two active, unexpired links. No factors, bearer
values, or message bodies were emitted. SMTP acceptance and synthetic proof
are not proof of human receipt.

The desktop retained private note/attachment and encrypted-frame baselines
before local rekey. Native release observation stopped because macOS is
locked and the computer-use tool requires manual OS unlock. The fixture clock
remains advanced for the pending controlled claim journey and must be reset
after that run. Original native claim, mandatory rekey, fresh confirmation,
and coupled interruption feedback remain unverified; M05 is In Progress.


## Original native acceptance completion (2026-10-02)

The Owner unlocked macOS and both original native apps observed RELEASED.
The actual recipient page rejected a wrong OTP, then returned B's bounded
handoff after the correct local Mailpit challenge. Native A rejected that
cross-device handoff. B refused a valid-format ERC from a different synthetic
account, accepted the retained shared native ERC without a second SRS fetch,
and reached mandatory rekey. Cancelling cleared memory and preserved all of
B's encrypted frames while its persistent ordinary-unlock gate survived restart.

Native A used its own link, contact OTP, and shared ERC. Owner start initially
refused missing recent presence, as designed. A guarded development-only locked
transaction temporarily set only the original A device's last_seen_at to the
controlled clock. It required the exact two-device RELEASED epoch/generation-1
account, both claimed grants, and no Owner request. The real bound native key
then signed Owner start; the previous timestamp was immediately restored with
an exact-marker condition. Private provenance confirms restoration. This
synthetic presence precondition is not a server-accepted heartbeat or native
activity evidence. No endpoint, production rule bypass, or retained mutation
script was introduced. The independent passing Core live test exercised the
actual recent signed-heartbeat requirement.

The actual Owner mailbox OTP enabled a fresh successor proposal. The Owner
entered/submitted the agent's privately retained synthetic new master password
and confirmed separate retention of the newly displayed native ERC. A completed
full local rekey and fresh protection confirmation. Service setup became ACTIVE
at epoch/generation 2 with a target commitment and sealed record. A is complete;
B remains not enrolled, with complete/pending rotation slots. Partial status
was not represented as protection for both devices.

Read-only desktop baselines show A's preserved Vault/device identities, changed
recovery identity, higher master revision, changed wrappers/header, and changed
ciphertext with generation increments for every item/attachment frame. A's
restart unlocked with the new existing password. Two independent native exports
were separately imported into empty targets and unlocked through the real UI;
both preserved the original note digest and complete synthetic attachment.
The original rekeyed source directory was restored byte-identically afterward.
B's original ciphertext and both OS bindings were preserved.

Both native apps stopped before the controlled clock was reset to zero.
Read-only proof confirms ACTIVE epoch/generation 2, a present target commitment,
one sealed target record, complete/pending slots, SQL echo disabled, and SQL
parameters hidden. Native B subsequently observed current ordinary server time.
The desktop now classifies its persistent recovery gate as vault_rekey_required
and gives actionable bilingual recovery guidance. Owner-unavailable copy also
explains the recent-presence prerequisite and possible request conflict. These
presentation fixes do not change service authorization, protocols, or crypto.

The desktop result ledger retains native screenshots, private artifact paths,
exact export hashes, failing-before/passing-after regressions, canonical checks,
and configured signed build results. Earlier dated sections are historical
checkpoints, not outstanding native handoffs. M05's controlled native journey,
two-copy restore, and critical refusal/interruption cases are complete. B needs
another available authorization and its own full rekey after cancelling its
one-shot claim; complete multi-device UX, Owner-forgot-MP, and independent ERC
rotation remain M06. Controlled time/warning proof and synthetic presence do
not qualify real mail receipt, production AWS/KMS, or hardware activity.
No push, deployment, protocol tag, or release approval is claimed.


Final desktop verification passed with 50 frontend tests and 178 Rust tests,
format/lint/type/protocol/asset checks, Clippy, and all-target/all-feature Cargo
check. Two intentional tests remain ignored in the default run; the isolated
live scenario passed independently above and was not rerun for the final
presentation/classification changes. Canonical and both configured native
builds passed, and both signed bundles passed deep/strict codesign verification
with the unchanged approved identity and device-scoped entitlements. Final A
unlocked its preserved source with the new MP and matched the original note
digest/attachment. Final B's separate synthetic password candidate hit the
explicit persistent gate, cleared the field, and exposed no content; it was not
B's correct old MP. The focused Rust regression separately verified correct-old-
MP refusal before/after restart. Both apps were quit afterward; A's database
remained byte-identical and B's encrypted frame digests/generations were unchanged.
A final read-only clock check returned zero. Only authorized local checkpoint
commits are made; no remote publication is performed.
