# ADR 0009: Isolated inactivity trigger tests

- Status: Accepted
- Date: 2026-10-11
- Governing decision: public Aeterna ADR 0027
- Authorization: The human approved the exact isolated storage and sample recovery scope after reviewing the ADR. Production deployment and real-recipient development mail are excluded.

## Decision

The new signed `/api/v1/trigger-tests/{operation}` namespace owns separate session,
challenge and email-outbox tables. It never writes normal policies, heartbeat
anchors, production recovery records or grants, account authority, or real Vaults.
Only a current active bound device controls its session; one active session per
device, three starts per account per day, a thirty-minute expiry, and bounded
proof/send attempts limit abuse. Test recipients are the current Owner mailbox or
an explicitly selected accepted, verified, confirm-now contact. Eligibility and
suppression are rechecked before provider submission.

A recovery-inclusive session remains preparing until native synthetic-library
creation, isolated ERC custody and wrapper installation are confirmed. Independent
source and successor factors reuse the existing private-text AES-GCM boundary
with purpose `trigger-test-srs` and session UUID. The authenticated plaintext is a
closed object binding role, exact recovery UUID and SRS. Cross-role ciphertext
swaps or cross-session ciphertext copies fail before any factor response. Normal
recovery KMS context, workload identities and IAM permissions remain unchanged.

The normal policy scheduler and test scheduler share one pure timing decision
helper. Test warning/threshold/grace durations are 60/120/60 seconds. A delayed scan
cannot skip warning or grace, and release waits for a full interval after both
actual grace entry and independent Owner warning proof. Only explicit test
mailbox codes establish proof. The initial Owner warning already includes its
code. A warning-code request within the first sixty seconds reuses that pending
challenge; after the resend interval it can queue a fresh code and invalidate the
older challenge. The recipient notice instead requires its separate code request.
Normal duration minima and activity rules remain unchanged; test activity is a
separate stop transition.

Every marked email passes through the existing constrained adapter but uses a
separate durable test outbox. Preparing dispatch commits before the external
effect. Stop and dispatch compete on the account/test locks. A sending crash
becomes ambiguous after two minutes, never an automatic resend. Explicit retry
is allowed only for known failures and remains bounded to three attempts.
Provider acceptance is transport evidence, not reading or mailbox proof. The
service does not claim provider delivery, native decryption or production
activity qualification.

The recipient notice contains an opaque fragment capability. Requesting its
separate ten-minute, eight-digit mailbox code requires that capability. Proof
attempts are limited to five; a successful proof yields only a five-minute test
claim, retained by native. Source retrieval and exact successor allocation require
that test claim and exact session/Vault/record binding. Native performs actual
synthetic decryption and full rekey with a user-entered password. Its signed
confirmation records the exact generation-two wrapper. Completed sessions may
reverify the same recipient and retrieve the same durable successor before
expiry; they never acquire production management authority.

The dedicated nonsecret `AETERNA_TRIGGER_TEST_NOTICE_ORIGIN` is empty by default,
which reports capability unavailable and rejects starts. A configured production
origin must be HTTPS, contain no path, credentials, query or fragment, and match
the API origin compiled into native. Development accepts only loopback HTTP.
Normal `FRONTEND_URL` and recovery links are unchanged. The root-path static GET
landing has no scripts, performs no mutation and never reads a fragment token.

Expiry and stopping invalidate unused claims, links and factors. Minimal results
remain for one day after expiry, then session rows and test children are deleted.
Logs and receipts exclude complete addresses, code/link/claim plaintext, SRS,
ERC, VDK, passwords and user content. Operation receipts hold keyed digests only.

## Verification and rollout

The implementation includes strict cross-language protocol fixtures, isolated
real-PostgreSQL tests, stop/dispatch and duplicate-worker races, wrong/expired
proofs, recipient eligibility, factor context tamper, interruption/reopen, normal
policy non-mutation and actual signed HTTP with local Mailpit. The additive
migration is exercised only against ephemeral synthetic PostgreSQL.

Deployment requires independent approval: migrate additive tables, configure
notice origin, update backend/worker/beat together, and complete approved live
provider acceptance. Empty or invalid configuration leaves the capability
unavailable rather than simulating functionality. No production migration,
provider call, IAM change, deployment or real-recipient test is authorized by this
implementation report.

## Capability outage read semantics

The safe view's `available` flag also covers reading and managing an existing
session during a notice-origin or email-provider outage. That session remains
observable and stoppable. It is not a promise that a new test can be started:
`create` independently checks current delivery configuration and returns
`trigger_test.unavailable` when it is absent. `sampleRecoveryAvailable` describes
availability for preparing a new sample; existing encrypted test factors retain
their approved claim and expiry checks.
