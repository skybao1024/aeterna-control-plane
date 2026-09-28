# I14 Owner recovery and rotation implementation results

- Date: 2026-09-27
- Baseline: `2ea0570be5e6f833e5e03e8506920518d3444e9e`
- Result: Accepted for the fail-closed engineering boundary
- Canonical decision: desktop ADR 0015, Owner recovery, rotation, and
  post-compromise rekey
- Public protocol: prepared v1.3.0 digest
  `b7b0f41af9023ae7e30b4f21f5fae47976ec9b8cf490b50c8d61d81137abb75f`
- Production cloud activity: none

## Implemented behavior

The service now supports signed bound-device Owner recovery with a recent
heartbeat requirement, mailbox OTP, a cancellable 24-hour cooldown, bounded
same-device SRS redelivery, and transactional security-email intents. If the
policy becomes released during cooldown, the request is cancelled and the
caller must use an explicitly authorized successor-epoch rekey.

Recovery records carry immutable policy epochs and monotonic recovery
generations. A pre-release ERC rotation becomes active only after the initiating
device confirms a working target-generation wrapper. Activation revokes old
live recovery records and grants. Every other device provisions a distinct SRS
and recovery record and confirms its own wrapper; exact `pending`,
`not_enrolled`, `complete`, and `excluded` states remain visible with safe device
labels and timestamps. The account permits only one live rotation batch.

Post-compromise confirmation preserves the terminal released policy, grants,
claims, and audit evidence while creating one current active successor epoch.
Only migrated devices can extend its inactivity deadline. Historical or old-
epoch heartbeats remain replay-protected presence evidence and do not mutate
policy state, deadlines, grants, or notifications.

The migrations add immutable policy epochs, generation-bound recovery records,
Owner requests, rotation batches, per-device record bindings, redacted audit
events, and Owner security-email references. Downgrades refuse operations that
would erase live I14 meaning.

## Verification evidence

The complete Dockerized suite passed 103 tests. Eleven real-PostgreSQL recovery
tests cover cooldown, cancellation/release serialization, bounded redelivery,
release-during-cooldown escalation, pre-release revocation, distinct per-device
SRS records, exact partial status, immutable successor epochs, preserved old
grants, conflicting duplicate confirmation, and concurrent batch denial. Six
heartbeat tests include the historical released-presence boundary.

Migration `b28a413c96d2` is the current head and `alembic check` reports no model
drift. All 21 changed Python files passed focused Black and Black-compatible
isort. Repository critical Flake8 and focused Bandit passed. The public protocol
registry tests consume the exact v1.3.0 vendored digest.

The destructive downgrade path was not executed because it intentionally
refuses to discard live immutable-epoch or per-device rotation evidence. No
test contacted AWS KMS, SES, or another production service, and no real email,
deployment, resource provisioning, or protocol tag publication occurred.
