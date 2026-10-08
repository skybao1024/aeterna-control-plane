# UX01 Owner configuration and safe message editing

- Date: 2026-10-03
- Status: Accepted within UX01 development scope
- Authority: desktop ADR 0020, Owner approved on 2026-10-03
- Scope: local development acceptance; no publication or production deployment

## Contract and implementation

Public protocol 1.7.0 is mirrored with digest
`4ebed102b09cfb905ec21ff938133cba874ce411f5f185e54393b24288ab4fb7`.
Three distinct signed operations read the Owner mailbox and at most ten known
account-owned contact addresses, read one saved message field, and atomically
edit one field at an expected version. Pending, unknown, dormant, lost, revoked,
wrong-key and cross-account access fail closed. Deleted addresses are null.
No account-wide discovery, database migration, encryption-format change,
provider change or local plaintext cache is introduced.

The account lock serializes absent-template creation and competing edits.
A stale version returns `notification.template_conflict`; the counterpart is
preserved. Existing private request digests protect exact replay/changed replay.
Idempotency receipts and audits contain only structural IDs/version/status.
Read responses use the existing no-store protocol envelope and 16 KiB bound.
The legacy whole-template service operation remains supported for compatibility;
the desktop removed its old caller/IPC permission and now uses field edits.
OpenAPI request/response models are registered with the real client routes.

## Verification

All runtime, format and test commands ran in the existing isolated Docker backend.
Tests used separate `m05_checks`; native acceptance uses retained `m05_smoke`.
The complete backend suite passed 129 tests with two existing deprecation warnings.
Final mirrored protocol verification passed 20 tests after generator formatting.
Black, Black-compatible isort and critical Flake8 E9/F63/F7/F82 passed for changed
Python files. SQL echo/parameter output was disabled for final execution.
Coverage includes identities, requested-ID scope, deletion redaction, unknown and
inactive devices, wrong key, stale activity, template readback/field preservation,
stale versions, concurrent creation with one winner, exact/changed replay,
receipt privacy, closed input, UTF-8/control/NFC bounds, package hashes and
cross-language/cross-domain signatures.

Signed native first/returning use, timing save, identities, saved-template edits
and restart passed against this service. Exact outcomes and final executable hash
are recorded in the desktop `docs/research/UX01-experience-results.md` ledger.
No complete recovery campaign is repeated for the unchanged recovery engine.
No commit, push, protocol tag, production email/provider or deployment occurred.
