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
secret environment values were never read or printed. Temporary ignored scripts
inject a bounded clock through dependency providers and operate the existing
scheduler and Outbox; they expose no HTTP control endpoint. Any injected warning
proof is synthetic evidence, not human acknowledgement.

Both isolated native apps completed mailbox OTP; the second device's approval
capsule was prepared in the first app. The Mac subsequently locked. Actual device approval and new master password
entry await user handoff under the computer-use credential policy.
No successful native claim, full rekey, fresh protection, shared-ERC enrollment,
export/restore, or complete failure matrix is claimed yet. The desktop M05
result ledger owns that final acceptance evidence. No production AWS, mail
recipient, staging qualification, protocol tag, push, or production deployment was used.
