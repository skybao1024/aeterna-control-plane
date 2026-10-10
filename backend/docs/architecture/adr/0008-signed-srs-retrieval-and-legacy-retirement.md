# ADR 0008: Signed SRS retrieval and legacy retirement

- Status: Accepted for implementation by the user on 2026-10-10
- Date: 2026-10-10
- Governing decision: public Aeterna ADR 0026
- Supersedes: Legacy contact claim and unsigned release compatibility in ADRs 0004 and 0006
- Production deployment and AWS activity: Separate authorization required

## Context

The retained `recovery.srs.read` route could release the source SRS with a valid
email link and mailbox proof before a native recipient rotation reserved the
record. It lacked the registered device signature required by recipient
recovery and consumed the contact's grant. Removing its frontend caller leaves
the service path callable. The user approved enforcing service security while
retaining the existing controlled-endpoint limit.

## Decision

The following legacy POST routes remain deprecated error-only tombstones:

- `/api/v1/recovery/claim/start`
- `/api/v1/recovery/claim/verify`
- `/api/v1/recovery/{recovery_id}/release-secret`

Valid legacy requests return the existing HTTP 400
`recovery.claim_unavailable` error with `Cache-Control: no-store`. Both the route
and direct service entry points reject legacy execution before database, KMS,
mail, audit or grant effects. Do not mint legacy challenges or tokens, redeem
previously issued `recovery.srs.read` tokens, or restore unsigned compatibility
on rollback. No new protocol error code or persistence migration is required.

Preserve original email link verifiers and the native recipient entry format.
The original link remains usable through recipient start and verification when
its exact grant or completion receipt is eligible. Recipient challenges retain
their separate purpose and `recovery.recipient.rotate` scope. A legacy token or
challenge cannot be converted into recipient authority. Existing consumed
grants cannot be silently reopened because their factor may have been disclosed.

Every recipient secret or rotation operation rechecks authoritative historical
`RELEASED` state, account, exact record/grant/contact authority, accepted verified
contact status, token purpose and expiry, exact device/Vault/wrapper bindings,
active registered device and its operation-specific signature. Completed
receipts resume only their exact confirmation. Preserve transactional
reservation and idempotent redelivery; failed responses must not strand the
legitimate signed recovery. Retain required redacted audit and security notices
for authorized native recovery.

Service custody continues to require KMS-encrypted SRS, narrowly scoped
generation/decryption workload roles, production TLS certificate validation,
no-store responses, and secret exclusion from gateway/application logs, tracing,
caches and crash output. Existing provider separation is not proof that live
IAM roles or gateway settings satisfy these requirements. The authenticated
release process and TLS termination gateway can see plaintext SRS; no additional
device-encrypted response or certificate pinning is introduced.

MP, ERC, VDK and Vault content are never uploaded. A compromised operating
system can capture secrets during native recovery and remains outside the
protection guarantee. Short-lived authorizations do not expire copied SRS.
The accepted full local rekey protects the updated Vault and cannot revoke
historical ciphertext or plaintext copies.

## Verification and rollout

Use synthetic Docker tests for all retired HTTP routes and direct service
methods, including a valid token minted before retirement. Assert no KMS calls,
mail delivery, claim minting, audit, grant mutation or recipient reservation.
Preserve original-link recipient verification, invalid-device-signature,
cross-binding, wrong-scope, expired-claim, retry and concurrency regressions.
Remove unused browser API wrappers and verify the browser recovery page only
explains how to continue in the native app.

Keep legacy protocol schemas and fixtures as historical contract evidence; they
do not authorize success responses. Vendor the exact public protocol package
and updated release digest. No production schema, grant or successor deletion
is part of the change. Deployment requires matching native recipient support
and separately verified TLS termination, secret redaction, KMS IAM and rollback
controls. Synthetic tests do not establish that operational acceptance.
