# ADR 0007: Custody verification freshness and recipient account management

- Status: Accepted
- Date: 2026-10-10
- Governing decision: public Aeterna ADR 0025 and explicit user approval
- Production deployment and real provider activity: Not authorized

## Decision

Custody adoption uses a five-minute, server-issued, device-signed challenge.
Verification consumes that exact challenge atomically, recording the request ID
and signed digest. Identical successful retries are accepted within its lifetime;
changed, mismatched, consumed, and expired challenges cannot be reused. ERC
commitments are comparisons only, never recovery or management credentials.
Account, device, policy, and recovery records are read without update locks; only
the short-lived challenge row is locked for consumption. IP limits precede
database work and authenticated-device limits precede record comparisons.
Redis counters are atomic, shared by workers, bounded by expiry, and fail closed.
IP identifiers use existing keyed lookup rather than reversible address hashes.
Challenge issuance deletes at most 256 expired nonce receipts using the expiry
index and SKIP LOCKED; active challenges and their live retry receipts are kept.
No raw ERC, passwords, content keys, or content enter this endpoint. Completed
recipient successor verification is rejected once a newer sealed Owner-managed
record or completed successor replaces the same device/Vault binding.

The official native client confirms only after local rekey. The service validates
the exact prepared receipt, verified contact, and registered device signature; it
cannot cryptographically prove local rekey or ERC possession without holding core
keys. A compromised registered device already has broad account API authority.
Exact recipient confirmation grants full account management.
Preparation, SRS release, and mailbox verification alone do not grant it.
Every successful recipient obtains an independently encrypted mailbox alias;
aliases are unique within an account and do not merge another account owned by
the same mailbox. The first completed alias remains the primary operational
mailbox. Later completions retain both recipients' full management and mailbox
verification ability. Original identity lookup remains an immutable locator;
it does not authorize the former mailbox after handoff. Explicit account-targeted
mailbox challenges accept any completed management alias and reject stale
pre-transfer mailbox challenges and grants. First handoff also cancels pending
original-Owner recovery OTP/cooldown requests, preserving their encrypted stages.
Mailbox proof writers acquire the account lock before child proof locks so
confirmation and future binding verification cannot commit stale authority.
On a genuinely unbound native client, the recipient may explicitly select the
recovered account ID for device-binding OTP verification. The grant stays bound
to that exact account even when the mailbox owns a separate account. A fresh
device remains pending when the account already has an active device; the
existing signed approval or delayed-confirmation flow activates it. Choosing an
account does not grant management or bypass OTP and binding approval.

The existing signed device credential retains full account API capability.
Confirmation does not revoke other devices, reencrypt other Vaults, reset the
historical policy, or expire copied old keys. An explicit subsequent policy
configuration creates a fresh ACTIVE epoch and enrollment namespace, preserving
historical release records. Only its initiating device joins the new activity
epoch automatically; other devices retain status and their historical content.

## Migration and verification

An additive migration follows recipient rotation migration f4ca2910b803.
Mailbox snapshots survive contact edits or deletion. Downgrade refuses live
management aliases instead of deleting authoritative mailbox data. Alias/rotation
foreign keys restrict deletion of live management history; an eventual hard-delete
operation needs an explicit cleanup procedure. No such account/device deletion
endpoint is added by this decision. Focused
PostgreSQL tests use generated isolated schemas and synthetic key/email adapters.
Tests cover replay, expiry, tampering, concurrency, multiple managers, existing
external-account collisions, stale mailbox grants, and explicit protection setup.
Production migration, KMS, and email delivery require separate deployment work.
