# ADR 0006: Recipient Vault rotation and local custody

- Status: Accepted
- Custody freshness and account-management authority superseded by ADR 0007
- Legacy contact retrieval compatibility superseded by [ADR 0008](./0008-signed-srs-retrieval-and-legacy-retirement.md)
- Date: 2026-10-10
- Governing decision: public Aeterna ADR 0024
- Production AWS activity and deployment: Not authorized by this implementation

## Context

A Recovery Contact must finish same-Vault recovery without the Owner's mailbox.
The native client replaces the master password, fully reencrypts the Vault with
a fresh VDK, and prepares fresh ERC/SRS protection. A lost response or an expired
mailbox authorization must not delete the only server factor matching the
locally updated Vault. Other Vaults may still depend on the Owner's shared ERC.

## Decision

Recipient recovery uses its own contact- and device-authorized transaction,
separate from Owner recovery and account rearm. The source record remains bound
to its immutable historical `RELEASED` policy, accepted verified contact, device,
Vault, and wrapper digest. A five-minute mailbox token alone cannot release SRS
or mutate a rotation; every operation also verifies the device signature over
its closed operation-specific document.

The recipient entry link remains usable while the exact released grant is
eligible, or its original contact needs to resume the rotation completion
receipt. It has no 24-hour entry deadline. Purpose-bound OTPs expire after ten
minutes and cannot be exchanged through legacy claim verification. The legacy
entry-link API keeps its existing lifetime.

The first successful native secret response reserves one rotation for the
source record and authorizes the existing Owner/other-contact security notices.
Exact retries do not create duplicate notices. Grants remain available until
confirmation. The legacy unsigned one-shot secret endpoint cannot bypass a
live recipient reservation.

Provision durably stores a KMS-encrypted successor before responding with the
temporary plaintext SRS. Exact target-ID and ERC-commitment retries decrypt the
same envelope. Prepare records the exact target wrapper digest before local
commit. The client places the new ERC in OS secure storage with readback, or
obtains explicit offline custody acknowledgement, before replacing local data.

Encrypted stages have no token-derived expiry and no automatic cleanup. The
same contact can verify the mailbox again after an interruption and finish the
exact stage. Confirmation atomically marks the stage complete, retires only its
source record and all grants/links/tokens for that record, and leaves every
other Vault, Owner policy, account epoch, and account ERC commitment unchanged.
Exact completion receipts remain replayable after renewed mailbox verification.
Recipient successor commitments use a separate per-Vault record namespace;
target generation is 1 and target epoch equals the source historical epoch.
`protection_active` remains false; recipient confirmation is not Owner rearm.

Only the same verified contact and registered device can abandon an unfinished
stage. The official client first verifies that the old source Vault is still
authoritative locally. Abandon frees the source reservation but retains any
encrypted successor because the server cannot prove that no local commit
occurred. At most 16 abandoned stages per source may be replaced in a rolling
day. Durable material and audit history are retained until explicit account-data
deletion or a separately approved archival procedure; token cleanup does not
touch them. A live stage requires the original contact to resume or abandon it;
another contact cannot take over that reservation.

Custody verification is a read-only signed operation against the current
Owner-managed `ACTIVE` sealed record. The supplied commitment must match both
the exact record and the current account commitment. A local password alone is
not evidence that an entered ERC is correct. No raw ERC is uploaded.

## Migration and verification

Migration `f4ca2910b803` adds the isolated recipient table, an authorization
scope, and redacted audit types after `d81b53aa672e`; existing account/record
commitments are untouched. Apply it before enabling the new native endpoints.
Rollback is refused while recipient material, tokens, or audit rows exist.
Restoring a backup or archiving these records requires a separate recovery plan;
deleting successor material to make a downgrade pass is unsafe.

The focused PostgreSQL suite runs this additive migration in a generated
isolated schema and checks response loss, long token expiry, duplicate and
concurrent confirmation, conflicting prepared digests, abandoned-material
retention, consent/release/signature checks, and current ERC custody validation.
Existing recovery regression tests run against the same isolated schema. This
is synthetic evidence, not a production KMS, SES, or desktop end-to-end test.

## Limits

Service revocation cannot revoke copied old keys or old encrypted Vault copies.
No SRS byte string expires cryptographically. The service does not possess MP,
ERC, VDK, plaintext content, or a cloud Vault backup. Account/authority deletion,
device-key loss, or permanent KMS-key loss can prevent further service access;
the new local password remains independent of pending server confirmation.
