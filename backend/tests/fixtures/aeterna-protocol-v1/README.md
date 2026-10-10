# Aeterna public protocol v1

This directory is the public, machine-readable source of truth for Aeterna I09
account/device binding, I10 signed heartbeat/device-status operations, I13
delayed-recovery records and signed recipient claims, and I14 Owner recovery,
recovery rotation, and post-compromise successor operations.
Private database models, generated OpenAPI output, and desktop implementation
types are consumers, not protocol authority.

## Transport

- HTTP endpoints use `/api/v1` and exact `Content-Type: application/json`.
- Every body contains `protocol_version: 1`.
- Request and response bodies are at most 16,384 bytes.
- Input is UTF-8 I-JSON without a BOM, duplicate object members, trailing data,
  non-finite numbers, or unknown fields.
- UUIDs are lowercase canonical hyphenated strings. Binary fields use unpadded
  RFC 4648 base64url.
- Schema extension keywords beginning with `x-aeterna-` are normative runtime
  constraints not expressible by standard JSON Schema vocabulary.

## Signatures

The `signed` object is serialized to RFC 8785 JCS UTF-8 bytes and signed with
Ed25519. The outer `signature` is the unpadded base64url encoding of the raw
64-byte signature. Signed objects are closed and carry protocol, signature,
canonicalization, operation, request, and domain values.

The proposed new device uses `aeterna.device-binding.request.v1`. An existing
active device uses `aeterna.device-binding.approval.v1`. Operation names prevent
replay between initial request, delayed confirmation, cancellation, and
existing-device approval.

A device queries its current binding under the distinct
`aeterna.device-binding.status.v1` domain. The service verifies the matching
device key before returning its current state. Only an active device receives
the active-device count. A pending device receives only its own binding
challenge and delay bounds so an interrupted desktop can recover the approval
request. The query returns no email, OTP, grant, or private key material.

An active device submits heartbeats under `aeterna.heartbeat.submit.v1` and
changes device eligibility under `aeterna.device-status.change.v1`. These
domains are not interchangeable with each other or with device binding. A
heartbeat signs only account/device routing identifiers, a request identifier,
and a positive monotonic sequence. It contains no client time or deadline.

An active bound device configures an ACTIVE policy under
`aeterna.policy.configure.v1` and reads current setup under
`aeterna.setup.status.v1`. Policy timing starts at server receipt time. Setup
status reports current policy and active-device record states without secrets.
The setup status response and policy configuration response are never cached.

M02 recovery enrollment uses `aeterna.recovery-record.enroll.v1` with an
account-bound `erc_commitment`. The commitment is the base64url encoding of
SHA-256 over the UTF-8 bytes `aeterna:erc-commitment:v1` followed by one zero
byte, the 16 account UUID bytes, the current policy epoch and recovery
generation as unsigned 32-bit big-endian integers, and the 16 raw ERC entropy
bytes. The existing `recovery_record.provision` signature remains unchanged.
The service stores only the digest and rejects a mismatched subsequent device.
`setup.status` exposes `erc_committed`, never the digest or ERC.

An active bound device provisions, confirms, or abandons one recovery record
under operation-specific signed domains. Provisioning returns a 32-byte SRS
once; confirmation binds the local wrapper digest. A released, accepted, and
verified contact then uses a fragment-carried claim-link token, an eight-digit
mailbox challenge, a five-minute opaque recipient claim token, and exact
device-signed retrieval and rotation operations. Secret-bearing responses
require `Cache-Control: no-store`.

An active, recently seen bound device starts Owner recovery under
`aeterna.owner-recovery.start.v1`; release, cancellation, completion, and status
use `aeterna.owner-recovery.action.v1`. Recovery generation and policy-epoch
rotations use separate provision and confirm domains. Owner recovery is bound to
one exact recovery wrapper. Post-compromise confirmation advances an immutable
policy epoch and always reports `rekey_required` before old material can be used.

Rotation confirmation optionally carries the target-generation ERC commitment.
M02-enrolled accounts require it. The service atomically establishes it when the
initiating wrapper confirms and requires matching later devices and exact duplicate
confirmations. The commitment uses the same account-bound computation above,
with the target epoch/generation. ADR 0019 explicitly approves this additive
exception to the general signed-field versioning rule for the M02/I14 integration.
Legacy signed documents remain byte-for-byte compatible.

## Publication and compatibility

`manifest.json` hashes every normative file and contains a release digest over
the RFC 8785 canonical manifest without `release_digest`. The private control
plane vendors this exact package, pins the release tag and digest, and runs the
same fixtures.

The prepared release is `1.9.0` with tag name `protocol-v1.9.0`; preparing the
manifest does not create or publish a Git tag. Signed field changes and security
semantic changes require a new major/versioned operation as defined by ADR 0012. The prior major remains supported for at least 180 days after a successor
reaches general availability, with at least 90 days' sunset notice unless a
separate urgent security decision records a shorter migration.

### Legacy contact retrieval retirement

[ADR 0026](../../docs/adr/0026-signed-srs-retrieval-and-service-boundary.md)
records the urgent security exception retiring unsigned contact retrieval
without a compatibility grace period. `POST /recovery/claim/start`,
`POST /recovery/claim/verify`, and
`POST /recovery/{recovery_id}/release-secret` remain deprecated, error-only
tombstones: valid legacy requests return HTTP 400 `recovery.claim_unavailable`
with `Cache-Control: no-store`, without database, KMS or notification side
effects. Previously issued `recovery.srs.read` tokens cannot be redeemed or
converted into recipient authority. Historical legacy schemas and fixtures
remain for contract evidence; no legacy success response is authorized.

Original email entry links remain usable through the recipient claim endpoints
when their exact grant or confirmation receipt is eligible. Recipient requests
retain their existing signature documents, scopes and error codes. This change
does not alter the encryption format or expire previously copied SRS.

## Recipient successor operations

ADR 0024 adds `/recovery/recipient/claim/start` and
`/recovery/recipient/claim/verify`. The entry URL remains usable while its exact
source entitlement is eligible, or for the same contact's outstanding exact
confirmation. Email challenges expire after ten minutes and the distinct
`recovery.recipient.rotate` grant expires after five minutes. Legacy claim
credentials cannot authorize these operations.

`/recovery/recipient/secret` and
`/recovery/recipient/rotations/{rotation_id}/{provision,prepare,confirm,abandon}`
require the original device signature and contact grant. Each signature domain
is `aeterna.recipient-recovery.<operation>.v1`. The signed fields identify the
exact historical source, rotation, and operation; target operations additionally
bind the fresh recovery identity, ERC commitment and, for prepare/confirm, exact
target wrapper digest. The outer claim token is not included in the signed
document. Another contact or changed target cannot take over a live reservation.

Provision retains encrypted successor SRS durably; prepare binds an immutable
target receipt before native commit. Neither OTP nor grant expiry deletes staged
material. Secret/provision redelivery and exact confirmation retries tolerate
lost responses. Confirmation retires only the source entitlement and records
the isolated `recipient_successor` binding with Vault-local generation one.
Confirmation also records full account management for the verified recipient.
Completed responses require `account_management_transferred: true` and the
recipient's `management_email`; prepared responses require false and a null
mailbox. The Owner account policy and shared ERC commitment do not change during
Vault confirmation. Responses explicitly return `protection_active: false`.
An authorized manager must explicitly configure the next policy epoch and
complete normal recovery enrollment before future protection is ready.

`/recovery/custody/challenge` uses
`aeterna.recovery-custody.challenge.v1` to obtain a five-minute server-issued
challenge bound to the exact signed account/device/Vault/recovery/wrapper.
`/recovery/custody/verify` uses `aeterna.recovery-custody.verify.v1` and additionally
signs `challenge_id`, the 32-byte `challenge`, and the ERC commitment. Only an
exact current sealed Owner binding or confirmed recipient successor can match.
The challenge is consumed atomically; an exact request retry returns its original
result only before expiry, while changed or expired replay is rejected.
Both operations are rate limited before database work and after device proof.
They never receive raw ERC, MP or VDK, release SRS, or grant management authority.
Local storage adoption follows successful verification and secure-store readback.

An account challenge may include `account_id` only for `device_binding`.
This targets a recovered account explicitly when the manager's mailbox also
belongs to another account. Successful manager mailbox snapshots remain
independent of that mailbox's original account. Signed configuration returns
`owner_email` for operational reminders and `management_email` for the current
device's preferred account verification. Mailbox values remain session-only in
the desktop client.

## Privacy boundary

The package contains only Owner email verification, opaque authorization
material, request/account/device/binding identifiers, public keys, signatures,
challenges, device state, and the minimum monotonic heartbeat sequence and
server receipt response. Unknown fields are rejected. There is no activity
type or observation, client timestamp or deadline, application/window/URL data,
input value, or local encrypted content. ADR 0020 explicitly permits the
active-device-only configuration operations to return the Owner mailbox, at most
ten known account-owned contact addresses, and saved notification messages.
These operations never discover contacts; deleted contact addresses are null.
Template reads return one field per response under the 16 KiB bound. Field edits
use a signed expected version, an account lock and atomic compare-and-set,
preserve the counterpart, and return structural receipts only. All configuration
responses require no-store. No personal values enter logs, audits or receipts. The only recovery secret field is the purpose-limited 32-byte `srs`
in provisioning, Owner release, rotation provision, and signed recipient secret
responses; it is absent from
requests, logs, error bodies, audit fixtures, and all other operations.
