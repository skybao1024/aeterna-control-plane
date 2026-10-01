# Aeterna public protocol v1

This directory is the public, machine-readable source of truth for Aeterna I09
account/device binding, I10 signed heartbeat/device-status operations, I13
delayed-recovery record and one-time claim operations, and I14 Owner recovery,
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
mailbox challenge, a five-minute opaque claim token, and one exact secret-read
operation. Secret-bearing responses require `Cache-Control: no-store`.

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

The prepared release is `1.6.0` with tag name `protocol-v1.6.0`; preparing the
manifest does not create or publish a Git tag. Signed field changes and security
semantic changes require a new major/versioned operation as defined by ADR 0012. The prior major remains supported for at least 180 days after a successor
reaches general availability, with at least 90 days' sunset notice unless a
separate urgent security decision records a shorter migration.

## Privacy boundary

The package contains only Owner email verification, opaque authorization
material, request/account/device/binding identifiers, public keys, signatures,
challenges, device state, and the minimum monotonic heartbeat sequence and
server receipt response. Unknown fields are rejected. There is no activity
type or observation, client timestamp or deadline, application/window/URL data,
input value, local encrypted content, contact email, or custom notification
payload. The only recovery secret field is the purpose-limited 32-byte `srs`
in provisioning, Owner release, rotation provision, and released-secret success
responses; it is absent from
requests, logs, error bodies, audit fixtures, and all other operations.
