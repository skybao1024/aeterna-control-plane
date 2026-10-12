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
ADR 0031 additionally permits the signed post-release device notice to return
full addresses for at most ten known account-owned contacts, with the policy
release time and mail transport evidence described below.
Template reads return one field per response under the 16 KiB bound. Field edits
use a signed expected version, an account lock and atomic compare-and-set,
preserve the counterpart, and return structural receipts only. All configuration
responses require no-store. No personal values enter logs, audits or receipts. The only recovery secret field is the purpose-limited 32-byte `srs`
in provisioning, Owner release, rotation provision, and signed recipient secret
responses; it is absent from
requests, logs, error bodies, audit fixtures, and all other operations.

## Isolated inactivity trigger tests

ADR 0027 adds the closed, device-signed `/api/v1/trigger-tests/{operation}`
operations and distinct `aeterna.trigger-test.<operation>.v1` domains. These
additive resources share no production policy, heartbeat, recovery grant or
management state. The exact operation fields are normative JSON
schemas, with generated synthetic signatures and cross-domain/extra-field
negative fixtures. The operation literal replaces route hyphens with underscores
under `trigger_test.*`.

Creation snapshots an explicitly eligible Owner or accepted/verified contact,
requires acknowledgement, and remains PREPARING until native sample preparation
(if selected) succeeds. Server clock starts only on activation. Warning is due
after 60 seconds, threshold after 120 seconds, and grace is at least 60 seconds
after both actual grace entry and warning proof. These timings apply only to
test resources; delayed scanning or delivery extends them. Activity/stop and
dispatch are transactional, terminal resources cannot restart, and a local
countdown cannot authorize a transition.

The warning code and recipient code are eight decimal digits, purpose-bound,
rate/attempt/expiry limited, and verified independently. Recipient challenge
requires the opaque notice token from the exact configured-origin URL
`/trigger-tests/notice#session=<UUID>&token=<base64url32>`. Fragment data never
reaches the notice GET endpoint; no GET mutates authorization. A test claim can
retrieve/confirm only its exact synthetic source or already allocated successor
binding and can never authorize production retrieval or management. Claim tokens
are signed fields for release-secret/rotation-confirm and stay native-only.

All responses use `Cache-Control: no-store`. Provision/release-secret responses
contain synthetic SRS only at the native/service boundary. No ERC, VDK, password
or user content is transmitted. Sample content is native-only and readable after
actual full rekey and exact service confirmation. Test evidence distinguishes
provider acceptance, mailbox proof, local decryption and confirmed replacement;
the service completion report is not hardware attestation of local recovery.
The native safe view can project the locally observed sample state while the
service retains authoritative lifecycle/evidence. Expiry/cleanup invalidate
unused capabilities and remove exact isolated test resources; mail or factors
already copied cannot be recalled.

## Post-release device recovery notice

ADR 0031 adds the read-only signed `POST /api/v1/recovery/notice/read` operation
under `aeterna.recovery-notice.read.v1` and `recovery_notice.read`. The prepared
package release is `protocol-v1.11.0`; it has not been published or deployed.
Existing signed documents remain unchanged. The signed request contains the
account ID, `authorizing_device_id`, request ID, versions, canonicalization, and
at most ten unique known account-owned `contact_ids`. The device ID selects the
key; only proof by the exact bound device authorizes the request. Unknown and
cross-account contact IDs fail closed. The operation cannot discover contacts.

An active device can read the current policy state. A pinned dormant device may
read only its exact released recovery source. Lost or revoked devices cannot
authorize this operation. The response binds `account_id`, `device_id`, and
`request_id` to the signed request and uses server UTC `observed_at`. The closed
states are `NOT_CONFIGURED`, `ACTIVE`, `PRE_WARNING`, `GRACE_PERIOD`, `RELEASED`,
`DISABLED`, and `DELETED`. Only `RELEASED` returns non-null `released_at` and any
recipients; that state also requires a positive epoch and `last_activity_at`.
Other states have null `released_at` and an empty recipient list. These times
describe accepted activity and the service release; they do not establish that
the Owner is dead, unavailable, or the operator of a subsequent computer session.

The user-approved notice displays full email addresses without requiring a
library password. Responses contain at most one entry per requested contact,
limited to `contact_id`, normalized `email`, mail `kind`, and transport `status`.
Both `x-aeterna-unique-contact-ids` and
`x-aeterna-requested-contact-ids-only` are mandatory runtime constraints. Only
events bound to the exact current release epoch/generation/source contribute.
A contact's release mail takes precedence over a release invitation. Status is
`delivered` when any matching mail has delivery evidence; `submitted` when a
matching provider acceptance has no known failure; `pending` for queued, sending,
or retry-pending mail; `failed` when all matching mails have failed, bounced,
complained, or been cancelled; and `unknown` when evidence is absent or ambiguous.
Provider acceptance and delivery do not prove that the recipient read the mail.

All responses require `Cache-Control: no-store`. No token, link capability,
notification content, Owner message, library content, password, ERC, VDK, or SRS
is returned. Personal values never enter logs, receipts, or audit descriptions.
The read does not submit activity, alter policy state, retry mail, grant recovery,
or retrieve recovery factors. Synthetic fixtures cover every policy state,
transport status, closed fields, contact bounds, release constraints, and signed
domain/contact-set tampering.

The separately signed `POST /api/v1/recovery/notice/resend` operation uses
`aeterna.recovery-notice.resend.v1` and `recovery_notice.resend`. Its closed
request binds one existing account-owned `contact_id`, the account and exact
authorizing device, request ID, versions, and canonicalization. No email address,
new contact, message, URL, invitation token, or recovery capability can be supplied.
After authoritative `RELEASED`, an active device or the exact pinned dormant
source device may request another copy of the designated recipient's existing
release mail or release invitation. Lost/revoked devices, unrelated contacts,
and pre-release policies fail closed. The service selects the mail kind from
current release evidence; the caller cannot change it or add recovery authority.

Resend responses bind the account, device, contact, and request identifiers and
return only server `observed_at`, `kind`, transport `status`, and an integer
`retry_after_seconds` from 1 through 86,400. They contain no address, message,
link, token, or recovery factor and require `Cache-Control: no-store`. A pending
receipt establishes queued work only; provider submission and delivery retain
the limitations above. Replaying the same signed request is idempotent; the
same request ID with changed signed fields is a conflict. Concurrent requests
must not create duplicate pending mail, and a server-enforced 60-second cooldown
per target bounds further resend attempts. Rate limits use
`notification.rate_limited` with a bounded retry interval; an unavailable current
source uses the existing `recovery.record_unavailable` conflict response.
Resending does not record activity, reset inactivity,
change policy release state, bypass mailbox verification, or authorize recovery.
