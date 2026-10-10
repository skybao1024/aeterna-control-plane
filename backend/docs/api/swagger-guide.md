# OpenAPI and Swagger

The service exposes separate documentation applications in development and
preview environments:

- `/client/docs` and `/client/openapi.json`
- `/backoffice/docs` and `/backoffice/openapi.json`
- `/api-docs/client.json` and `/api-docs/backoffice.json`

Client and backoffice routes are registered in
`app/route/router_registry.py`. Update the corresponding OpenAPI tags whenever a
route group changes.

The client account/device routes implement the public desktop protocol v1 at:

- `POST /api/v1/account-challenges`
- `POST /api/v1/account-challenges/{challenge_id}/verify`
- `POST /api/v1/device-bindings`
- `POST /api/v1/device-bindings/{binding_id}/approvals`
- `POST /api/v1/device-bindings/{binding_id}/delayed-confirmations`
- `POST /api/v1/device-bindings/{binding_id}/cancellations`
- `POST /api/v1/heartbeats`
- `POST /api/v1/device-status-changes`
- `POST /api/v1/contacts`
- `POST /api/v1/contacts/{contact_id}/invite`
- `DELETE /api/v1/contacts/{contact_id}`
- `POST /api/v1/contacts/{contact_id}/status`
- `POST /api/v1/contact-invitations/respond`
- `PUT /api/v1/notifications/template`
- `POST /api/v1/notifications/test`

These routes manually enforce the public transport boundary before Pydantic
validation: exact JSON media type, a 16,384-byte limit, UTF-8 I-JSON, no BOM,
no duplicate members, closed schemas, and matching protocol versions. Their
OpenAPI request bodies are supplied from the same closed Pydantic models even
though runtime parsing is manual.

Successes contain `protocol_version`, `request_id`, and a closed `data` object.
Failures contain the protocol version, an optional syntactically valid request
ID, and a stable nonlocalized `error.code`. Device-binding, delayed-confirmation,
and cancellation grants use an opaque one-use token in the `Authorization:
Bearer` header. Existing-device approval instead requires the registered
device's Ed25519 signature. The legacy password/JWT client-auth router is not
registered; backoffice authentication is unchanged.

Heartbeat and device-status requests also use closed RFC 8785/Ed25519 signed
documents under operation-specific domains. Heartbeats carry only account and
device routing identifiers plus a monotonic sequence. Server receipt time owns
cooldown, dormancy, and aggregation; no client timestamp or deadline is
accepted.

Contact and notification-template mutations use operation-specific signed
RFC 8785/Ed25519 documents from an active bound device. Invitation responses
are deliberately generic and accept the single-purpose secret only in the
bounded JSON body; the secret is never an API path or query parameter. The
fixed invitation page receives the token in the URL fragment and submits it in
the request body. Unknown fields, phone numbers, SMS channels, headers,
attachments, arbitrary HTML, and message text over 4,096 UTF-8 bytes are
rejected. Contact status exposes consent and transport state without provider
message identifiers, recipient addresses, or message bodies.

The AWS SES event callback is intentionally excluded from Client and
Backoffice Swagger. `POST /api/internal/v1/email-events/aws-sns` accepts only a
bounded Amazon SNS envelope for the configured topic, requires SignatureVersion
2 verification, and records transport-only evidence. When the temporary
`AWS_SES_SNS_CONFIRMATION_CAPTURE_ENABLED` control is enabled, signed
subscription confirmation material is cached in Redis for at most 15 minutes.
An authenticated operator confirms it through the backend setup script; the
callback never follows a confirmation link or changes an SNS subscription.
During this temporary setup window, only an operator-registered SES test
message ID may be acknowledged without an application Outbox record. Its
registration and verified receipt metadata expire after 15 minutes.
See [AWS SES setup](../deployment/aws-ses.md) for the explicit operator workflow.

Documentation is not an authorization boundary. Every protected route must
enforce its authentication and authorization dependency even when production
documentation is disabled.

The OpenAPI contract must not advertise generic file upload or cloud-storage
operations. Aeterna control-plane APIs never accept vault content, messages,
media, or attachments.

Recipient recovery is separate from Owner account recovery. The desktop uses
`POST /api/v1/recovery/recipient/claim/start` and
`POST /api/v1/recovery/recipient/claim/verify` to obtain a five-minute
`recovery.recipient.rotate` mailbox authorization. Subsequent operations require
both that token in the closed body and the registered device's signature:

- `POST /api/v1/recovery/recipient/secret`
- `POST /api/v1/recovery/recipient/rotations/{rotation_id}/provision`
- `POST /api/v1/recovery/recipient/rotations/{rotation_id}/prepare`
- `POST /api/v1/recovery/recipient/rotations/{rotation_id}/confirm`
- `POST /api/v1/recovery/recipient/rotations/{rotation_id}/abandon`

The signed source binding always includes account, device, Vault, recovery
record, wrapper digest, and rotation IDs. Provision adds the successor record ID
and ERC commitment; prepare and confirm also bind the successor wrapper digest.
Domains are `aeterna.recipient-recovery.<operation>.v1`. The service never accepts
a password, ERC, VDK, or Vault content. The claim website directs the contact to
native recovery and does not generate a desktop JSON handoff.

Recipient entry links have no 24-hour entry deadline while the exact source
grant is eligible, or the same contact must resume an exact completed rotation
receipt. Recipient OTPs still expire after ten minutes and are purpose-bound so
legacy claim verification cannot consume them.

The legacy `POST /api/v1/recovery/claim/start`,
`POST /api/v1/recovery/claim/verify`, and
`POST /api/v1/recovery/{recovery_id}/release-secret` routes are deprecated,
error-only tombstones. Valid requests return HTTP 400
`recovery.claim_unavailable` with `Cache-Control: no-store`, without reading
recovery state, calling KMS, sending mail or consuming grants. Previously issued
`recovery.srs.read` tokens cannot be redeemed or promoted to recipient authority.
Original email entry links remain usable through the native recipient flow when
their exact grant or confirmation receipt is eligible. Existing claimed grants
are not automatically reopened. See
[signed SRS retrieval and legacy retirement](../architecture/adr/0008-signed-srs-retrieval-and-legacy-retirement.md).

Successor SRS responses use `Cache-Control: no-store`. The encrypted server
envelope and prepared digest survive mailbox-token expiry and long offline
local work. Exact re-verification by the same contact permits redelivery or
confirmation of the same stage. Confirmation retires only the source record and
its grants. It does not rearm account protection, advance the account policy
epoch, or change the account-wide ERC commitment. See
[recipient rotation and custody](../architecture/adr/0006-recipient-vault-rotation-and-custody.md).

`POST /api/v1/recovery/custody/verify` verifies a supplied ERC commitment for the
current Owner-managed, `ACTIVE`, sealed local binding. It uses domain
`aeterna.recovery-custody.verify.v1`, requires the registered device signature,
and returns only `{verified: true}`. It changes no account state and does not
receive or return the ERC itself.
