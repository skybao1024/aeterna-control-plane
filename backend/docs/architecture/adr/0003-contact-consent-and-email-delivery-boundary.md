# ADR 0003: Contact consent and email delivery boundary

- Status: Accepted
- Date: 2026-09-27
- Scope: I12 contacts, consent, encrypted notification fields, and email delivery
- Governing decision: public Aeterna ADR 0010
- Provider integration: AWS SES selected on 2026-09-27
- Launch approval: Not granted; production delivery remains fail closed

The status and launch statement above record the original I12 decision.
The 2026-10-09 implementation clarification below describes the later unified
application transport without granting deployment or live-send approval.

## Context

I11 commits provider-neutral notification intent with policy state but does not
own contact consent, recipient data, rendering, provider effects, or delivery
evidence. I12 must support confirm-now and private-until-release without turning
an unverified mailbox into recovery authority, leaking private content in a
first message, retrying an ambiguous external effect, or treating transport as
proof that a human read a warning.

AWS SES has been selected for the production adapter, but no operating-region
set, sender identity, processor agreement, jurisdictional assessment, or live
send acceptance has been approved. The existing SMTP and Brevo code does not
constitute a production path.

## Decision

1. A Notification Target and a Recovery Contact are one persisted type with a
   closed consent state. Only `ACCEPTED` plus non-null `verified_at`, with no
   deletion marker, is a Recovery Contact. Acceptance proves mailbox control
   through a short-lived invitation secret and does not create an account or
   password.
2. Confirm-now queues a neutral invitation during setup. Private-until-release
   stores only the encrypted target and cannot queue an invitation until the
   authoritative account policy is `RELEASED`. The first private email is the
   same fixed neutral invitation. Neither flow can include custom text, trigger
   details, recovery instructions, a claim, a credential, SRS, or an attachment
   before acceptance and verification.
3. Contact addresses and bounded Owner/contact text use the existing
   AES-256-GCM PII boundary with purpose- and record-bound authenticated data.
   Production continues to require the approved KMS/HSM implementation and has
   no environment-key fallback. Invitation secrets are deterministically
   derived under the secret key for the invitation ID; PostgreSQL stores only a
   verifier and key version.
4. Every Owner mutation is an operation-specific RFC 8785/Ed25519 signed
   request from an active, non-dormant bound device. Account, recipient, and IP
   abuse evidence uses keyed lookups, never plaintext addresses. Public token
   responses are generic to resist enumeration.
5. The I12 email Outbox stores routing references, event type, a stable
   idempotency key, attempts, transport state, and redacted error codes. It does
   not store recipient plaintext or rendered content. The redacted audit stores
   no email address, body, token, provider message ID, or secret.
6. Send authorization first changes one event to `sending` and commits. A crash
   after that point leaves an ambiguous record for reconciliation instead of
   automatically repeating the external effect. An adapter may automatically
   retry a known pre-acceptance failure only when it guarantees the same stable
   idempotency key. Concurrent workers serialize in account, contact, email
   event, then attempt lock order.
7. Transport states are `queued`, `sending`, `retry_pending`,
   `provider_accepted`, `delivered`, `bounced`, `complained`, `ambiguous`,
   `failed`, and `cancelled`. Authenticated callbacks are idempotent and monotonic under
   duplicates and reordering. An open pixel, click, or other observation is not
   accepted as a human-read state. No transport callback sets I11 Owner warning
   proof.
8. The constrained adapter owns sender headers and forbids caller-controlled
   headers, attachments, and arbitrary HTML. Plaintext bodies are rendered from
   fixed copy plus escaped, 4,096-byte bounded text only after the authorization
   gate. Development SMTP accepts only local sink host names and never
   auto-retries ambiguity.
9. The AWS SES v2 adapter uses the standard IAM credential provider chain,
   simple content only, a fixed configuration set, and a hashed event tag. SES
   `SendEmail` has no cross-request idempotency token, so SDK retries are
   disabled and the adapter does not automatically repeat a failed or ambiguous
   call.
10. SES events arrive through an exact-topic SNS boundary requiring
    SignatureVersion 2, a region-bound Amazon certificate URL, and RSA/SHA-256
    signature verification. Send, delivery, bounce, complaint, and rejection
    are transport evidence. Open and click events are ignored.
11. Production remains unavailable unless the explicit enable flag and complete
    Region, sender identity, configuration set, and SNS topic configuration are
    present. Enabling the flag still requires an approved operating and
    recipient jurisdiction set and completion of the deferred live-send
    acceptance.

## Security and privacy consequences

- A private target receives no pre-release setup, resend, or test email.
- Decline creates a keyed suppression and wipes the recoverable contact
  ciphertext. Owner deletion revokes pending tokens, cancels unsent email, and
  also makes the stored ciphertext undecryptable.
- A dispatch already serialized as `sending` may complete after a concurrent
  deletion; the lock winner is the durable authorization boundary. Queued and
  retry-pending work is cancelled when deletion wins first.
- Provider acceptance, mailbox delivery, and bounce are visible separately;
  none claims that a person read or understood the email.
- I13 claim, OTP, SRS, and recovery-secret delivery remain absent.

## Alternatives rejected

### Treat provider acceptance as warning proof

Rejected because it proves only that a provider accepted a transport request.

### Retry SMTP after an unknown outcome

Rejected because SMTP has no cross-process idempotency contract. Retrying can
duplicate a security-sensitive message.

### Persist rendered email for retry

Rejected because it would duplicate recipient and custom plaintext outside the
field-encryption boundary.

### Enable a candidate provider before region review

Rejected because a package, configuration field, or existing account does not
approve a new third-party personal-data recipient or an unsolicited-message
policy interpretation.

## Implementation clarification (2026-10-09)

All application mail now resolves through the same constrained provider factory.
Owner mailbox challenges and device-binding security notices retain
`EmailAeternaAccountNotifier` and `EmailService` for their existing rendering
and immediate result contract. Retained generic registration, verification
resend, and password-reset service calls use that facade too; their legacy
client routes remain unregistered. Contact invitations/tests, policy reminders,
warnings/releases, recovery links, and claim OTPs continue through the durable
email Outbox and `AeternaEmailDeliveryService`, using the same adapter.
Later recovery behavior remains governed by ADR 0004; the historical I12 scope
above is unchanged.

Production and preview require `AETERNA_EMAIL_PRODUCTION_ENABLED=true`,
`AETERNA_EMAIL_PROVIDER=aws-ses`, and complete validated SES Region, sender,
configuration-set, and SNS topic controls. Only explicit development selects
the local SMTP sink adapter; unknown environments fail closed. The independent
FastMail/synchronous SMTP fallback and unused Brevo sending module are removed.
Existing templates, lifetimes, consent/recovery conditions, failure semantics,
redaction, and desktop protocol remain unchanged.

The SES SDK still makes one total attempt. An ambiguous outcome cannot trigger
a fallback or automatic replay; durable Outbox authorization and reconciliation
remain authoritative. Immediate facade sends preserve their existing failure
contract and do not become Outbox events or warning proof.

Immediate facade envelopes use an internal delivery-tracking flag and receive
the adapter-owned `aeterna-delivery=immediate` SES tag. Production and preview
callbacks authenticate the existing signature and exact topic before
acknowledging that exact marker without business-state changes. Missing or
unknown markers retain the original Outbox lookup and rejection behavior;
this does not add immediate-mail delivery tracking or bounce suppression.
AWS client-construction failures reach the send boundary as the redacted
`aws-ses-configuration-error`, preserving challenge failure status and
best-effort security notices.

AWS `ProductionAccessEnabled` is independent of the project enable flag.
A pending AWS production-access request still permits sandbox delivery to
identities verified in the sending Region within its quotas. Reported identity
verification does not establish complete application configuration or authorize
enablement. The local MVP transport repair authorizes code, local verification,
and documentation only. See the
[SES configuration and sandbox guide](../../deployment/aws-ses.md) for the
placeholder controls, bounded operator checks, and separately authorized live
acceptance workflow.
