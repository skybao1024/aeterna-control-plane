# I12 contacts and email notification results

- Date: 2026-09-27
- Baseline: `7ecb2a1752c718b6f667f978fe3433ccd2f73902`
- Repository: `aeterna-control-plane`
- Result: Accepted for the fail-closed engineering boundary
- ADR: [Contact consent and email delivery boundary](../architecture/adr/0003-contact-consent-and-email-delivery-boundary.md)
- Production email: Disabled; live AWS SES sending was explicitly deferred

## Implemented boundary

I12 implements both disclosure modes, encrypted contact and template fields,
neutral invitation consent, explicit mailbox acceptance, confirmed-contact test
delivery, I11 notification materialization, delivery state, abuse limits,
suppression, deletion, and redacted audit. A private-until-release target queues
no email before the authoritative policy reaches `RELEASED`; its first allowed
email is the same fixed neutral invitation used by confirm-now.

The selected production adapter is AWS SES v2. It uses simple content, a fixed
sender and configuration set, the standard AWS credential provider chain, and
one SDK attempt. SES has no cross-request send idempotency token, so an unknown
outcome is terminally `ambiguous` and is not automatically replayed. Production
startup remains fail closed until the explicit enable flag and complete approved
Region, sender, configuration set, and exact SNS topic are present.

## Consent, privacy, and delivery evidence

- Contact addresses and bounded Owner/contact text are encrypted with
  purpose-bound AES-256-GCM authenticated data. Only keyed lookups are used for
  uniqueness, abuse evidence, and suppression.
- Invitations store only a verifier and key version. Accepting a live token
  changes the target to `ACCEPTED` and records mailbox verification; declining
  deletes the target, destroys its recoverable ciphertext, revokes pending
  invitations, cancels unsent mail, and creates keyed suppression.
- The email Outbox and audit contain no plaintext address, rendered body,
  invitation token, provider payload, or provider message identifier in audit.
- Authenticated SNS events distinguish provider acceptance, delivery, bounce,
  complaint, and rejection. Open and click events are ignored. No transport
  state can set I11 Owner-warning proof or claim that a human read a message.
- Permanent bounces and complaints create keyed recipient suppression.

## AWS callback boundary

The hidden `POST /api/internal/v1/email-events/aws-sns` endpoint accepts only a
bounded SNS `Notification` from the exact configured topic. It requires
SignatureVersion 2, validates a Region-bound AWS certificate URL, refuses
redirects, verifies RSA/SHA-256 over the canonical envelope, rejects duplicate
JSON members, and persists only minimal redacted transport evidence. Concurrent
replays serialize through the account lock and recheck callback identity before
insert, so the same notification remains idempotent under a race.

Subscription confirmation is intentionally outside the application boundary;
the service does not follow callback-provided URLs.

## Verification evidence

The focused I12 matrix passed 21 tests. It covers confirm-now and
private-until-release behavior, signature authorization, encrypted fields,
neutral pre-verification content, HTML escaping, token acceptance and decline,
deletion, abuse limits, retry policy, concurrent sends, concurrent duplicate
callbacks, reordered callbacks, bounce visibility, complaint suppression,
redacted persistence, I11 materialization and cancellation, SES request shape
and failure classification, and locally generated RSA/X.509 SNS signatures.

The complete Dockerized backend suite passed 86 tests. Migration
`b1e89ccdb30a` passed `alembic current`, `alembic check`, downgrade to
`6b8f7d4a91c2`, re-upgrade, and a second current/check. Client OpenAPI contains
all seven I12 operations, while the SNS callback is hidden and POST-only. The
live Celery worker registered scan, I11-to-I12 materialization, and I12 dispatch.
`pip check`, focused Black and Black-compatible isort, focused and
repository-wide critical Flake8, and focused Bandit checks passed.

The repository's raw global Black check still identifies eight untouched legacy
files, and raw isort lacks the Black profile used by the codebase. Those
pre-existing tooling findings were not changed by I12; every changed Python
file passes the compatible focused checks.

## Deferred production acceptance

No test contacted AWS or sent real email, as requested. Before production
enablement, operations must approve the sender entity, SES Region, recipient
jurisdictions, lawful-basis and transparency analysis, exact use case, retention
and deletion path, and then run the documented sandbox and production-readiness
send/callback matrix. These are launch gates, not incomplete runtime behavior:
until they are satisfied, production sending remains disabled and fail closed.

I13 recovery claims, OTP, ERC/SRS/VDK handling, recovery-secret delivery, and
post-release retrieval remain outside I12.

## M04 interface integration (2026-09-30)

The desktop now signs I12 contact and template operations with its bound device.
The public frontend serves `/contact-invitation` without the Owner route guard,
reads the token from a URL fragment, removes that fragment from browser history,
and submits accept or decline without an Owner session. Because the I12
response is deliberately generic for invalid and replayed tokens, the page
does not claim that a recipient was verified solely from `processed: true`;
the signed Owner status remains authoritative. The isolated native, browser,
Mailpit, and synthetic bounce journey is documented in the client repository's
M04 result note.
