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

## Shared application transport repair (2026-10-09)

The existing SES v2 adapter and provider factory now serve every application
email entry point. `EmailService` retains template rendering and the immediate
account/auth delivery-result contract while delegating to that factory;
notifications and delayed-recovery email retain the existing durable Outbox.
The separate FastMail/synchronous SMTP fallback and unused Brevo sender are
removed. Production and preview require the project gate and complete SES
configuration, explicit development permits only the local sink, and unknown
environments fail closed. There is no fallback or automatic replay after an
ambiguous SES result.

Immediate facade messages receive an adapter-owned delivery marker so signed,
exact-topic SNS callbacks can be acknowledged without Outbox state changes.
Missing or unknown markers retain the original message lookup and rejection;
the repair does not add immediate-mail delivery tracking or bounce suppression.
AWS client-construction errors become redacted failures at the existing send
boundary, preserving challenge failure status and best-effort security notices.

This repair changes delivery transport only. It retains the desktop protocol,
fixed email copy/templates, challenge lifetimes, consent and recovery gates,
suppression and once-only send authorization, public error semantics, and
sensitive-data handling. The earlier verification counts above remain historical
I12 evidence; they are not results of this repair. No AWS resource, server
configuration, deployment, or live send is authorized by the local repair.
Current activation prerequisites and the distinction between AWS sandbox
status and the project gate are recorded in the
[SES guide](../deployment/aws-ses.md).

Verification for this repair ran inside the Docker backend service:

- The four focused unit modules `tests/unit/test_aeterna_verification_email.py`,
  `tests/unit/test_aeterna_aws_email.py`, `tests/unit/test_aeterna_notification.py`,
  and `tests/unit/test_aeterna_sns_subscription.py` passed 121 tests with three
  existing deprecation warnings.
- The three integration modules `tests/integration/test_aeterna_identity_protocol.py`,
  `tests/integration/test_aeterna_notification.py`, and
  `tests/integration/test_aeterna_recovery.py` passed 36 tests with two existing
  deprecation warnings. They used a temporary isolated PostgreSQL instance
  prepared through the existing migrations, leaving the ordinary development
  database untouched. The temporary test container was removed after the run.
- The integration matrix includes three SES-backed synthetic Outbox cases:
  read timeout and invalid acceptance remain terminally `ambiguous`, while
  throttling remains terminally `failed` because SES has no cross-request
  idempotency guarantee. Each verifies one provider call and no replay on
  another dispatch attempt. Provider clients were mocked; no AWS request or
  real email was sent.
- Focused `black --check`, `isort --check-only`, and critical Flake8 checks
  (`E9,F63,F7,F82`) passed on all 11 changed Python files. `git diff --check`
  also passed.

Frontend and native checks were unnecessary for this backend transport change:
HTTP contracts, email templates, frontend code, and desktop code are unchanged.
No frontend or native build was run.
