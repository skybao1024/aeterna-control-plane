# ADR 0010: Post-release computer notice

- Status: Accepted for the user-requested computer notice implementation
- Date: 2026-10-12
- Product authority: Desktop ADR 0031 and `docs/DESIGN.md`
- Related decisions: ADRs 0002, 0003, 0004, 0007 and 0008

## Context

A designated contact may not know about Aeterna Relay or check email regularly.
After a terminal inactivity release, a relative opening the Owner's computer
needs a clear local notice and a path to the existing mailbox recovery flow.
The user explicitly approved full contact email addresses on the released
notice page, including while the local library is locked. This approval does
not disclose contact details before release or grant recovery authority.

Existing contact status gives the last email transport state for any event;
it cannot establish whether a release email was sent. Ordinary Owner account
configuration is a broader unlocked read and cannot serve this locked notice.
The released policy and its exact email events already exist durably, so this
feature needs no database migration or new dependency.

## Decision

Add `POST /api/v1/recovery/notice/read` under the distinct signed domain
`aeterna.recovery-notice.read.v1`, operation `recovery_notice.read`. Closed
requests sign account, authorizing device, request ID and at most ten unique
known contact IDs, using the existing RFC 8785/Ed25519 protocol. The bound
device's pinned signature is verified before taking account or device locks.
Reads serialize with account mutations and never update device eligibility,
heartbeat sequencing, accepted activity, policy timing, consent or recovery
state.

An active device may obtain current policy state. A dormant device may obtain
only a `RELEASED` notice, without regaining any ordinary activity or recovery
authority. Missing, pending, lost and revoked identities remain denied. The
response's explicit null fields represent unavailable policy timing; a released
notice requires an exact epoch, last accepted policy activity and release time.

Only a current nonretired `RELEASED` policy may disclose contact emails. Supplied
IDs must identify contacts owned by that account. The read does not enumerate
unknown contacts. Deleted contacts are omitted because deletion already
destroys their encrypted mailbox. It returns no Owner-authored message,
password, ERC, SRS, claim link, OTP, bearer, content or provider message ID.

Derive recipients from exact durable release evidence:

- Private invitations must reference a policy Outbox event for this exact
  policy with `owner-release-authorized` and `to_state=RELEASED`.
- Recovery-entry emails must reference a claim link whose grant and recovery
  record match this account, contact, current policy epoch and current recovery
  generation. Test emails, setup invitations, OTPs and historical cycles are
  excluded.

Return at most one record per requested contact. Prefer recovery-entry mail over
a prior invitation. Aggregate evidence across that contact's exact release
events: any delivered event yields `delivered`; otherwise accepted transport
yields `submitted`; otherwise queued, sending or retrying yields `pending`;
all failed, bounced, complained or cancelled yields `failed`; ambiguous evidence
yields `unknown`. These values do not establish readership or completed local
recovery. The response uses `Cache-Control: no-store`.

## Risks and verification

### Explicit resend

The user requested an immediate resend when the original contact email cannot be
found. Add `POST /api/v1/recovery/notice/resend`, signed under
`aeterna.recovery-notice.resend.v1`, operation `recovery_notice.resend`. This
explicit action is limited to an existing undeleted, unsuppressed account-owned
target after exact current `RELEASED` evidence. The same pinned active/dormant
device proof applies. It cannot accept a replacement address, add a recipient,
override contact consent, retrieve a recovery factor or reactivate activity.

An accepted verified contact receives one fresh entry on an already available
grant whose sealed record matches the authorizing device and current policy
epoch/recovery generation. Missing matching material fails rather than falling
back to a different computer or reviving a claimed/revoked grant. Use the
existing recovery-link construction and mailbox resumption semantics. Existing
entry links, grant states and recovery privileges remain unchanged; stored link
age does not introduce a new recovery action deadline.

An unaccepted private target receives only fixed neutral invitation text. Reuse
a still-valid invitation for this release cycle; otherwise use the existing
invitation helper to create a current invitation. Never disclose custom Owner
instructions or a recovery entry before consent and mailbox verification.

Authenticate first, then serialize the account, device and contact. Commit the
fresh mail intent, invitation/link where needed, redacted budget evidence and
exact signed-request receipt together. Operation/request-ID uniqueness plus a
digest bound to contact and device returns the same receipt for exact retries,
while changed reuse conflicts. No provider call runs inside this API transaction.
The existing Outbox dispatcher retains its retry/ambiguity rules. Return only
account/device/contact IDs, server time, mail kind, pending state and a 60-second
retry interval. Links, tokens, emails and recovery factors never enter the
response or idempotency receipt.

Reuse the existing 30 account actions/day and five recipient actions/day email
budgets. Add ten resends/device/day using redacted durable receipt fields, and
a 60-second cooldown for that target across devices. Exact retries do not consume
another budget or queue another message. This needs no new dependency or schema
migration. Test concurrent exact retries, changed replay, competing intents,
cooldowns, all three daily budgets, signature/contact/policy/device rejection,
transaction interruption, private consent separation and unchanged old links.

Full emails are an intentional post-release disclosure on the Owner's computer.
Clients must keep them transient and must not put them in notification text,
logs, telemetry, browser storage or local notice journals. OS notification
delivery still depends on the app running and authorized system notifications.
The desktop must not infer death or physical absence from a missing activity
heartbeat, and opening this read-only notice must not reset inactivity.

Verify signature and cross-account rejection, request bounds, absence of contact
details before release, exact policy/generation mail filtering, invitation and
release separation, transport states, duplicate device mail aggregation,
dormant released-only access without reactivation, terminal-device denial,
explicit null response validation and no-store transport. Use only synthetic
accounts in the local Docker development database; do not send production mail,
deploy or migrate production as part of this implementation.
