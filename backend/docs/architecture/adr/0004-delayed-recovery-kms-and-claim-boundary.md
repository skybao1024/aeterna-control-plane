# ADR 0004: Delayed recovery KMS and claim boundary

- Status: Accepted
- Date: 2026-09-27
- Scope: I13 encrypted SRS records, release grants, contact claims, and alerts
- Governing decision: public Aeterna ADR 0014
- Production AWS activity: Not authorized by this implementation change

## Context

The desktop Vault needs one independent 256-bit Server Release Secret per
device recovery record. The service must hold that factor until the existing
account policy is irreversibly `RELEASED`, without storing Vault content, the
Emergency Recovery Code, the Vault Data Key, a master password, or plaintext
SRS. A database disclosure alone must not reveal SRS, and neither contact
delivery state nor possession of an unverified address may create recovery
authority.

The Owner approved one cost-controlled AWS KMS customer-managed symmetric
single-Region key in `ap-southeast-1`, and approved AWS SES as the channel for
the time-limited recovery link and separate OTP. Live AWS requests, resources,
deployment, and production enablement remain separate launch actions.

## Decision

1. Provisioning calls `GenerateDataKey` with `AES_256` and the exact version 1
   non-secret encryption context. PostgreSQL stores only the returned KMS
   ciphertext, exact key ARN/material identifier, context and crypto versions,
   and record bindings. The one plaintext SRS is returned once and cleared from
   the mutable application buffer.
2. A signed active device creates a pending record, installs the local recovery
   wrapper, then signs its exact digest to seal the record. A missing
   provisioning response is not replayed; the client abandons or waits for
   expiry and provisions a new SRS. Expired unconfirmed records are deleted by
   scheduled cleanup and opportunistically before reprovisioning.
3. The release worker locks the account and policy, requires authoritative
   `RELEASED`, and creates one independent grant per sealed record and accepted,
   verified, non-deleted Recovery Contact. Grant, 24-hour link verifier, redacted
   audit, and email Outbox authorization commit together.
4. Claim links are 32-byte bearer values carried only in a URL fragment. The
   database stores only SHA-256 digests. Expired valid links may trigger a
   replacement to the same verified mailbox, limited to three in a rolling 24
   hours and at least 60 seconds apart.
5. A live link creates a 10-minute eight-digit email OTP challenge with five
   attempts. Calling start before 60 seconds reuses the challenge; calling it
   after 60 seconds invalidates the old challenge and sends a new code.
   Successful verification consumes link and challenge and creates a
   digest-only five-minute token scoped to `recovery.srs.read`.
6. Secret release locks and rechecks account, policy, recovery record, contact
   grant, and claim token. It validates device, Vault, wrapper, contact, scope,
   and expiry bindings before KMS `Decrypt`. Only successful decrypt plus
   transaction commit consume token and grant and authorize Owner and
   other-contact security notices.
7. Recovery responses use `Cache-Control: no-store`. Logs, audit, fixtures,
   errors, and persisted email records contain no SRS, ERC, claim bearer, OTP,
   rendered body, or complete address.
8. The code has distinct provision and claim provider dependencies so a later
   production deployment can use `GenerateDataKey`-only and `Decrypt`-only
   workload roles. The current disabled local application is not evidence that
   those production IAM roles have been provisioned or tested.
9. The personal-project MVP has no Multi-Region KMS replica, CloudHSM/custom key
   store, automatic Region failover, automatic rotation, recovery-specific
   cross-Region backup, or plaintext application fallback.

## Consequences

- PostgreSQL disclosure does not reveal SRS plaintext. Compromise of both the
  application authorization path and KMS permission remains a critical threat.
- A selected-Region outage delays provisioning and recovery. Permanent loss or
  deletion of the only usable key makes the affected SRS unrecoverable.
- SES is allowed to receive the verified contact address, one link bearer, and
  one OTP as necessary notification content. It never receives ERC, Vault
  content, VDK, SRS, or master-password material.
- Each accepted contact has independent one-time authority. One successful
  contact claim does not consume another contact's grant.
- I14 owns Owner self-recovery and factor rotation. I15 owns production AWS
  provisioning, role separation, monitoring, retention, backup and outage
  drills, and live launch authorization.

## Alternatives rejected

Multi-Region KMS, CloudHSM/custom key stores, a shared PII/SRS key,
application-generated SRS, plaintext retry storage, pre-release decrypt,
query-string bearers, JWT claim tokens, global consumption after one contact,
and live AWS acceptance inside I13 are rejected by public ADR 0014.
