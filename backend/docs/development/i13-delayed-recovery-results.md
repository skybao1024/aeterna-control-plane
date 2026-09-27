# I13 delayed recovery implementation results

- Date: 2026-09-27
- Baseline: `6c7d4ebb35d62ac4b0ce029ea718a5b7b0abcf82`
- Result: Accepted for the fail-closed engineering boundary
- ADR: [Delayed recovery KMS and claim boundary](../architecture/adr/0004-delayed-recovery-kms-and-claim-boundary.md)
- Public protocol: prepared v1.2.0 digest
  `456335ec6baf6f7161aa715263943427402ff675606fc68db79cb381572ed2e1`
- Production AWS activity: none

## Implemented behavior

The service now owns encrypted per-device SRS records, signed record
confirmation and abandonment, post-release per-contact grants, digest-only
claim links and claim tokens, keyed OTP verification, exact recovery bindings,
redacted recovery audit, and Owner/other-contact security notifications. Every
business mutation is in the service layer and uses PostgreSQL row locks and
transactional Outbox authorization.

The AWS KMS adapter uses `GenerateDataKey(AES_256)` and `Decrypt` with an exact
configured key ARN and exact versioned encryption context. It validates key
identity, plaintext size, and ciphertext bounds and converts provider details
to a fixed safe failure. Startup accepts either the fully disabled boundary or
the approved `ap-southeast-1` key configuration; partial and wrong-Region
configuration fails closed.

AWS SES rendering is late and authorized from durable Outbox rows. A recovery
link uses a URL fragment and a separate OTP email follows a valid start. No
rendered message, bearer, OTP, complete address, plaintext SRS, or provider
payload is persisted in recovery tables or audit.

## Verification evidence

The complete Dockerized suite passed 96 tests. The six real-PostgreSQL I13
tests cover pre-release and unverified-contact denial, provisioning replay,
expired-record deletion and reprovisioning, post-release claim and local-binding
data, single use, KMS rollback, concurrent single-winner release, late link/OTP
email rendering, OTP resend invalidation, and three-per-24-hour link replacement.

Migration `350391c65e38` passed `alembic current`, `alembic check`, downgrade to
`b1e89ccdb30a`, re-upgrade, and a second current/check. All 18 changed Python
files passed focused Black and Black-compatible isort. Repository critical
Flake8 and focused Bandit passed. The OpenAPI registry test covers all six I13
operations and the public protocol fixture digest.

## Deferred production acceptance

No test contacted KMS, SES, or another AWS endpoint, and no real email was sent.
The key, alias, workload roles, sender, Region, monitoring, and deployment have
not been provisioned. Production remains disabled and fail closed. See the
[AWS KMS recovery deployment boundary](../deployment/aws-kms-recovery.md) for
the I15 launch responsibilities.
