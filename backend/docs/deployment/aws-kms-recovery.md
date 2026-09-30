# AWS KMS delayed-recovery boundary

I13 includes a disabled production adapter for one AWS KMS customer-managed,
symmetric, single-Region key in `ap-southeast-1`. This document describes the
configuration contract; it does not provision a key, role, alias, alarm, or
AWS account resource.

## Fail-closed configuration

The safe default is:

```text
AETERNA_RECOVERY_KEY_PROVIDER=disabled
AETERNA_RECOVERY_KMS_ENABLED=false
AETERNA_RECOVERY_KMS_REGION=ap-southeast-1
AETERNA_RECOVERY_KMS_KEY_ARN=
```

For an isolated development service, `AETERNA_RECOVERY_KEY_PROVIDER=local-test`
uses an injected `AETERNA_RECOVERY_LOCAL_TEST_KEY`. The key must be a canonical
unpadded base64url encoding of 32 synthetic bytes and must remain stable across
service restarts while its test records are needed. This adapter is rejected in
`preview` and `production`, and it cannot be combined with
`AETERNA_RECOVERY_KMS_ENABLED=true`. Keep the populated key in an uncommitted
runtime environment file; never put it in the repository or a response.

Production enablement requires all of the following values together:

```text
AETERNA_RECOVERY_KEY_PROVIDER=aws-kms
AETERNA_RECOVERY_KMS_ENABLED=true
AETERNA_RECOVERY_KMS_REGION=ap-southeast-1
AETERNA_RECOVERY_KMS_KEY_ARN=arn:aws:kms:ap-southeast-1:<ACCOUNT_ID>:key/<KEY_ID>
```

Do not place AWS access keys in environment files. The adapter uses the normal
AWS SDK credential-provider chain. The planned human-readable alias is
`alias/aeterna-prod-recovery-srs-v1`, but runtime configuration pins the
immutable key ARN rather than trusting an alias target.

## Required production separation

Provisioning needs only `kms:GenerateDataKey` with `KeySpec=AES_256`. Claims
need only `kms:Decrypt`. Both permissions must be limited to the exact key and
the four required encryption-context entries: purpose, environment, context
version, and opaque binding digest. Rewrap and key administration are separate
operational roles and are not application permissions.

The repository exposes distinct provider dependencies for provision and claim
work. I15 must choose and verify a deployment topology that actually gives
those workloads separate IAM roles before enabling production; a single local
process does not satisfy that requirement.

## Cost and resilience scope

The MVP intentionally pays for one customer-managed single-Region key plus API
requests. It does not create a Multi-Region replica, CloudHSM/custom key store,
automatic failover, automatic rotation, or a recovery-specific cross-Region
backup. Current AWS pricing must be checked at provisioning time because prices
are external and can change.

A Regional outage delays provisioning and claims. There is no application-key
or plaintext fallback. Scheduling deletion or permanently losing the sole key
makes affected SRS unrecoverable, so key deletion remains a separately approved
operational action.

## Launch checklist ownership

I15 owns actual resource creation, least-privilege key/IAM policies, CloudTrail
and alarms, deletion safeguards, backup/restore and outage drills, live KMS and
SES acceptance, retention, and the production rollback plan. Until that gate
passes, keep both recovery KMS and production email switches disabled.
