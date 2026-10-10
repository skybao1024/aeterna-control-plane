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

For the Owner-selected shared-key trial, set `AETERNA_KMS_ALLOW_SHARED_KEY=true`
and set `AETERNA_RECOVERY_KMS_KEY_ARN` to the existing identity key ARN. This
reuses the KMS wrapping key while preserving separate data keys and encryption
contexts. Production recovery remains disabled until its own permission and
delivery acceptance checks pass.

For a claim-only IAM identity, use this policy with the exact shared or dedicated
key ARN in `<RECOVERY_KEY_ARN>`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DecryptReleasedRecoveryFactors",
    "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": "<RECOVERY_KEY_ARN>",
    "Condition": {
      "StringEquals": {
        "kms:EncryptionContext:aeterna-purpose": "recovery-srs",
        "kms:EncryptionContext:aeterna-environment": "production",
        "kms:EncryptionContext:aeterna-context-version": "1"
      },
      "StringLike": {
        "kms:EncryptionContext:aeterna-binding": "???????????????????????????????????????????"
      },
      "ForAllValues:StringEquals": {
        "kms:EncryptionContextKeys": [
          "aeterna-purpose", "aeterna-environment",
          "aeterna-context-version", "aeterna-binding"
        ]
      }
    }
  }]
}
```

The binding pattern requires a 43-character value. The application reconstructs
the exact digest from the account/device/vault/recovery record before decrypting;
the IAM pattern alone does not validate that business binding or release state.
For the provision-only identity, use the same resource/context conditions,
change `Sid` to `GenerateRecoveryFactors`, change `Action` to
`kms:GenerateDataKey`, and add `"kms:KeySpec": "AES_256"` under
`StringEquals`. Do not add that KeySpec condition to the decrypt policy.
Keep identity policies scoped to their three `identity-*` purposes, and keep
recovery policies scoped to `recovery-srs`, even when their resource ARN matches.
The key policy must permit the selected IAM principals or account delegation;
these identity-based policies do not override an explicit key-policy denial.

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

## Sanitized configuration diagnosis

The operator-only `scripts/diagnose_recovery_configuration.py` checks the
active backend container's named recovery environment controls and packaged
Pydantic schemas. It does not open `.env` files, import application settings,
call AWS or the database, inspect personal responses, or change configuration.
It suppresses other logging during execution and prints one JSON object with
fixed status labels, booleans and schema counts. No credential, ARN, mailbox,
raw exception, identity envelope or recovery material is included.

All four recovery controls must be explicitly present in the process environment
before it classifies configuration. Compose `env_file` normally supplies them.
Missing values cannot establish effective application settings because the
application also supports `.env` fallback, which this diagnostic does not read.

From the repository root, use the existing active Compose configuration:

```bash
docker compose exec -T backend python -m scripts.diagnose_recovery_configuration
```

To diagnose a deployed image that predates this script, copy only the reviewed
script into a temporary container path and run it against that image's existing
environment and schemas. Replace `<BACKEND_CONTAINER>` with the current backend
container name; do not replace its environment or restart the application:

```bash
docker cp backend/scripts/diagnose_recovery_configuration.py <BACKEND_CONTAINER>:/tmp/aeterna-recovery-diagnostic.py
docker exec -w /app <BACKEND_CONTAINER> python /tmp/aeterna-recovery-diagnostic.py
```

| Status | Meaning and next step |
| --- | --- |
| `configuration_controls_not_supplied` | One or more process controls are absent. The script cannot inspect application file fallback; presence flags/count identify the missing controls without reading `.env`. Do not infer that recovery is disabled. |
| `recovery_provider_disabled` | Recovery generation is disabled in this container. Waiting or rebuilding the desktop cannot enable it; review the approved service setup with the operator. |
| `recovery_configuration_invalid` | Provider, enablement, region or exact key ARN does not match the approved production configuration. Use the boolean checks to identify the mismatch without sharing its value. |
| `recovery_configured_not_probed` | Configuration shape is valid. This does not establish AWS credentials, key state, IAM/key-policy permissions or KMS network availability. Continue with a separately authorized service acceptance check. |
| `diagnostic_unavailable` | The diagnostic could not inspect configuration or schemas safely. Share only this output and the installed image/revision metadata. |
| `invalid_arguments` | Invoke the script without arguments; it accepts no credentials, key values or AWS probe flags. |

Exit code 0 means configuration is shaped correctly, not recovery readiness;
code 1 reports missing controls, a disabled, invalid or unavailable result, and code 2 reports
invalid arguments. Schema flags describe declarations in this image, not live
route behavior or applied database migrations. A false `management_email_required`
flag indicates that this image lacks the desktop's current required configuration
field and needs a contract/version review. A false feature with fewer than three
available schema modules may also indicate an older image.

The existing `/api/v1/config/health` checks API, PostgreSQL and Redis only. A
healthy response does not establish recovery KMS readiness. Do not run
`docker compose config`, dump process environments or share raw production logs
for this diagnosis. Do not regenerate identity material, enable recovery, add
IAM permissions or deploy a release merely to make this check pass.
