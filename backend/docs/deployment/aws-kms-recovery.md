# AWS KMS delayed-recovery boundary

The service supports one AWS KMS customer-managed, symmetric, single-Region key
in `ap-southeast-1`. Recovery provisioning and recovery claims run with distinct
AWS identities. This document describes the application and host contract; it
does not create a key, IAM identity, access key, alarm, or other AWS resource.

## Fail-closed configuration

The safe default is:

```text
AETERNA_RECOVERY_KEY_PROVIDER=disabled
AETERNA_RECOVERY_KMS_ENABLED=false
AETERNA_RECOVERY_KMS_REGION=ap-southeast-1
AETERNA_RECOVERY_KMS_KEY_ARN=
AETERNA_RECOVERY_PROVISIONER_SOCKET=/app/recovery-provisioner/provisioner.sock
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
AETERNA_RECOVERY_PROVISIONER_SOCKET=/app/recovery-provisioner/provisioner.sock
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
`kms:GenerateDataKey`, and add
`"kms:EncryptionAlgorithm": "SYMMETRIC_DEFAULT"` under `StringEquals`.
Do not use `"kms:KeySpec": "AES_256"`: the `kms:KeySpec` condition describes
the KMS key resource, whose value for this symmetric encryption key is
`SYMMETRIC_DEFAULT`; it does not describe the requested data-key length. If a
`kms:KeySpec` defense-in-depth condition is retained, its value must be
`SYMMETRIC_DEFAULT`. The application itself sends `KeySpec=AES_256` to
`GenerateDataKey` and rejects a response that is not exactly 32 bytes. Do not
add these provision-only conditions to the decrypt policy.
Keep identity policies scoped to their three `identity-*` purposes, and keep
recovery policies scoped to `recovery-srs`, even when their resource ARN matches.
The key policy must permit the selected IAM principals or account delegation;
these identity-based policies do not override an explicit key-policy denial.

The production topology is fixed as follows:

- `backend` uses the runtime AWS profile. It can call `kms:Decrypt` for the
  exact `recovery-srs` context but has no `kms:GenerateDataKey` permission.
- `recovery-provisioner` is a separate, minimal container using the provisioner
  AWS profile. It can call only `kms:GenerateDataKey` for the exact
  `recovery-srs` context and has no `kms:Decrypt` permission.
- The provisioner listens only on a Unix domain socket in a named Docker volume.
  It publishes no TCP port, receives no database, Redis, JWT, email, or identity
  envelope configuration, mounts only its own read-only AWS profile, and uses a
  dedicated egress network instead of the application network.
- The backend mounts the socket volume read-only. It never mounts the
  provisioner AWS profile. Other application containers mount neither.

The two IAM identities may use the same KMS key for the shared-key trial, but
they must not share credentials. A single profile or a single application
process with both KMS actions does not satisfy this boundary. The managed
release rejects a provisioner profile name or directory that is the same as the
runtime profile name or directory.

## Non-EC2 host credential layout

Keep the two AWS profiles outside the repository and outside runtime environment
files. The release deployment expects these host directories:

```text
/etc/aeterna/aws-runtime/
  config
  credentials
/etc/aeterna/aws-recovery-provisioner/
  config
  credentials
```

The provisioner profile name is `aeterna-recovery-provisioner`. Its `config`
file contains only public SDK settings:

```ini
[profile aeterna-recovery-provisioner]
region = ap-southeast-1
output = json
```

Its `credentials` file has this shape. Replace the placeholders only on the
server; never paste their values into chat, source control, logs, or a runtime
environment file:

```ini
[aeterna-recovery-provisioner]
aws_access_key_id = <ACCESS_KEY_ID>
aws_secret_access_key = <SECRET>
```

Create the directory and both files through a root-controlled operation, assign
them to numeric UID/GID `1000:1000` (the production container application user),
then set directory mode `0700` and file mode `0600`. No other host identity
should be able to traverse or read that directory. Rotate a credential if it is
ever disclosed. Prefer an instance role or another short-lived credential
provider when the deployment platform supports it.

The root-owned `/etc/aeterna/deployment.conf` contains only these public
controls for the shared-key production topology:

```text
AETERNA_KMS_ALLOW_SHARED_KEY=true
AETERNA_RECOVERY_KEY_PROVIDER=aws-kms
AETERNA_RECOVERY_KMS_ENABLED=true
AETERNA_RECOVERY_KMS_REGION=ap-southeast-1
AETERNA_RECOVERY_KMS_KEY_ARN=arn:aws:kms:ap-southeast-1:<ACCOUNT_ID>:key/<KEY_ID>
AETERNA_RECOVERY_PROVISIONER_SOCKET=/app/recovery-provisioner/provisioner.sock
AETERNA_RECOVERY_PROVISION_AWS_CONFIG_DIRECTORY=/etc/aeterna/aws-recovery-provisioner
AETERNA_RECOVERY_PROVISION_AWS_PROFILE=aeterna-recovery-provisioner
```

The current default KMS key policy statement that delegates key use to this AWS
account is sufficient when both IAM identities are in the same account and
their scoped identity policies are attached. Do not add either application
identity as a key administrator. Do not grant `kms:*`, `kms:DisableKey`,
`kms:ScheduleKeyDeletion`, or `kms:PutKeyPolicy` to either application identity.
An explicit deny in any applicable policy still takes precedence and must be
resolved separately.

## Activation sequence

1. Deploy this code while recovery remains disabled. This creates the separate
   workload definition without starting it.
2. Create the provision-only IAM access key and store it only in the external
   provisioner profile above. Never copy it into the runtime profile.
3. Add the public controls to `/etc/aeterna/deployment.conf` and run the normal
   immutable release. The release automatically enables Compose profile
   `recovery-kms`, validates the external profile files, waits for the
   provisioner health check, and then checks the socket from `backend`.
4. Confirm `recovery_provisioner_healthy` and the sanitized configuration status
   `recovery_configured_not_probed`. Neither result performs a KMS operation.
5. Run a separately authorized synthetic enrollment and claim acceptance test.
   Keep production recovery unavailable to users until both GenerateDataKey and
   Decrypt have succeeded through their respective workloads.

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

Production launch still requires CloudTrail and alarms, deletion safeguards,
backup/restore and outage drills, live KMS and SES acceptance, retention, and a
reviewed rollback plan. Until that gate passes, keep both recovery KMS and
production email switches disabled.

## Sanitized configuration diagnosis

The operator-only `scripts/diagnose_recovery_configuration.py` checks the
active backend container's named recovery environment controls and packaged
Pydantic schemas. It does not open `.env` files, import application settings,
call AWS or the database, inspect personal responses, or change configuration.
It suppresses other logging during execution and prints one JSON object with
fixed status labels, booleans and schema counts. No credential, ARN, mailbox,
raw exception, identity envelope or recovery material is included.

All five recovery controls must be explicitly present in the process environment
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
| `recovery_configuration_invalid` | Provider, enablement, region, exact key ARN, or private socket path does not match the approved production configuration. Use the boolean checks to identify the mismatch without sharing its value. |
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
