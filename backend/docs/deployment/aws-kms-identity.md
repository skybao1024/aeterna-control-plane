# AWS KMS production identity setup

This guide runs from the repository root using Docker Compose. Python commands
run inside the backend image at `/app`; no host Python environment is needed.
All AWS commands below are operator-run launch actions. Do not send credentials,
private keys, application keys, or AWS profile contents to support or an AI chat.

## Resources and permissions

Create a customer-managed **symmetric**, **Encrypt and decrypt**, **KMS origin**,
**Single-Region** key. The suggested alias is
`alias/aeterna-prod-identity-v1`; runtime always pins its full immutable key ARN.
Use `ap-southeast-1` unless a different identity Region has been deliberately
selected. Separate identity and recovery keys are the default; an explicitly
selected shared-key trial is supported as described below.

Keep the KMS key policy's default account/IAM delegation statement. Create two
dedicated IAM identities and attach the corresponding policies below, replacing
`<IDENTITY_KEY_ARN>` with the complete key ARN. Do not select unrelated AWS
service roles as key users or give the application KMS administration/delete
permissions. These IAM policies rely on the default account delegation; a
restricted custom key policy must explicitly allow the chosen identities.

Runtime policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DecryptProductionIdentityKeys",
    "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": "<IDENTITY_KEY_ARN>",
    "Condition": {
      "StringEquals": {
        "kms:EncryptionContext:aeterna-purpose": [
          "identity-pii", "identity-lookup", "identity-otp"
        ],
        "kms:EncryptionContext:aeterna-environment": "production",
        "kms:EncryptionContext:aeterna-context-version": "1",
        "kms:EncryptionContext:aeterna-key-version": "1"
      },
      "ForAllValues:StringEquals": {
        "kms:EncryptionContextKeys": [
          "aeterna-purpose", "aeterna-environment",
          "aeterna-context-version", "aeterna-key-version"
        ]
      }
    }
  }]
}
```

Provisioning policy: use the same resource and conditions, changing `Sid` to
`InitializeProductionIdentityKeys` and `Action` to
`kms:GenerateDataKeyWithoutPlaintext`. It does not need `kms:Decrypt`. Remove
the provisioning permission after the first successful initialization. A check
uses the runtime identity. Preview needs its own key, envelope, IAM identities,
and policies with environment `preview`; do not share production envelopes.

## AWS credentials on the server

Prefer temporary credentials. On EC2, use a suitably scoped instance role and
the standard SDK provider chain, making IMDS available to the intended Docker
containers. Do not include `docker-compose.aws.yml` on EC2 unless deliberately
using profiles. On other clouds, use IAM Roles Anywhere or another supported
temporary-credential mechanism. A `credential_process` profile needs its helper
executable and certificate material available inside the container; the optional
overlay only mounts the profile directory, not an executable outside it.

If temporary federation is not yet available, a dedicated least-privilege IAM
user can supply a shared-credentials profile as a temporary deployment option.
Create its access key for an application outside AWS and enter it locally with
the AWS CLI. Do not create root access keys, write credential values to runtime
environment files, or use the administrator identity for normal application
operation. Rotate/revoke this bootstrap mechanism when federation is ready.

Use separate external directories and profiles:

- `/etc/aeterna/aws-runtime`, profile `aeterna-runtime`: decrypt-only identity.
- `/etc/aeterna/aws-identity-provisioner`, profile
  `aeterna-identity-provisioner`: initialize-only identity.

The directories must already exist and be readable only by the operator and
the container's `app` user. Verify the image's numeric user ID before assigning
ownership. The current Dockerfiles create `app` as UID 1000; do not assume that
an unrelated custom image uses the same UID. A root-owned `0600` profile is not
readable by `app`. The overlay mounts the chosen directory read-only at
`/home/app/.aws`; keep it outside the repository and build context. Do not place
both identities' credential files in the runtime directory.

An operator with AWS CLI installed can privately populate each shared profile:

```bash
sudo install -d -m 700 /etc/aeterna/aws-runtime /etc/aeterna/aws-identity-provisioner
AWS_SHARED_CREDENTIALS_FILE=/etc/aeterna/aws-runtime/credentials \
AWS_CONFIG_FILE=/etc/aeterna/aws-runtime/config \
aws configure --profile aeterna-runtime
```

Repeat for the provisioning directory/profile using that identity's credentials.
The CLI prompts are private local input; never paste the values into chat. If
using temporary shared credentials, include the session token privately and
provide a renewal mechanism; `aws configure` alone does not renew them.

After configuring files as an operator, set their ownership and permissions
privately. For the current images with `app` UID/GID 1000:

```bash
sudo chown -R 1000:1000 /etc/aeterna/aws-runtime /etc/aeterna/aws-identity-provisioner
sudo chmod 700 /etc/aeterna/aws-runtime /etc/aeterna/aws-identity-provisioner
sudo chmod 600 /etc/aeterna/aws-runtime/config /etc/aeterna/aws-runtime/credentials
sudo chmod 600 /etc/aeterna/aws-identity-provisioner/config \
  /etc/aeterna/aws-identity-provisioner/credentials
```

Use these file commands only for shared-credentials profiles; certificate/helper
setups need their own least-privilege ownership and executable permissions. Do
not print files to verify them; check numeric ownership and mode only.

## Configure the application

Privately set these non-credential controls in the ignored runtime configuration:

```text
AETERNA_IDENTITY_KEY_PROVIDER=aws-kms
AETERNA_IDENTITY_KMS_ENABLED=true
AETERNA_IDENTITY_KMS_REGION=ap-southeast-1
AETERNA_IDENTITY_KMS_KEY_ARN=arn:aws:kms:ap-southeast-1:<ACCOUNT_ID>:key/<KEY_ID>
AETERNA_IDENTITY_KMS_ENVELOPE_PATH=/app/identity-keys/envelope.json
AETERNA_PII_KEY_V1=
AETERNA_LOOKUP_KEY_V1=
AETERNA_OTP_KEY_V1=
AWS_CONFIG_DIRECTORY=/etc/aeterna/aws-runtime
AETERNA_AWS_PROFILE=aeterna-runtime
```

The three plaintext identity fields must be empty in production and preview.
Keep recovery KMS and email enablement controls at their current disabled values
until those independent launch requirements have been completed. Preserve the
same `COMPOSE_PROJECT_NAME`; it selects the durable identity volume.

### Shared-key trial

To reuse the existing identity KMS key without creating another billed key, set:

```text
AETERNA_KMS_ALLOW_SHARED_KEY=true
AETERNA_RECOVERY_KMS_KEY_ARN=<EXISTING_IDENTITY_KEY_ARN>
```

Both ARNs must name the same immutable single-Region key in `ap-southeast-1`.
This opt-in changes configuration validation only. It does not regenerate the
three identity data keys, rewrite their envelope, or enable recovery or email.
Never run initialization again against an existing database.

The identity runtime/provisioning policies above remain scoped to their three
identity purposes. Recovery permissions must use `recovery-srs` and the distinct
record-binding context described in [the recovery guide](./aws-kms-recovery.md).
Do not broaden application permissions to unrestricted `kms:Decrypt` or `kms:*`.
The existing key policy may delegate to the separately scoped IAM policies;
shared use does not require granting every principal access to both purposes.

For the managed CI/CD host, these public controls can be set in the root-owned
`/etc/aeterna/deployment.conf`; the release wrapper exports them into the
production Compose services. Install the updated `deployment/ssh-release.sh`
before the first shared-key release. Runtime credentials stay in their external
profiles. For an operator-run Compose deployment, supply the same controls
through the process environment or private runtime configuration.

For an operator-run check that explicitly supplies the same recovery ARN, add
`--recovery-key-arn '<EXISTING_IDENTITY_KEY_ARN>' --allow-shared-key --check` to
the initializer command. A check only decrypts the existing envelope. Without
`--check`, the CLI continues to refuse an existing output before calling AWS.

One shared key has one key-level disable/delete boundary for both identity and
recovery data. A future move to separate keys requires reviewing existing
ciphertext and rewrap requirements; changing an ARN alone is not a migration.

## Initialize exactly once

Only use this procedure for a new production identity database. It does not
convert existing development accounts or rotate keys for existing records.
After initializing, back up the `identity-keys` volume and do not delete or
recreate it. Replacing it with new keys makes previous identity data unusable.

On a non-EC2 host with external SDK profiles, run:

```bash
AWS_CONFIG_DIRECTORY=/etc/aeterna/aws-identity-provisioner \
AETERNA_AWS_PROFILE=aeterna-identity-provisioner \
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f docker-compose.aws.yml --profile identity-setup \
  run --rm --build identity-setup \
  --region ap-southeast-1 \
  --key-arn 'arn:aws:kms:ap-southeast-1:<ACCOUNT_ID>:key/<KEY_ID>' \
  --environment production
```

The setup image does not start the API or depend on PostgreSQL/Redis. It creates
only three KMS-wrapped ciphertext entries, never receiving plaintext keys.
The script refuses any existing output before asking KMS to generate keys. It
stores `envelope.json` with mode `0600` using atomic no-replace publication.
For EC2, omit the AWS profile overlay and environment prefixes and use a
separately authorized provisioning identity for this one-time job.

## Check and start

Run this credential-backed check yourself and share only its sanitized status:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f docker-compose.aws.yml --profile identity-setup \
  run --rm identity-setup \
  --region ap-southeast-1 \
  --key-arn 'arn:aws:kms:ap-southeast-1:<ACCOUNT_ID>:key/<KEY_ID>' \
  --environment production --check
```

This uses the runtime profile and calls only `Decrypt`; it prints no keys,
ciphertext, ARN, credential values, or provider exception details. Success is
`Identity KMS check succeeded.` A failure exits nonzero with a generic
status; inspect AWS permission/Region/key state locally using sanitized
diagnostics. It does not certify the rest of the production application.

After that check succeeds, start through repository orchestration:

```bash
AETERNA_USE_AWS_PROFILES=1 ./deploy.sh prod
```

Use the same prefix for subsequent repository commands on a profile-backed
deployment. On EC2 with its instance role, use `./deploy.sh prod` without the
profile overlay. The backend, Celery worker, and beat share the identity envelope
read-only and the intended runtime credential chain. Normal runtime never
generates replacement keys.

## Outages, backup, and versioning

Startup fails closed if the envelope, configuration, AWS credentials, or KMS
decrypt authority is unavailable. Complete successful keysets are cached for
the process lifetime; API startup loads them before serving traffic, so normal
requests do not perform blocking KMS calls. Already running processes can keep
using their loaded keys during a KMS outage. Credential/KMS revocation does not
erase plaintext already in memory; stop/restart every affected service to
invalidate its cache. Failed loads have no plaintext fallback and are not cached.

Back up the ciphertext envelope together with the matching database; record its
key ARN, Region, and environment. Never use `docker compose down -v` for a live
deployment. KMS key deletion is irreversible for affected application data once
the waiting period ends. This implementation supports application key version 1
only; migration from plaintext development keys or application-key rotation is
separate work and must not use the initializer.

## References

- [KMS data keys](https://docs.aws.amazon.com/kms/latest/developerguide/data-keys.html)
- [GenerateDataKeyWithoutPlaintext API](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html)
- [Encryption context and policy conditions](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)
- [Boto3 credential-provider chain](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html)
- [IAM for non-AWS workloads](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_non-aws.html)
- [ADR 0005](../architecture/adr/0005-production-identity-kms-envelope.md)
