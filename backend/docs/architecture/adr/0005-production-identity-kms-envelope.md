# ADR 0005: Production identity KMS envelope

- Status: Implemented; live AWS acceptance and deployment remain operator actions
- Date: 2026-10-08
- Scope: Production/preview identity PII, lookup, and OTP/token application keys

## Context

The identity boundary needs three independent, stable 32-byte application keys.
PII uses AES-256-GCM; lookup and OTP/token derivation use HMAC-SHA256. Replacing
these keys would change persisted lookup values, strand encrypted PII, and
invalidate existing tokens. The development environment-key provider cannot be
used in production. The Owner requested AWS KMS integration after creating an
identity customer-managed single-Region symmetric key in Singapore.

## Decision

1. One customer-managed KMS key wraps the three independent application keys.
   Its immutable commercial-AWS single-Region UUID key ARN must match the
   configured Region. Separate identity and recovery keys remain the default.
   On 2026-10-08 the Owner requested a cost-controlled trial using the existing
   key for both purposes. `AETERNA_KMS_ALLOW_SHARED_KEY=true` explicitly permits
   the same recovery ARN; without that opt-in, reuse fails closed. Shared use
   retains the distinct application keys and exact purpose-specific contexts.
   Singapore is the deployment default. No aliases, Multi-Region keys, plaintext
   fallback, or custom KMS endpoints are accepted.
2. The setup role uses only `kms:GenerateDataKeyWithoutPlaintext`, with
   `KeySpec=AES_256`. Each ciphertext binds exactly its identity purpose,
   environment, context version, and key version. It never receives plaintext
   application keys. Context contains no personal data.
3. Initialization creates a version-1 JSON ciphertext envelope using atomic
   exclusive publication and mode `0600`. It refuses existing paths, including
   symlinks, before any KMS generation. It never overwrites an envelope. This is
   a first-install operation, not a rotation or migration command.
4. Backend and Celery containers mount the same durable `identity-keys` volume
   read-only. Only the opt-in setup container mounts it read-write. The image
   initializes that directory as owned by its non-root `app` user.
5. Runtime permissions allow only `kms:Decrypt` on the exact identity key and
   required contexts. The provider validates the entire envelope before KMS
   operations, then validates each returned ARN, algorithm, and key size. It
   accepts only a complete set of distinct keys; provider errors are sanitized.
6. Successful complete keysets are cached for the process lifetime. API startup
   loads them before serving traffic; requests do not perform blocking KMS
   refresh calls. Failures are not cached. Process identity and a post-fork reset
   prevent reuse of parent keys or locks in prefork workers. API shutdown clears
   cached references. Plaintext keys exist in application memory; Python does
   not guarantee memory erasure.
7. Startup requires KMS-backed keys in production and preview. All three
   plaintext environment-key fields must be empty there. Development/test
   behavior stays explicit: empty fields allow startup, partial keys fail.
8. AWS credentials use the normal SDK provider chain. An EC2 instance role can
   supply temporary credentials. On other hosts, an opt-in Compose overlay
   mounts an external SDK profile directory read-only. Provisioning and runtime
   use separate identities and separate profile directories.

## Consequences

- The public protocol, AES-GCM nonce/AAD, HMAC derivations, API responses, and
  database schema do not change. No frontend change or migration is required.
- Database access alone cannot unwrap identity keys. Compromise of both the
  application and its KMS authority remains a threat.
- KMS revocation or outage prevents new processes from loading identity keys.
  Already running processes retain their loaded keys until shutdown/restart.
  Stop/restart every affected process for revocation to invalidate its cache;
  disabling KMS authority alone does not revoke plaintext already in memory.
  There is no plaintext fallback when loading fails.
- The envelope must be backed up alongside its database. Deleting its volume,
  regenerating version-1 data keys, or deleting the KMS key makes existing
  identity data unusable. The initializer cannot identify an unrelated existing
  database; operators must not initialize a replacement against existing data.
- Only application key version 1 is supported. Moving an existing development
  database or rotating application keys requires a separately designed migration;
  creating a new envelope does not migrate data.
- Recovery SRS role separation, production email acceptance, TLS, monitoring,
  and other launch requirements remain independent. This implementation does
  not enable them or create IAM/KMS resources.
- Shared-key trials require purpose-scoped IAM policies for identity and
  recovery operations. A shared key couples key-level administration, disablement,
  and deletion across both data categories. Independent application data keys
  and ciphertext formats are preserved; opt-in does not regenerate the existing
  identity envelope. Moving existing recovery ciphertext to a separate key later
  requires a reviewed rewrap/migration rather than changing its configured ARN.
