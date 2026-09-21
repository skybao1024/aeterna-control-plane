# Secret Handling and AI Isolation

Runtime environment files and credential-bearing configuration are confidential.
Never read, display, search, quote, summarize, or commit them. Use only the root
`.env.example` for configuration shape.

## Prohibited data

Do not place any of the following in source, logs, tests, issues, API examples,
or AI conversations:

- Passwords, tokens, cookies, private keys, provider credentials, or real
  connection strings.
- Master passwords, emergency recovery codes, vault data keys, server release
  secrets, or decrypted recovery material.
- Vault content, messages, media, attachments, or full contact details.

## Diagnostics

- Prefer presence checks, type checks, redacted identifiers, and provider error
  codes.
- Never print Compose-resolved configuration or process environments.
- Use synthetic addresses and content in tests.
- Treat logs, traces, task payloads, dead-letter queues, and audit metadata as
  potential disclosure channels.
- Revoke and rotate a credential immediately if exposure is suspected.

Production SRS and sensitive PII handling requires reviewed envelope encryption
with KMS/HSM separation. Application database access alone must not provide
plaintext access.
