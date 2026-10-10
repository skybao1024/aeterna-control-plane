# Aeterna Control Plane Documentation

This directory contains backend-specific documentation. The desktop repository
remains authoritative for product behavior, cryptography, recovery UX, and the
public client protocol.

## Architecture

- [Project architecture](./architecture/project-architecture.md)
- [Docker deployment](./architecture/docker-deployment.md)
- [ADR 0001: Account-policy transaction and outage semantics](./architecture/adr/0001-account-policy-transaction-and-outage-semantics.md)
- [ADR 0002: Warning, grace, and transactional Outbox state machine](./architecture/adr/0002-warning-grace-outbox-state-machine.md)
- [ADR 0003: Contact consent and email delivery boundary](./architecture/adr/0003-contact-consent-and-email-delivery-boundary.md)
- [ADR 0004: Delayed recovery KMS and claim boundary](./architecture/adr/0004-delayed-recovery-kms-and-claim-boundary.md)
- [ADR 0005: Production identity KMS envelope](./architecture/adr/0005-production-identity-kms-envelope.md)
- [ADR 0006: Recipient Vault rotation and local custody](./architecture/adr/0006-recipient-vault-rotation-and-custody.md)
- [ADR 0007: Custody freshness and recipient management](./architecture/adr/0007-custody-freshness-and-recipient-management.md)
- [ADR 0008: Signed SRS retrieval and legacy retirement](./architecture/adr/0008-signed-srs-retrieval-and-legacy-retirement.md)

## API

- [OpenAPI and Swagger](./api/swagger-guide.md)

## Deployment

- [AWS SES unified application email boundary, sandbox controls, and operator checks](./deployment/aws-ses.md)
- [Temporary SNS subscription setup policy](./deployment/aws-sns-setup-policy.example.json)
- [AWS KMS delayed-recovery boundary](./deployment/aws-kms-recovery.md)
- [AWS KMS production identity setup](./deployment/aws-kms-identity.md)

## Development

- [Development workflow](./development/development-framework.md)
- [Read-only PostgreSQL MCP](./development/postgresql-mcp.md)
- [I03 concurrency prototype results](./development/i03-concurrency-prototype-results.md)
- [I11 warning/grace state machine results](./development/i11-state-machine-results.md)
- [I12 contacts and email notification results](./development/i12-notification-results.md)
- [I13 delayed recovery implementation results](./development/i13-delayed-recovery-results.md)
- [I14 Owner recovery and rotation results](./development/i14-owner-recovery-rotation-results.md)
- [M05 recovery completion and live acceptance](./development/m05-recovery-completion-results.md)
- [UX01 Owner configuration and safe message editing](./development/ux01-owner-configuration-results.md)

## Security

- [Secret handling and AI isolation](./security/ai-security-isolation.md)
- [I12 email provider policy review](./security/i12-email-provider-policy-review.md)

Documents from the original template are not architectural authority. If a
document conflicts with the root `AGENTS.md`, `ARCHITECTURE.md`, or the desktop
design, follow the root guidance and update the stale document.
