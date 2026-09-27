# AWS SES production email boundary

AWS SES is the selected I12 provider integration. It is present in code but is
disabled by default. This document is an operations checklist, not permission
to enable production delivery.

## Runtime boundary

- Outbound mail uses the SES v2 `SendEmail` simple-content operation.
- AWS credentials come only from the standard AWS SDK credential provider
  chain. Prefer a workload IAM role; do not add access keys to repository or
  Vite configuration.
- The adapter fixes sender, recipient, subject, text, HTML, configuration set,
  and event tag fields. It exposes no raw-message, attachment, or arbitrary
  header API.
- Boto3 retries are limited to one total attempt. SES has no cross-request
  idempotency token for `SendEmail`, so an ambiguous result is never replayed.
- The stable Aeterna event key is SHA-256 hashed into an SES email tag for
  correlation only; the tag does not provide provider deduplication.

## Required configuration

Set these only after the launch review is approved:

```text
AETERNA_EMAIL_PROVIDER=aws-ses
AETERNA_EMAIL_PRODUCTION_ENABLED=true
AWS_SES_REGION=<APPROVED_REGION>
AWS_SES_FROM_ADDRESS=<VERIFIED_SENDER>
AWS_SES_CONFIGURATION_SET=<CONFIGURATION_SET>
AWS_SES_SNS_TOPIC_ARN=<EXACT_TOPIC_ARN>
```

The application rejects partial production configuration at startup. The SNS
topic Region must equal `AWS_SES_REGION`. No static AWS credential variable is
part of the application configuration contract.

## AWS provisioning checklist

1. Approve the sender entity, SES Region, operating regions, recipient
   jurisdictions, and private-mode availability.
2. Verify the sender domain or address and configure DKIM, SPF, and DMARC.
3. Obtain SES production access and written acceptance of the exact invitation
   and notification use case.
4. Grant the workload role only the required SES v2 send permission and scope it
   to the approved identity and configuration set where AWS supports that scope.
5. Create the configuration set and publish Send, Delivery, Bounce, Complaint,
   Reject, and Rendering Failure events to the exact SNS topic. Open and Click
   tracking are unnecessary and ignored by Aeterna.
6. Configure SNS SignatureVersion 2 and subscribe the HTTPS endpoint:
   `POST /api/internal/v1/email-events/aws-sns`.
7. Confirm the SNS subscription out of band with an authenticated AWS operator.
   The application deliberately rejects automatic subscription-confirmation
   links.
8. Ensure the service can retrieve the region-bound SNS signing certificate
   over HTTPS. The callback rejects redirects, unexpected hosts, topics, and
   signature versions.
9. Exercise sandbox and production-readiness matrices for acceptance, delivery,
   hard/soft bounce, complaint, rejection, duplicate callback, reordered
   callback, provider outage, and deletion races before enabling the flag.

## Evidence semantics

SES acceptance, delivery, bounce, and complaint are transport evidence only.
They do not prove that a human read a message and never set I11 Owner-warning
proof. Complaints and permanent bounces create keyed recipient suppression.
Provider payload addresses and rendered messages are not written to Outbox or
audit records.
