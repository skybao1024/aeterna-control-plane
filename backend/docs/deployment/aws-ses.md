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
   Use the temporary capture and explicit operator workflow below. The callback
   never follows a confirmation link or calls `ConfirmSubscription` itself.
8. Ensure the service can retrieve the region-bound SNS signing certificate
   over HTTPS. The callback rejects redirects, unexpected hosts, topics, and
   signature versions.
9. Exercise sandbox and production-readiness matrices for acceptance, delivery,
   hard/soft bounce, complaint, rejection, duplicate callback, reordered
   callback, provider outage, and deletion races before enabling the flag.

## SNS subscription setup before production access

SES sandbox testing and SNS subscription setup do not require production
sending to be enabled. Deploy the callback code through the normal immutable
release flow and configure the following public controls in the server's
private runtime configuration without displaying or copying credential values:

```text
AETERNA_EMAIL_PROVIDER=aws-ses
AETERNA_EMAIL_PRODUCTION_ENABLED=false
AWS_SES_REGION=<SES_REGION>
AWS_SES_FROM_ADDRESS=<VERIFIED_SENDER>
AWS_SES_CONFIGURATION_SET=<CONFIGURATION_SET>
AWS_SES_SNS_TOPIC_ARN=<EXACT_TOPIC_ARN>
AWS_SES_SNS_CONFIRMATION_CAPTURE_ENABLED=true
```

Recreate the backend container through the release flow to apply configuration.
Restarting an existing container alone does not reload its environment. Leave
SNS raw message delivery disabled, leave subscription filters empty, and use
SignatureVersion 2 on the topic. Only a signed `SubscriptionConfirmation` for
the exact configured topic is staged. The Redis cache expires after 15 minutes;
the token and confirmation URL are never returned or logged. The callback has
no SNS administrative SDK client and cannot confirm or unsubscribe itself.

The authenticated operator needs `sns:Subscribe`, `sns:ConfirmSubscription`,
`sns:ListSubscriptionsByTopic`, and `sns:GetSubscriptionAttributes`. Use the
[temporary setup policy example](aws-sns-setup-policy.example.json), adjusting
its exact topic ARN and endpoint for the deployment. Add it as a separate
temporary policy; preserve the workload's SES and KMS policies. Receiving
ordinary signed SNS callbacks does not require these IAM permissions.

From the active release directory, using its complete production Compose
configuration and the backend service, run:

```sh
docker compose exec -T backend python -m scripts.manage_sns_subscription \
  request-confirmation --endpoint https://api.example.com/api/internal/v1/email-events/aws-sns
docker compose exec -T backend python -m scripts.manage_sns_subscription \
  status --endpoint https://api.example.com/api/internal/v1/email-events/aws-sns
docker compose exec -T backend python -m scripts.manage_sns_subscription \
  confirm --endpoint https://api.example.com/api/internal/v1/email-events/aws-sns
```

Use `--profile <OPERATOR_PROFILE>` when a distinct operator profile is mounted.
The default uses the standard SDK credential chain. Wait for
`signed_confirmation_cached: true` before confirming; request a fresh message
if the 15-minute window expires. The explicit confirm operation signs the AWS
request with `AuthenticateOnUnsubscribe=true`, verifies the resulting topic,
HTTPS endpoint, authentication status, and raw-delivery setting, then deletes
the cached token. A `confirmed` result is independent of SES production access.

Send one approved sandbox test to a verified recipient with the configured
configuration set. Immediately register its SES message ID with the operator
script's `expect-event --message-id <SES_MESSAGE_ID>` command, using the same
`--endpoint` argument. Only this explicitly registered message may bypass the
business Outbox lookup while temporary capture is enabled; unknown messages
retain the normal rejection behavior. Registration expires after 15 minutes
and never creates a business delivery record. A callback that arrives before
registration remains retryable, allowing the subsequent SNS retry to succeed.
The `status` command exposes short-lived, verified Send and
Delivery receipt metadata so the operator can compare the SES message ID;
recipient addresses, mail content, and full provider payloads are excluded.
An SDK test message may have no application Outbox row, so this evidence does
not imply an application business event was delivered.

After verification, run `clear --message-id <SES_MESSAGE_ID>`, set
`AWS_SES_SNS_CONFIRMATION_CAPTURE_ENABLED=false`, apply the public configuration
through the release flow, and remove the temporary setup policy. Receipt
metadata expires after 15 minutes. Ordinary signed callbacks continue to work;
business outbound sending remains governed by its separate launch gate.

## Evidence semantics

SES acceptance, delivery, bounce, and complaint are transport evidence only.
They do not prove that a human read a message and never set I11 Owner-warning
proof. Complaints and permanent bounces create keyed recipient suppression.
Provider payload addresses and rendered messages are not written to Outbox or
audit records.
