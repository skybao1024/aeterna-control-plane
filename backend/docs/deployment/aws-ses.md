# AWS SES application email boundary

AWS SES v2 is the shared provider for every application email in production
and preview. Sending is disabled by default. This document describes
configuration and operator checks; it does not authorize deployment, runtime
configuration changes, cloud provisioning, or a live send.

## Application entry points

All paths resolve the provider through `get_aeterna_email_adapter()`. Business
authorization and template rendering stay in their existing services.

| Email | Application path | Send authorization |
| --- | --- | --- |
| Owner mailbox challenge and device-binding security notice | `EmailAeternaAccountNotifier` -> `EmailService` -> shared adapter | Existing account/device verification and abuse checks |
| Registration, verification resend, and password reset in the retained generic auth service | `ClientAuthService` -> `EmailService` -> shared adapter | Existing auth-service checks; legacy client auth routes remain unregistered |
| Contact invitations and confirmed-contact tests | Notification service -> email Outbox -> `AeternaEmailDeliveryService` -> shared adapter | Existing consent, verification, suppression, and deletion checks |
| Owner/contact reminders, warnings, release notices, recovery links, and claim OTPs | Policy/recovery service -> email Outbox -> `AeternaEmailDeliveryService` -> shared adapter | Existing policy/recovery gates and durable Outbox send authorization |

`EmailService` is a rendering and delivery-result facade. It has no separate
FastMail or synchronous SMTP fallback. The unused Brevo sender is removed.
The desktop protocol, email copy and templates, challenge lifetimes, consent,
recovery conditions, and public failure responses are unchanged by this
transport unification.

## Runtime boundary

- Production and preview outbound mail use the SES v2 `SendEmail`
  simple-content operation when the project gate and configuration are valid.
  A disabled or unavailable provider fails closed for every entry point.
- Only explicit `ENV=development` selects the existing local SMTP sink adapter.
  Its allowed hosts are `localhost`, `127.0.0.1`, `::1`, `mailpit`, and
  `mailhog`. An unknown environment cannot select SMTP or SES. Production
  `MAIL_*` values cannot select a second delivery path.
- AWS credentials come only from the standard AWS SDK credential provider
  chain. Prefer a workload IAM role; do not add access keys to repository or
  Vite configuration.
- If AWS client construction fails, provider resolution returns an unavailable
  adapter and the send boundary reports `aws-ses-configuration-error` without
  exposing the credential-chain exception. Owner challenge failure status and
  best-effort security-notice handling retain their existing behavior.
- Services retain their fixed templates and bounded, escaped content. The
  adapter fixes the sender, configuration set, and event tag format, and
  accepts one recipient per envelope. It exposes no raw-message, attachment,
  or arbitrary header API.
- Boto3 uses `Config(retries={"total_max_attempts": 1, "mode": "standard"})`:
  one initial request and zero SDK retries. Unlike `max_attempts` in a Config
  object, `total_max_attempts` includes the initial request. See the
  [Boto3 retry configuration guide](https://docs.aws.amazon.com/boto3/latest/guide/retries.html).
- SES has no cross-request idempotency token for `SendEmail`. Neither the
  rendering facade nor Outbox dispatcher automatically repeats an ambiguous
  send or switches transports after failure. Outbox authorization still commits
  `sending` before the external effect; uncertainty remains for reconciliation.
- Stable Outbox event keys and opaque immediate-send correlation keys are
  SHA-256 hashed into an SES email tag for correlation only; the tag does not
  provide provider deduplication.
- Immediate facade sends carry the adapter-owned
  `aeterna-delivery=immediate` tag. Outbox envelopes retain durable tracking by
  default; callers cannot supply arbitrary SES tags through the facade.
  Configure the configuration set's SNS event destination so callbacks include
  custom tags in `mail.tags` arrays. Identity-level feedback notifications do
  not publish those tags; do not route them to this business SNS topic.
  Untagged unknown messages retain rejection behavior. See the
  [AWS SNS event-publishing examples](https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-sns-examples.html).
- Delivery logs and persisted provider errors contain redacted classifications,
  never recipient addresses, rendered messages, OTPs, tokens, or raw provider
  exceptions.

## Required configuration

After separate authorization to activate application sending, prepare these
public controls in private runtime configuration. Use the actual approved
environment (`production` or `preview`) and replace every placeholder:

```text
ENV=production
AETERNA_EMAIL_PROVIDER=aws-ses
AETERNA_EMAIL_PRODUCTION_ENABLED=true
AWS_SES_REGION=<APPROVED_REGION>
AWS_SES_FROM_ADDRESS=<VERIFIED_SENDER>
AWS_SES_CONFIGURATION_SET=<CONFIGURATION_SET>
AWS_SES_SNS_TOPIC_ARN=<EXACT_TOPIC_ARN>
```

Production and preview reject an enabled but partial or invalid configuration
at startup. The SNS topic Region must equal `AWS_SES_REGION`. Leave
`AETERNA_EMAIL_PRODUCTION_ENABLED=false` while preparing or reviewing settings.
No static AWS credential variable is part of the application configuration
contract. Apply authorized configuration through the normal release flow;
restarting an existing container alone does not reload its environment.

Development Compose keeps `ENV=development`, points `MAIL_HOST` at `mailpit`,
and uses port `1025` with `MAIL_ENCRYPTION=none`. All application email uses
that same controlled sink for local testing; SMTP credentials and remote SMTP
hosts are not a production alternative.

## SES sandbox and the project gate

AWS `ProductionAccessEnabled` and project
`AETERNA_EMAIL_PRODUCTION_ENABLED` describe different conditions. SES sandbox
status is per Region. A sandbox account can send to real addresses or domains
verified in the sending Region, and to the SES mailbox simulator. Its default
limits are 200 messages per 24 hours and one message per second. A pending
production-access request therefore does not mean SES cannot send. Moving out
of the sandbox permits unverified recipients; sender identities still require
verification. See
[AWS SES sandbox restrictions](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html).

Application sends through SES still require the project enable flag and all
configuration above, including for an approved sandbox test. AWS production
access does not enable that flag, establish application consent, or authorize
a deployment or live send. The application does not automatically inspect AWS
account sandbox status or bypass the gate for verified recipients.

On 2026-10-09, the owner confirmed that SES production access is approved and
authorized committing and deploying the shared-mail repair and enabling
application sending. The existing deployment uses `ap-southeast-1`, the sender
`no-reply@aeternarelay.com`, configuration set `aeterna-transactional`, and the
confirmed HTTPS subscription on `aeterna-ses-events`. Earlier bounded tests
verified signed Send and Delivery callbacks for the same SES message ID.
The pre-release server check still found the previous backend and the project
send gate disabled. The workload cannot call `GetAccount` under its current
least-privilege policy; approval status is owner-reported, and runtime read
permissions do not need to be expanded to send mail. Deployment, enablement,
and live verification remain separate operations from this recorded approval.

## Read-only operator checks before activation

After authorizing credential-backed diagnostics, an operator can use an
approved AWS CLI session for these read-only checks. Replace placeholders
locally and share only the selected flags, quotas, and verification results;
do not display runtime environment files, credential files, or SDK debug logs.

```sh
aws sesv2 get-account --region <APPROVED_REGION> \
  --query '{ProductionAccessEnabled:ProductionAccessEnabled,SendingEnabled:SendingEnabled,EnforcementStatus:EnforcementStatus,SendQuota:SendQuota}'
aws sesv2 get-email-identity --region <APPROVED_REGION> \
  --email-identity <VERIFIED_SENDER_IDENTITY> \
  --query '{VerificationStatus:VerificationStatus,VerifiedForSendingStatus:VerifiedForSendingStatus}'
aws sesv2 get-email-identity --region <APPROVED_REGION> \
  --email-identity <VERIFIED_TEST_RECIPIENT_IDENTITY> \
  --query '{VerificationStatus:VerificationStatus,VerifiedForSendingStatus:VerifiedForSendingStatus}'
aws sesv2 get-configuration-set --region <APPROVED_REGION> \
  --configuration-set-name <CONFIGURATION_SET> \
  --query '{SendingEnabled:SendingOptions.SendingEnabled}'
```

The selected fields follow the AWS CLI references for
[GetAccount](https://docs.aws.amazon.com/cli/latest/reference/sesv2/get-account.html),
[GetEmailIdentity](https://docs.aws.amazon.com/cli/latest/reference/sesv2/get-email-identity.html),
and [GetConfigurationSet](https://docs.aws.amazon.com/cli/latest/reference/sesv2/get-configuration-set.html).

The recipient check is required while in the sandbox; a verified recipient
domain may be used as the identity. Confirm locally that API, worker, and beat
use the same reviewed provider controls and workload credential chain, that the
sender/configuration-set/topic Regions align, and that the exact SNS topic has
the expected events and confirmed HTTPS subscription. The existing
`manage_sns_subscription status` command below provides bounded subscription
status. These checks do not send mail or prove application delivery. An actual
send and callback acceptance matrix requires separate authorization.

## AWS provisioning checklist

1. Approve the sender entity, SES Region, operating regions, recipient
   jurisdictions, and private-mode availability.
2. Verify the sender domain or address and configure DKIM, SPF, and DMARC.
3. Confirm AWS sandbox status and current quotas in the selected Region.
   Obtain production access before sending to unverified recipients; verified
   sandbox recipients can be used for separately approved internal testing.
   Retain the exact invitation and notification use-case review.
4. Grant the workload role only the required SES v2 send permission and scope it
   to the approved identity and configuration set where AWS supports that scope.
5. Create the configuration set and publish Send, Delivery, Bounce, Complaint,
   Reject, and Rendering Failure through its SNS event destination to the exact
   topic. Keep identity-level feedback notifications off that topic so custom
   delivery tags remain available. Open and Click tracking are unnecessary and
   ignored by Aeterna.
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

SNS callback capture can be prepared while the project sending flag is false;
it does not enable application mail. AWS sandbox status does not prevent this
subscription setup. After separate authorization, deploy the callback code
through the normal immutable release flow and configure the following public
controls in private runtime configuration without displaying credential values:

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

After separate live-send authorization, send one approved sandbox test to a
verified recipient with the configured configuration set. An operator SDK test
is outside application delivery; an application-originating test requires the
project sending flag. Immediately register its SES message ID with the operator
script's `expect-event --message-id <SES_MESSAGE_ID>` command, using the same
`--endpoint` argument. For operator SDK tests without the fixed immediate
marker, only this explicitly registered message may bypass the business Outbox
lookup; unknown unmarked messages retain the normal rejection behavior.
Registration expires after 15 minutes
and never creates a business delivery record. A callback that arrives before
registration remains retryable, allowing the subsequent SNS retry to succeed.
The `status` command exposes short-lived, verified Send and
Delivery receipt metadata so the operator can compare the SES message ID;
recipient addresses, mail content, and full provider payloads are excluded.
An SDK test message may have no application Outbox row, so this evidence does
not imply an application business event was delivered.
Use an operator SDK test or an Outbox-backed application test for this receipt
matrix; immediate facade callbacks are acknowledged without receipt state.

After verification, run `clear --message-id <SES_MESSAGE_ID>`, set
`AWS_SES_SNS_CONFIRMATION_CAPTURE_ENABLED=false`, apply the public configuration
through the release flow, and remove the temporary setup policy. Receipt
metadata expires after 15 minutes. Ordinary signed callbacks continue to work;
business outbound sending remains governed by its separate launch gate.

## Evidence semantics

SES acceptance, delivery, bounce, and complaint are transport evidence only.
They do not prove that a human read a message and never set I11 Owner-warning
proof. Outbox complaints and permanent bounces create keyed recipient
suppression.
Provider payload addresses and rendered messages are not written to Outbox or
audit records.

Immediate account/auth facade sends do not create an I12 email Outbox row.
Their provider acceptance is the existing immediate delivery result; it is not
mailbox delivery or human-read proof. In production and preview, the callback
first verifies the existing SNS signature and exact-topic boundary. It then
acknowledges only the exact `aeterna-delivery=immediate` marker without changing
business state or adding immediate-mail delivery or bounce-suppression records.
This prevents SNS retries for the deliberately untracked facade path. Missing,
unknown, or other marker values retain the original Outbox lookup and rejection
behavior; unknown message IDs are not generally ignored. Temporary explicitly
registered operator tests retain the bounded capture workflow above and do not
create business delivery records.
