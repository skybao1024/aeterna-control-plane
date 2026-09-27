# I12 email provider and jurisdiction policy review

- Review date: 2026-09-27
- Scope: first email to a previously unverified private Notification Target
- Provider decision: AWS SES selected for integration on 2026-09-27
- Result: no production Region or jurisdiction set approved
- Runtime consequence: production email delivery fails closed

This is an engineering launch gate, not legal advice. AWS SES is the selected
adapter, but Aeterna has not selected the sender entity, SES Region, operating
regions, or recipient jurisdictions. Live external sending was explicitly
deferred. The review therefore does not claim that a hypothetical worldwide
launch is lawful or accepted by AWS.

## Official sources reviewed

### Brevo

Brevo's official anti-spam guidance says solicitation must be expected and
requires recipient consent to be active, explicit, and specific. A previously
unverified private target has not given that consent to Aeterna. The current
evidence therefore does not approve Brevo for this first-message flow.

- [Brevo anti-spam policy guidance](https://help.brevo.com/hc/en-us/articles/209405205-What-is-the-anti-spam-policy-of-Brevo)

### Amazon SES — selected integration

AWS prohibits unsolicited mass email in its Acceptable Use Policy, scans SES
mail for unsolicited or harmful content, and may suspend sending for unwanted
mail, bounces, or complaints. Its sending-review guidance asks whether every
message was specifically requested and how addresses, opt-in, and opt-out are
handled. Aeterna's fixed one-to-one invitation is not a mass campaign, but these
sources do not affirmatively approve an unsolicited first contact. The adapter
and authenticated callback boundary may be implemented without sending mail,
but launch still requires a use-case review, abuse plan, Region selection, and
explicit approval.

- [AWS Acceptable Use Policy](https://aws.amazon.com/aup/)
- [AWS Service Terms, Amazon SES](https://aws.amazon.com/service-terms/)
- [Amazon SES sending review FAQs](https://docs.aws.amazon.com/ses/latest/dg/faqs-enforcement.html)

### United States

The FTC explains that CAN-SPAM's transactional or relationship categories are
narrow and generally depend on a transaction or relationship the recipient has
already agreed to. A private target has not agreed to an Aeterna relationship.
If a message is commercial, the full commercial-message rules may apply; if it
is neither commercial nor transactional, that classification still does not
resolve provider policy, state law, privacy, harassment, or abuse concerns.

- [FTC CAN-SPAM compliance guide](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business)

### European Union and United Kingdom

Article 13 of the ePrivacy Directive regulates unsolicited electronic mail for
direct marketing, with implementation varying by member state. UK ICO guidance
distinguishes factual, non-promotional service messages from direct marketing,
but also emphasizes purpose, expectations, transparency, and data-protection
basis. The neutral invitation is designed to contain no promotion, tracking, or
custom content, but no EU/UK lawful-basis or country implementation assessment
has been approved.

- [EU ePrivacy Directive 2002/58/EC](https://eur-lex.europa.eu/eli/dir/2002/58/oj)
- [UK ICO service-message and data-protection guidance](https://ico.org.uk/for-organisations/advice-for-small-organisations/direct-marketing-and-data-protection/marketing-and-data-protection-in-detail/)

## Required decision before production delivery

The remaining approver decision must name:

1. the sending entity and AWS SES Region;
2. the initial operating and recipient jurisdiction set;
3. the lawful-basis and transparency analysis for storing the third party's
   address and sending the one-time neutral invitation;
4. AWS-confirmed acceptability of this exact use case;
5. the data-processing region, retention, subprocessors, and deletion path;
6. authenticated callback, hard-bounce, complaint, suppression, and abuse
   operations; and
7. whether private-until-release is enabled, disabled, or region-gated; and
8. successful sandbox and production-readiness send/callback acceptance.

Until that decision is recorded, the production enable flag remains false. The
development SMTP adapter accepts only local sink hosts, and tests use synthetic
in-process SES and SNS boundaries. No acceptance test sends real external mail.
