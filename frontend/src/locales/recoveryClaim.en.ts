export const recoveryClaimCopy = {
  heading: 'Aeterna recovery claim',
  introduction:
    'This link is scoped to one local device and vault. Only the verified contact mailbox can authorize a claim after release. Vault content and the emergency recovery code stay on the local computer.',
  start: 'Send mailbox code',
  code: 'Contact mailbox code (8 digits)',
  verify: 'Verify and prepare desktop handoff',
  loading: 'Loading recovery link…',
  sending: 'Processing recovery claim…',
  otp: 'Check the contact mailbox for the separate code. The code expires after 10 minutes.',
  handoff:
    'Paste this short-lived handoff into Emergency recovery in the local Aeterna app for this device. It permits one server-factor read for five minutes. It contains no emergency recovery code or vault content. Do not send it to anyone else.',
  label: 'Desktop claim handoff',
  error: 'The claim could not proceed. The link or code may be invalid, expired, consumed, or not yet released. Check the release email and try again.',
};
