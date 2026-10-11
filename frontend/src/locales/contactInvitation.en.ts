export const contactInvitationCopy = {
  language: 'en',
  heading: 'Aeterna Relay recovery contact invitation',
  loading: 'Loading invitation…',
  introduction: 'Aeterna Relay is a personal library app that encrypts and stores information on the user’s own device.',
  role: 'The inviter identified in your email has asked you to be a recovery contact. This role allows you to receive recovery notifications and help with recovery when it is authorized.',
  consent:
    'Accepting confirms your control of this email address and your consent to the role. It does not provide access to the encrypted library. No account or password is needed to accept or decline.',
  decline: 'If you do not recognize the inviter, confirm with them using a contact method you already know, or decline and delete the invitation.',
  acceptAction: 'Accept and verify email',
  declineAction: 'Decline and delete',
  sending: 'Processing your choice…',
  accepted: 'Your choice was submitted. If this invitation was active, your email was verified and the role was accepted.',
  declined: 'Your choice was submitted. If this invitation was active, it was declined and deleted.',
  error: 'This link is invalid or your choice could not be submitted. Ask the inviter for a new invitation if needed.',
};

export type ContactInvitationCopy = typeof contactInvitationCopy;
