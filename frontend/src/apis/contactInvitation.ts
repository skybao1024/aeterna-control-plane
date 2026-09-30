export type InvitationDecision = 'accept' | 'decline';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function invitationTokenFromHash(hash: string): string | null {
  const token = new URLSearchParams(hash.replace(/^#/, '')).get('token');
  return token && TOKEN_PATTERN.test(token) ? token : null;
}

export async function respondToContactInvitation(token: string, decision: InvitationDecision): Promise<void> {
  if (!TOKEN_PATTERN.test(token)) throw new Error('invitation.invalid_link');
  const requestId = crypto.randomUUID();
  // The recipient route is public; the Owner Axios client would attach an unrelated session.
  const response = await fetch('/api/v1/contact-invitations/respond', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ protocol_version: 1, request_id: requestId, token, decision }),
    credentials: 'omit',
    cache: 'no-store',
  });
  const body: unknown = await response.json().catch(() => null);
  if (
    !response.ok ||
    typeof body !== 'object' ||
    body === null ||
    !('protocol_version' in body) ||
    body.protocol_version !== 1 ||
    !('request_id' in body) ||
    body.request_id !== requestId ||
    !('data' in body) ||
    typeof body.data !== 'object' ||
    body.data === null ||
    !('processed' in body.data) ||
    body.data.processed !== true
  ) {
    throw new Error('invitation.unavailable');
  }
}
