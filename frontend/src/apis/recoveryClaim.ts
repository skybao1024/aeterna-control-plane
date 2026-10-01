const MAX_RESPONSE_BYTES = 16_384;
const REQUEST_TIMEOUT_MS = 20_000;

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function request(path: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
  // Public recipient requests must not attach the Owner Axios session.
  const requestId = crypto.randomUUID();
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let body: unknown;
  try {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
      body: JSON.stringify({ protocol_version: 1, request_id: requestId, ...data }),
    });
    if (!response.ok || !response.body) throw new Error('recovery.unavailable');
    const reader = response.body.getReader();
    const bytes = new Uint8Array(MAX_RESPONSE_BYTES);
    let length = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        if (length + chunk.value.byteLength > MAX_RESPONSE_BYTES) throw new Error('recovery.unavailable');
        bytes.set(chunk.value, length);
        length += chunk.value.byteLength;
      }
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)));
    } finally {
      // Abort also stops an oversized body; no complete unbounded text is allocated.
      controller.abort();
      reader.releaseLock();
    }
  } finally {
    window.clearTimeout(timeout);
    controller.abort();
  }
  if (!record(body) || body.protocol_version !== 1 || body.request_id !== requestId || !record(body.data)) throw new Error('recovery.unavailable');
  return body.data;
}

export async function startRecoveryClaim(token: string): Promise<string> {
  if (!TOKEN_PATTERN.test(token)) throw new Error('recovery.unavailable');
  const data = await request('/api/v1/recovery/claim/start', { claim_link_token: token });
  if (typeof data.challenge_id !== 'string' || !UUID_PATTERN.test(data.challenge_id) || data.expires_in_seconds !== 600 || data.resend_after_seconds !== 60)
    throw new Error('recovery.unavailable');
  return data.challenge_id;
}

export async function verifyRecoveryClaim(token: string, challengeId: string, code: string): Promise<string> {
  if (!TOKEN_PATTERN.test(token) || !UUID_PATTERN.test(challengeId) || !/^[0-9]{8}$/.test(code)) throw new Error('recovery.unavailable');
  const data = await request('/api/v1/recovery/claim/verify', { claim_link_token: token, challenge_id: challengeId, code });
  for (const field of ['account_id', 'device_id', 'recovery_id', 'vault_id']) {
    if (typeof data[field] !== 'string' || !UUID_PATTERN.test(data[field])) throw new Error('recovery.unavailable');
  }
  if (
    typeof data.claim_token !== 'string' ||
    !TOKEN_PATTERN.test(data.claim_token) ||
    typeof data.wrapper_digest !== 'string' ||
    !TOKEN_PATTERN.test(data.wrapper_digest) ||
    data.scope !== 'recovery.srs.read' ||
    typeof data.expires_at !== 'string' ||
    !Number.isFinite(Date.parse(data.expires_at))
  )
    throw new Error('recovery.unavailable');
  return JSON.stringify(data);
}
