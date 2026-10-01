import { useEffect, useRef, useState } from 'react';
import { Button, Input } from 'antd';
import { invitationTokenFromHash } from '@/apis/contactInvitation';
import { startRecoveryClaim, verifyRecoveryClaim } from '@/apis/recoveryClaim';
import { recoveryClaimCopy as copy } from '@/locales/recoveryClaim.en';
import styles from './index.module.scss';

export default function RecoveryClaim() {
  const token = useRef<string | null>(null);
  const challenge = useRef<string | null>(null);
  const operation = useRef(0);
  const [state, setState] = useState<'loading' | 'ready' | 'otp' | 'sending' | 'handoff' | 'error'>('loading');
  const [code, setCode] = useState('');
  const [error, setError] = useState(false);
  const [handoff, setHandoff] = useState('');

  useEffect(() => {
    // StrictMode must not consume the fragment twice.
    if (token.current === null) token.current = invitationTokenFromHash(window.location.hash);
    if (window.location.hash) window.history.replaceState(null, '', window.location.pathname + window.location.search);
    setState(token.current ? 'ready' : 'error');
    const clear = () => {
      operation.current += 1;
      token.current = null;
      challenge.current = null;
      setHandoff('');
      setCode('');
      setState('error');
    };
    const receiveLink = () => {
      operation.current += 1;
      token.current = invitationTokenFromHash(window.location.hash);
      challenge.current = null;
      setHandoff('');
      setCode('');
      setError(false);
      if (window.location.hash) window.history.replaceState(null, '', window.location.pathname + window.location.search);
      setState(token.current ? 'ready' : 'error');
    };
    window.addEventListener('hashchange', receiveLink);
    window.addEventListener('pagehide', clear);
    return () => {
      operation.current += 1;
      window.removeEventListener('pagehide', clear);
      window.removeEventListener('hashchange', receiveLink);
    };
  }, []);

  const start = async () => {
    const link = token.current;
    if (!link) return;
    const epoch = ++operation.current;
    setState('sending');
    try {
      const challengeId = await startRecoveryClaim(link);
      if (operation.current !== epoch) return;
      challenge.current = challengeId;
      setState('otp');
    } catch {
      if (operation.current !== epoch) return;
      setState('error');
    }
  };
  const verify = async () => {
    const link = token.current;
    const challengeId = challenge.current;
    if (!link || !challengeId) return;
    const epoch = ++operation.current;
    setError(false);
    const value = code;
    setCode('');
    setState('sending');
    try {
      const response = await verifyRecoveryClaim(link, challengeId, value);
      // An old request must not restore a bearer after navigation or a new link.
      if (operation.current !== epoch) return;
      setHandoff(response);
      token.current = null;
      challenge.current = null;
      setState('handoff');
    } catch {
      if (operation.current !== epoch) return;
      setError(true);
      setState('otp');
    }
  };

  return (
    <main className={styles.page}>
      <div className={styles.card}>
        <h1>{copy.heading}</h1>
        {error && <p role="alert">{copy.error}</p>}
        <p>{copy.introduction}</p>
        {state === 'loading' && <p role="status">{copy.loading}</p>}
        {state === 'ready' && (
          <Button type="primary" onClick={() => void start()}>
            {copy.start}
          </Button>
        )}
        {state === 'sending' && <p role="status">{copy.sending}</p>}
        {state === 'otp' && (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void verify();
            }}
          >
            <p role="status">{copy.otp}</p>
            <label htmlFor="contact-code">{copy.code}</label>
            <Input id="contact-code" value={code} inputMode="numeric" autoComplete="off" maxLength={8} onChange={(event) => setCode(event.target.value)} />
            <Button htmlType="submit" type="primary" disabled={!/^[0-9]{8}$/.test(code)}>
              {copy.verify}
            </Button>
          </form>
        )}
        {state === 'handoff' && (
          <>
            <p role="status">{copy.handoff}</p>
            <label htmlFor="claim-handoff">{copy.label}</label>
            <Input.TextArea id="claim-handoff" readOnly value={handoff} autoComplete="off" rows={8} />
          </>
        )}
        {state === 'error' && <p role="alert">{copy.error}</p>}
      </div>
    </main>
  );
}
