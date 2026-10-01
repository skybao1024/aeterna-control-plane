import { useEffect, useRef, useState } from 'react';
import { Button } from 'antd';
import { invitationTokenFromHash, respondToContactInvitation, type InvitationDecision } from '../../apis/contactInvitation';
import styles from './index.module.scss';

function takeInvitationToken(): string | null {
  const token = invitationTokenFromHash(window.location.hash);
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }
  return token;
}

export default function ContactInvitation() {
  const [token, setToken] = useState<string | null>(null);
  const currentToken = useRef<string | null>(null);
  const [state, setState] = useState<'loading' | 'ready' | 'sending' | 'accepted' | 'declined' | 'error'>('loading');

  useEffect(() => {
    const onHashChange = () => {
      const nextToken = takeInvitationToken();
      currentToken.current = nextToken;
      setToken(nextToken);
      setState(nextToken ? 'ready' : 'error');
    };
    window.addEventListener('hashchange', onHashChange);
    // StrictMode replays mount effects after the fragment has been removed.
    if (currentToken.current === null) onHashChange();
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const respond = async (decision: InvitationDecision) => {
    if (!token || state !== 'ready') return;
    setState('sending');
    try {
      await respondToContactInvitation(token, decision);
      if (currentToken.current === token) setState(decision === 'accept' ? 'accepted' : 'declined');
    } catch {
      if (currentToken.current === token) setState('error');
    }
  };

  return (
    <main className={styles.page}>
      <div className={styles.card}>
        <h1>Aeterna recovery contact invitation</h1>
        {state === 'loading' && <p role="status">Loading invitation…</p>}
        {state === 'ready' && (
          <>
            <p>
              An Aeterna owner invited you to be a recovery contact. Accepting verifies control of this email address and allows a recovery claim only after the owner’s policy
              releases. No account or password is needed.
            </p>
            <p>You can decline and request deletion of this invitation instead.</p>
            <div className={styles.actions}>
              <Button type="primary" onClick={() => void respond('accept')}>
                Accept and verify
              </Button>
              <Button onClick={() => void respond('decline')}>Decline and delete</Button>
            </div>
          </>
        )}
        {state === 'sending' && <p role="status">Processing your choice…</p>}
        {state === 'accepted' && <p role="status">Your choice was submitted. If this invitation was active, your email was verified and the role was accepted.</p>}
        {state === 'declined' && <p role="status">Your choice was submitted. If this invitation was active, it was declined and deleted.</p>}
        {state === 'error' && <p role="alert">This link is invalid or the response could not be submitted. Ask the owner for a new invitation if needed.</p>}
      </div>
    </main>
  );
}
