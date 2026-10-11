import { useEffect, useRef, useState } from 'react';
import { Button } from 'antd';
import { invitationTokenFromHash, respondToContactInvitation, type InvitationDecision } from '@/apis/contactInvitation';
import { contactInvitationCopy as englishCopy } from '@/locales/contactInvitation.en';
import { contactInvitationCopy as chineseCopy } from '@/locales/contactInvitation.zh-CN';
import styles from './index.module.scss';

function invitationCopy() {
  const locale = new URLSearchParams(window.location.search).get('locale');
  if (locale === 'zh-CN') return chineseCopy;
  if (locale === 'en') return englishCopy;
  return navigator.language.toLowerCase().startsWith('zh') ? chineseCopy : englishCopy;
}

function takeInvitationToken(): string | null {
  const token = invitationTokenFromHash(window.location.hash);
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }
  return token;
}

export default function ContactInvitation() {
  const [copy] = useState(invitationCopy);
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
    <main className={styles.page} lang={copy.language}>
      <div className={styles.card}>
        <h1>{copy.heading}</h1>
        {state === 'loading' && <p role="status">{copy.loading}</p>}
        {state === 'ready' && (
          <>
            <p>{copy.introduction}</p>
            <p>{copy.role}</p>
            <p>{copy.consent}</p>
            <p>{copy.decline}</p>
            <div className={styles.actions}>
              <Button type="primary" onClick={() => void respond('accept')}>
                {copy.acceptAction}
              </Button>
              <Button onClick={() => void respond('decline')}>{copy.declineAction}</Button>
            </div>
          </>
        )}
        {state === 'sending' && <p role="status">{copy.sending}</p>}
        {state === 'accepted' && <p role="status">{copy.accepted}</p>}
        {state === 'declined' && <p role="status">{copy.declined}</p>}
        {state === 'error' && <p role="alert">{copy.error}</p>}
      </div>
    </main>
  );
}
