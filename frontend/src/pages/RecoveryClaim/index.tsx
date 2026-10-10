import { useEffect, useRef, useState } from 'react';
import { invitationTokenFromHash } from '@/apis/contactInvitation';
import { recoveryClaimCopy as englishCopy } from '@/locales/recoveryClaim.en';
import { recoveryClaimCopy as chineseCopy } from '@/locales/recoveryClaim.zh-CN';
import styles from './index.module.scss';

export default function RecoveryClaim() {
  const initialized = useRef(false);
  const [ready, setReady] = useState(false);
  const copy = navigator.language.toLowerCase().startsWith('zh') ? chineseCopy : englishCopy;

  useEffect(() => {
    const receiveLink = () => {
      setReady(invitationTokenFromHash(window.location.hash) !== null);
      // The website provides instructions only; native recovery owns mailbox proof.
      if (window.location.hash) window.history.replaceState(null, '', window.location.pathname + window.location.search);
    };
    if (!initialized.current) {
      initialized.current = true;
      receiveLink();
    }
    const clear = () => setReady(false);
    window.addEventListener('hashchange', receiveLink);
    window.addEventListener('pagehide', clear);
    return () => {
      window.removeEventListener('hashchange', receiveLink);
      window.removeEventListener('pagehide', clear);
    };
  }, []);

  return (
    <main className={styles.page} lang={copy.language}>
      <div className={styles.card}>
        <h1>{copy.heading}</h1>
        <p>{copy.introduction}</p>
        {ready ? (
          <>
            <ol>
              <li>{copy.openApp}</li>
              <li>{copy.useLink}</li>
              <li>{copy.verify}</li>
              <li>{copy.update}</li>
            </ol>
            <p>{copy.expiredLink}</p>
          </>
        ) : (
          <p role="alert">{copy.error}</p>
        )}
        <p>{copy.privacy}</p>
      </div>
    </main>
  );
}
