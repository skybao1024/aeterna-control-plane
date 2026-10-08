import type { FC } from 'react';
import { contactPortalCopy as copy } from '@/locales/contactPortal.en';
import styles from './index.module.scss';

const ContactPortal: FC = () => (
  <div className={styles.page}>
    <header className={styles.header}>
      <span className={styles.brand}>{copy.brand}</span>
      <a href="https://aeternarelay.com/">{copy.product}</a>
    </header>
    <main className={styles.content}>
      <p className={styles.label}>{copy.label}</p>
      <h1>{copy.heading}</h1>
      <p className={styles.introduction}>{copy.introduction}</p>
      <section className={styles.instructions} aria-labelledby="personal-link-heading">
        <h2 id="personal-link-heading">{copy.linkHeading}</h2>
        <p>{copy.linkInstructions}</p>
      </section>
      <div className={styles.flows}>
        <section>
          <h2>{copy.invitationHeading}</h2>
          <p>{copy.invitationDescription}</p>
        </section>
        <section>
          <h2>{copy.recoveryHeading}</h2>
          <p>{copy.recoveryDescription}</p>
        </section>
      </div>
      <p className={styles.note}>{copy.missingLink}</p>
      <footer className={styles.footer}>{copy.privacy}</footer>
    </main>
  </div>
);

export default ContactPortal;
