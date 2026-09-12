import { FC, ReactNode } from 'react';
import { Outlet } from 'react-router-dom';
import styles from './index.module.scss';

interface LayoutProps {
  children?: ReactNode;
}

const Layout: FC<LayoutProps> = () => {
  return (
    <div className={styles.layout}>
      <aside className={styles.sidebar}>
        <div className={styles.logo}>Logo</div>
        <nav className={styles.nav}>
          <a href="/dashboard">Dashboard</a>
        </nav>
      </aside>
      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
