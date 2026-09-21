import { FC } from 'react';
import styles from './index.module.scss';

const Home: FC = () => {
  return (
    <div className={styles.home}>
      <h1 className={styles.title}>Aeterna Control Plane</h1>
      <p className={styles.subtitle}>Operational dashboards will be added with the corresponding audited domain APIs.</p>
    </div>
  );
};

export default Home;
