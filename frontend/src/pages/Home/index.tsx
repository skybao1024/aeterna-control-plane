import { FC } from 'react';
import { Button } from 'antd';
import styles from './index.module.scss';

const Home: FC = () => {
  return (
    <div className={styles.home}>
      <h1 className={styles.title}>Welcome to Your App</h1>
      <p className={styles.subtitle}>This is your dashboard home page.</p>
      <div className={styles.actions}>
        <Button type="primary" size="large">
          Get Started
        </Button>
        <Button size="large">Learn More</Button>
      </div>
    </div>
  );
};

export default Home;
