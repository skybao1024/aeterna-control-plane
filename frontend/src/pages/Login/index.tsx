import { FC, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button, Input, Form, Card, Typography } from 'antd';
import { useUserStore } from '@/store/useUserStore';
import { PATHS } from '@/router/paths';
import styles from './index.module.scss';

const { Title, Text, Link } = Typography;

const Login: FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { setTokens, setUser } = useUserStore();
  const [loading, setLoading] = useState(false);

  // Get redirect path from URL
  const searchParams = new URLSearchParams(location.search);
  const from = searchParams.get('from');

  const getRedirectPath = (): string => {
    if (from && from.startsWith('/') && !from.startsWith('//')) {
      return from;
    }
    return PATHS.dashboard;
  };

  const handleSubmit = async (values: { email: string; password: string }) => {
    setLoading(true);
    try {
      // TODO: Replace with actual login API call
      // Simulating login for demo purposes
      console.log('Login with:', values);

      // Mock successful login
      setTokens('mock-access-token', 'mock-refresh-token');
      setUser({ email: values.email, name: 'Demo User' });

      navigate(getRedirectPath(), { replace: true });
    } catch (error) {
      console.error('Login failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.container}>
      <Card className={styles.card}>
        <div className={styles.header}>
          <Title level={2} className={styles.title}>
            Sign In
          </Title>
          <Text className={styles.subtitle}>Welcome back! Please sign in to continue.</Text>
        </div>

        <Form layout="vertical" onFinish={handleSubmit} className={styles.form}>
          <Form.Item
            name="email"
            label="Email"
            rules={[
              { required: true, message: 'Please enter your email' },
              { type: 'email', message: 'Please enter a valid email' },
            ]}
          >
            <Input size="large" placeholder="Enter your email" />
          </Form.Item>

          <Form.Item name="password" label="Password" rules={[{ required: true, message: 'Please enter your password' }]}>
            <Input.Password size="large" placeholder="Enter your password" />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" size="large" loading={loading} block>
              Sign In
            </Button>
          </Form.Item>
        </Form>

        <div className={styles.footer}>
          <Text>Don&apos;t have an account? </Text>
          <Link onClick={() => navigate('/register')}>Sign Up</Link>
        </div>
      </Card>
    </div>
  );
};

export default Login;
