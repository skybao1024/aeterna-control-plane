import { FC, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button, Input, Form, Card, Typography } from 'antd';
import { login } from '@/apis/auth';
import { useUserStore } from '@/store/useUserStore';
import { PATHS } from '@/router/paths';
import styles from './index.module.scss';

const { Title, Text } = Typography;

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
      const response = await login(values);
      const { access_token: accessToken, refresh_token: refreshToken } = response.data.data;
      setTokens(accessToken, refreshToken);
      setUser({ email: values.email });

      navigate(getRedirectPath(), { replace: true });
    } catch {
      // The shared HTTP client displays the server-safe error message.
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
          <Text className={styles.subtitle}>Sign in to the Aeterna operations console.</Text>
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
            <Input size="large" placeholder="Enter your email" autoComplete="email" />
          </Form.Item>

          <Form.Item name="password" label="Password" rules={[{ required: true, message: 'Please enter your password' }]}>
            <Input.Password size="large" placeholder="Enter your password" autoComplete="current-password" />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" size="large" loading={loading} block>
              Sign In
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};

export default Login;
