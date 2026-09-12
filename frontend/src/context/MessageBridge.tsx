import { App as AntdApp } from 'antd';
import { useEffect, ReactNode, FC } from 'react';
import { setMessageApi } from '../utils/messageClient';

interface MessageBridgeProps {
  children: ReactNode;
}

const MessageBridge: FC<MessageBridgeProps> = ({ children }) => {
  const { message } = AntdApp.useApp();

  useEffect(() => {
    setMessageApi(message);
    return () => setMessageApi(null);
  }, [message]);

  return children;
};

export default MessageBridge;
