// src/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, useRoutes } from 'react-router-dom';
import routes from './router/routes';
import './index.css';
import './assets/styles/theme.scss';
import './assets/styles/semantic.scss';
import 'virtual:svg-icons-register';
import { App as AntdApp, ConfigProvider } from 'antd';
import enUS from 'antd/locale/en_US';
import MessageBridge from './context/MessageBridge';
import { getAntdThemeConfig } from './theme/antdTheme';

function AppRouter() {
  return useRoutes(routes);
}

function App() {
  return (
    <ConfigProvider locale={enUS} theme={getAntdThemeConfig(true)}>
      <AntdApp>
        <MessageBridge>
          <BrowserRouter>
            <AppRouter />
          </BrowserRouter>
        </MessageBridge>
      </AntdApp>
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
