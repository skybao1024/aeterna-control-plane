import axios, { AxiosError } from 'axios';
import { useUserStore } from '../store/useUserStore';
import { getMessageApi } from './messageClient';

declare module 'axios' {
  export interface AxiosRequestConfig {
    hideMessageModal?: boolean;
  }
}

const notifyError = (content: string): void => {
  const messageApi = getMessageApi();
  if (messageApi) {
    messageApi.error(content);
  } else {
    console.error(content);
  }
};

const service = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  timeout: 10_000,
  headers: {
    'Content-Type': 'application/json;charset=UTF-8',
  },
});

let isRedirecting = false;
const AUTH_PATHS = ['/login'];

const getValidFromPath = (): string => {
  const currentPath = location.pathname;
  if (AUTH_PATHS.some((authPath) => currentPath.startsWith(authPath))) {
    return '/dashboard';
  }
  return currentPath + location.search;
};

const redirectToLogin = (): void => {
  if (isRedirecting) return;
  isRedirecting = true;
  const from = getValidFromPath();
  window.location.href = `/login?from=${encodeURIComponent(from)}`;
};

service.interceptors.request.use(
  (config) => {
    const token = useUserStore.getState().token;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (timezone) {
      config.headers['X-Client-Timezone'] = timezone;
    }

    return config;
  },
  (error) => Promise.reject(error)
);

service.interceptors.response.use(
  (response) => {
    const { data, status, config } = response;
    const successCodes = [200, 201, 204];

    if (!successCodes.includes(status)) {
      if (!config.hideMessageModal) {
        notifyError(data?.message || 'Request failed');
      }
      return Promise.reject(response);
    }

    if (config.responseType === 'blob' || !data || status === 204) {
      return response;
    }

    if (!successCodes.includes(data.code)) {
      if (!config.hideMessageModal) {
        notifyError(data.message || 'Request failed');
      }
      return Promise.reject(response);
    }

    return response;
  },
  (error: AxiosError) => {
    const status = error.response?.status;
    const responseData = error.response?.data as { message?: string } | undefined;

    if (status === 401 && !AUTH_PATHS.includes(location.pathname)) {
      useUserStore.getState().clearAuth();
      redirectToLogin();
    }

    if (!error.config?.hideMessageModal && error.name !== 'CanceledError' && error.name !== 'AbortError') {
      notifyError(responseData?.message || 'An error occurred');
    }
    return Promise.reject(error);
  }
);

export default service;
