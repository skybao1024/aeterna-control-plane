import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import { useUserStore } from '../store/useUserStore';
import { getMessageApi } from './messageClient';

// Extend Axios config types
declare module 'axios' {
  export interface AxiosRequestConfig {
    hideMessageModal?: boolean; // Hide error message
  }
  export interface InternalAxiosRequestConfig {
    _retry?: boolean; // Mark if already retried (for token refresh)
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
  timeout: 10 * 1000,
  headers: {
    'Content-Type': 'application/json;charset=UTF-8',
  },
});

// Token refresh state
let isRefreshing = false;
let isRedirecting = false;
let failedQueue: Array<{
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

// Process queued requests
const processQueue = (error: AxiosError | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Auth paths to exclude from redirect
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
  setTimeout(() => {
    isRedirecting = false;
  }, 1000);
  window.location.href = `/login?from=${encodeURIComponent(from)}`;
};

// Request interceptor
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

// Response interceptor
service.interceptors.response.use(
  (response) => {
    const { data, status, config } = response;
    const successCodes = [200, 201, 204];

    if (!successCodes.includes(status)) {
      if (!config.hideMessageModal) {
        notifyError(response.data.message);
      }
      return Promise.reject(response);
    } else {
      // For blob responses, return directly
      if (config.responseType === 'blob') {
        return Promise.resolve(response);
      }

      if (!data || response.status === 204) return Promise.resolve(response);
      const { code } = data;

      if (!successCodes.includes(code)) {
        if (!config.hideMessageModal) {
          notifyError(data.message);
        }
        return Promise.reject(response);
      }
      return Promise.resolve(response);
    }
  },
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
    const status = error?.response?.status;
    const responseData = error?.response?.data as { code?: number; message?: string } | undefined;

    if (status === 204) {
      return Promise.resolve(error.response);
    }

    // TODO: 启用后端后取消注释以下代码以启用 Token 刷新
    // Handle 401 error - Token expired
    // if (status === 401 && originalRequest && !originalRequest._retry) {
    //   if (isRefreshing) {
    //     return new Promise((resolve, reject) => {
    //       failedQueue.push({ resolve, reject });
    //     })
    //       .then((token) => {
    //         if (originalRequest.headers) {
    //           originalRequest.headers.Authorization = `Bearer ${token}`;
    //         }
    //         return service(originalRequest);
    //       })
    //       .catch((err) => Promise.reject(err));
    //   }
    //
    //   originalRequest._retry = true;
    //   isRefreshing = true;
    //
    //   const refreshToken = useUserStore.getState().refreshToken;
    //
    //   if (!refreshToken) {
    //     isRefreshing = false;
    //     processQueue(error, null);
    //     const errorMessage = (error?.response?.data as { message?: string })?.message || 'Session expired';
    //     notifyError(errorMessage);
    //     useUserStore.getState().clearAuth();
    //     window.localStorage.clear();
    //     redirectToLogin();
    //     return Promise.reject(error);
    //   }
    //
    //   try {
    //     // Call refresh token API
    //     const response = await axios.post(
    //       `${import.meta.env.VITE_API_BASE_URL}/v1/auth/refresh`,
    //       { refresh_token: refreshToken },
    //       {
    //         headers: {
    //           'Content-Type': 'application/json;charset=UTF-8',
    //         },
    //       }
    //     );
    //
    //     if (response.data.code === 200) {
    //       const { access_token, refresh_token: newRefreshToken } = response.data.data;
    //       useUserStore.getState().setTokens(access_token, newRefreshToken);
    //
    //       if (originalRequest.headers) {
    //         originalRequest.headers.Authorization = `Bearer ${access_token}`;
    //       }
    //
    //       processQueue(null, access_token);
    //       isRefreshing = false;
    //       return service(originalRequest);
    //     }
    //   } catch (refreshError) {
    //     processQueue(refreshError as AxiosError, null);
    //     isRefreshing = false;
    //     notifyError('Session expired, please login again');
    //     useUserStore.getState().clearAuth();
    //     window.localStorage.clear();
    //     redirectToLogin();
    //     return Promise.reject(refreshError);
    //   }
    // }

    // 临时：忽略未使用变量警告
    void originalRequest;
    void isRefreshing;
    void failedQueue;
    void processQueue;
    void redirectToLogin;

    // Other error handling
    if (!error?.config?.hideMessageModal && error.name !== 'CanceledError' && error.name !== 'AbortError') {
      const errorMessage = responseData?.message || 'An error occurred';
      notifyError(errorMessage);
    }
    return Promise.reject(error);
  }
);

export default service;
