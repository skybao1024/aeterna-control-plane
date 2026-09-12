// API module example
import service from '@/utils/https';

// Example API types
interface LoginRequest {
  email: string;
  password: string;
}

interface LoginResponse {
  access_token: string;
  refresh_token: string;
}

interface ApiResponse<T> {
  code: number;
  message: string;
  data: T;
}

// Example login API
export const login = (data: LoginRequest) => {
  return service.post<ApiResponse<LoginResponse>>('/v1/auth/login', data);
};

// Example get current user API
export const getCurrentUser = () => {
  return service.get<ApiResponse<{ email: string; name: string }>>('/v1/users/me');
};
