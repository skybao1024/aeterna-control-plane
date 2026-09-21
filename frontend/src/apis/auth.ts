import service from '@/utils/https';

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

interface ApiResponse<T> {
  code: number;
  message: string;
  data: T;
}

export const login = (data: LoginRequest) => {
  return service.post<ApiResponse<LoginResponse>>('/v1/backoffice/auth/login', data);
};
