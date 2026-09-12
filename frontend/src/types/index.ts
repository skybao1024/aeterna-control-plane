// Type definitions example

// User types
export interface User {
  id?: number;
  email: string;
  name?: string | null;
  avatar?: string | null;
}

// API response types
export interface ApiResponse<T = unknown> {
  code: number;
  message: string;
  data: T;
}

// Pagination types
export interface PaginationParams {
  page: number;
  pageSize: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}
