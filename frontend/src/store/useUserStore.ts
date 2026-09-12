import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';

// User type definition
interface User {
  id?: number;
  email: string;
  name?: string | null;
  avatar?: string | null;
}

interface UserState {
  user: User | null;
  token: string;
  refreshToken: string;
  setUser: (user: User | null) => void;
  setToken: (token: string) => void;
  setRefreshToken: (refreshToken: string) => void;
  setTokens: (accessToken: string, refreshToken: string) => void;
  clearAuth: () => void;
}

export const useUserStore = create<UserState>()(
  persist(
    (set) => ({
      user: null,
      token: '',
      refreshToken: '',
      setUser: (user) => set({ user }),
      setToken: (token) => set({ token }),
      setRefreshToken: (refreshToken) => set({ refreshToken }),
      setTokens: (accessToken, refreshToken) => set({ token: accessToken, refreshToken }),
      clearAuth: () => set({ user: null, token: '', refreshToken: '' }),
    }),
    {
      name: 'userStore',
      storage: createJSONStorage(() => localStorage),
    }
  )
);
