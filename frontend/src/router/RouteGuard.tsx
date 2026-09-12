// src/router/RouteGuard.tsx
import { useEffect, ReactNode, FC } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useUserStore } from '../store/useUserStore';

interface RouteGuardProps {
  children: ReactNode;
}

const RouteGuard: FC<RouteGuardProps> = ({ children }) => {
  const { token } = useUserStore();
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    // TODO: 启用后端后取消注释以下代码以启用认证检查
    // Public paths (accessible without login)
    // const publicPaths: string[] = [PATHS.login];
    // const isPublic = publicPaths.includes(location.pathname);
    // Redirect to login if not public and not authenticated
    // if (!isPublic && !token) {
    //   const from = encodeURIComponent(location.pathname + location.search);
    //   navigate(`${PATHS.login}?from=${from}`, { replace: true });
    // }

    // 临时：无后端时跳过认证检查
    void token;
    void navigate;
  }, [location.pathname, location.search, token, navigate]);

  return <>{children}</>;
};

export default RouteGuard;
