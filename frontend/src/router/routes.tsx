// src/router/routes.tsx
import { lazy, Suspense, ComponentType, FC } from 'react';
import { Navigate } from 'react-router-dom';
import type { RouteObject } from 'react-router-dom';
import RouteGuard from './RouteGuard';
import { PATHS } from './paths';

// Lazy load components
const Layout = lazy(() => import('../components/Layout'));
const NotFound: FC = () => <div>404 - Not Found</div>;
const Home = lazy(() => import('../pages/Home'));
const Login = lazy(() => import('../pages/Login'));

// Loading spinner component
const LoadingSpinner: FC = () => <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>Loading...</div>;

// Suspense wrapper
function withSuspense(Component: ComponentType) {
  return (
    <Suspense fallback={<LoadingSpinner />}>
      <Component />
    </Suspense>
  );
}

const routes: RouteObject[] = [
  {
    path: '/',
    element: <RouteGuard>{withSuspense(Layout)}</RouteGuard>,
    children: [
      {
        index: true,
        element: <Navigate to={PATHS.dashboard} replace />,
      },
      { path: PATHS.dashboard.slice(1), element: withSuspense(Home) },
    ],
  },
  {
    path: PATHS.login,
    element: withSuspense(Login),
  },
  {
    path: '*',
    element: <NotFound />,
  },
];

export default routes;
