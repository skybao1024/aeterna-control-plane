import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { chunkSplitPlugin } from 'vite-plugin-chunk-split';
import eslintPlugin from 'vite-plugin-eslint';
import { createSvgIconsPlugin } from 'vite-plugin-svg-icons';

// https://vite.dev/config/
export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiProxyTarget = process.env.API_PROXY_TARGET || env.API_PROXY_TARGET || `http://localhost:${env.API_PORT || '8001'}`;

  return {
    plugins: [
      react({
        babel: {
          plugins: ['babel-plugin-react-compiler'],
        },
      }),
      chunkSplitPlugin({
        customSplitting: {
          'react-vendor': [/node_modules\/react/, /node_modules\/react-dom/],
          utils: [/src\/utils/, /src\/components/],
        },
      }),
      ...(command === 'serve' ? [eslintPlugin({ failOnError: false })] : []),
      createSvgIconsPlugin({
        iconDirs: [path.resolve(__dirname, 'src/assets/svg')],
        symbolId: 'icon-[dir]-[name]',
        inject: 'body-last',
        customDomId: '__svg_icons',
      }),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
      },
    },
    server: {
      proxy: {
        '^/api': {
          target: apiProxyTarget,
          changeOrigin: true,
        },
      },
      host: '0.0.0.0',
      port: 3000,
    },
    build: {
      sourcemap: false,
      minify: 'terser',
    },
    esbuild: {
      pure: ['console'],
    },
  };
});
