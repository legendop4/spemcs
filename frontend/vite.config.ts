import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// https://vitejs.dev/config/
const projectRoot = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, projectRoot, 'BACKEND_');
  const backendHost = env.BACKEND_HOST;
  const backendPort = env.BACKEND_PORT;

  if (!backendHost || !backendPort) {
    throw new Error('BACKEND_HOST and BACKEND_PORT must be set in the project root .env file.');
  }

  return {
    envDir: projectRoot,
    plugins: [react()],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    optimizeDeps: {
      exclude: ['lucide-react'],
    },
    server: {
      proxy: {
        '/api': {
          target: `http://${backendHost}:${backendPort}`,
          changeOrigin: true,
          ws: true,
        },
      },
    },
  };
});
