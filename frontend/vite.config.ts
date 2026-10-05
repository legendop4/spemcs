import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// https://vitejs.dev/config/
const projectRoot = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig(({ mode, command }) => {
  const env = loadEnv(mode, projectRoot, 'BACKEND_');
  const backendHost = env.BACKEND_HOST;
  const backendPort = env.BACKEND_PORT;

  // Only the local development server requires the local proxy configuration.
  // Production builds (e.g. on Vercel) use vercel.json rewrites instead.
  if (command === 'serve' && (!backendHost || !backendPort)) {
    throw new Error('BACKEND_HOST and BACKEND_PORT must be set in the project root .env file for local development.');
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
      host: '0.0.0.0',
      ...(backendHost && backendPort ? {
        proxy: {
          '/api': {
            target: backendPort === '443' ? `https://${backendHost}` : `http://${backendHost}:${backendPort}`,
            changeOrigin: true,
            secure: false,
            ws: true,
            headers: {
              host: 'spemcs.shivamsharma.tech',
            },
            configure: (proxy, _options) => {
              proxy.on('error', (err) => {
                const code = (err as any)?.code || '';
                const msg = err?.message || '';
                if (code === 'ECONNABORTED' || code === 'ECONNRESET' || msg.includes('ECONNABORTED') || msg.includes('ECONNRESET')) {
                  return;
                }
                console.error('[vite] proxy error:', err);
              });
              proxy.on('proxyReqWs', (_proxyReq, _req, socket) => {
                socket.on('error', (err) => {
                  const code = (err as any)?.code || '';
                  const msg = err?.message || '';
                  if (code === 'ECONNABORTED' || code === 'ECONNRESET' || msg.includes('ECONNABORTED') || msg.includes('ECONNRESET')) {
                    return;
                  }
                });
              });
            },
          },
        },
      } : {}),
    },
  };
});

