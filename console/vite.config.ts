import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Where the backend is. Override to point this console at another instance,
// e.g. `KAVACH_SAST_API=http://127.0.0.1:8799 npm run console`.
const API = process.env.KAVACH_SAST_API ?? 'http://127.0.0.1:8788';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: Number(process.env.KAVACH_SAST_CONSOLE_PORT ?? 5174),
    // The console runs locally against the local backend; proxying keeps the
    // browser on one origin so there is no CORS story to get wrong in dev.
    proxy: {
      '/v1': { target: API, changeOrigin: true },
      '/healthz': { target: API, changeOrigin: true },
    },
  },
});
