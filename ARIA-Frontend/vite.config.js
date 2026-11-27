import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies /api -> ARIA FastAPI bridge (frontend_api.py) so the browser
// talks same-origin and CORS never comes into play during local development.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.ARIA_API_TARGET || 'http://127.0.0.1:8000'
  return {
    plugins: [react()],
    base: env.VITE_BASE || '/',
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: { '/api': { target: apiTarget, changeOrigin: true } },
    },
    preview: {
      port: 4173,
      strictPort: true,
      proxy: { '/api': { target: apiTarget, changeOrigin: true } },
    },
  }
})
