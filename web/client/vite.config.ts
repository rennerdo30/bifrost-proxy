import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Relative base so the Web UI works behind reverse proxies that mount
  // it under a path prefix (Home Assistant Ingress, Traefik, Cloudflare
  // Tunnel, nginx subpath). See web/server/vite.config.ts for rationale.
  base: './',
  build: {
    outDir: '../../internal/api/client/static',
    emptyOutDir: true,
  },
  server: {
    port: 5174,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
