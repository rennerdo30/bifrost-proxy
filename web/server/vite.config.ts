import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Relative base so the Web UI works behind reverse proxies that mount
  // it under a path prefix (Home Assistant Ingress, Traefik, Cloudflare
  // Tunnel, nginx subpath). Without this, generated asset URLs like
  // `<script src="/assets/..">` resolve to the proxy's root rather than
  // Bifrost's mount point and 404.
  base: './',
  build: {
    outDir: '../../internal/api/server/static',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8081',
        changeOrigin: true,
      },
      '/proxy.pac': {
        target: 'http://localhost:8081',
        changeOrigin: true,
      },
      '/wpad.dat': {
        target: 'http://localhost:8081',
        changeOrigin: true,
      },
    },
  },
})
