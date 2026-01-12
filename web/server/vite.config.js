import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
    plugins: [react()],
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
});
