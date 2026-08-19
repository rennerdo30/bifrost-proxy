import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // Use the bundler's default minifier (Oxc as of Vite 8). Naming 'esbuild'
    // explicitly would require esbuild as a separate dependency.
    minify: true,
  },
  server: {
    port: 5175,
    strictPort: true,
  },
})
