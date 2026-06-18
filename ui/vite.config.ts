import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/_/iam/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Match tsconfig (ES2022). esbuild >=0.28 refuses to downlevel
    // destructuring in dependency code to vite's legacy default
    // baseline; this admin dashboard targets modern browsers only.
    target: 'es2022',
    rollupOptions: {
      output: { manualChunks: undefined },
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
