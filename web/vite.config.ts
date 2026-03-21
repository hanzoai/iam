import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

export default defineConfig({
  plugins: [react()],
  server: {
    port: 7001,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/swagger": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/files": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/.well-known/openid-configuration": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/cas": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/scim": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "build",
    sourcemap: false,
  },
  define: {
    "process.env": "{}",
  },
  css: {
    postcss: "./postcss.config.cjs",
  },
})
