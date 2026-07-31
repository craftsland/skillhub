import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

const JS_BUILD_TARGET = 'es2020'
const LEGACY_BROWSER_TARGETS = ['chrome83', 'edge83', 'firefox78', 'safari14']
const DEV_API_TARGET = process.env.SKILLHUB_DEV_API_TARGET?.trim() || 'http://localhost:8080'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    target: JS_BUILD_TARGET,
    cssTarget: LEGACY_BROWSER_TARGETS,
  },
  optimizeDeps: {
    esbuildOptions: {
      target: JS_BUILD_TARGET,
    },
  },
  test: {
    exclude: ['**/node_modules/**', '**/e2e/**'],
    testTimeout: 30000,
    hookTimeout: 30000,
  },
  server: {
    port: 3000,
    watch: {
      usePolling: true,
      interval: 150,
    },
    proxy: {
      '/api': {
        target: DEV_API_TARGET,
        changeOrigin: true,
      },
      '/oauth2': {
        target: DEV_API_TARGET,
        changeOrigin: false,
      },
      '/login/oauth2/code': {
        target: DEV_API_TARGET,
        changeOrigin: false,
      },
    },
  },
})
