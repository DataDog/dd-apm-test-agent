import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const TEST_AGENT = process.env.LEASH_TEST_AGENT_URL ?? 'http://localhost:8126'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5280,
    strictPort: true,
    proxy: {
      '/leash/api': { target: TEST_AGENT, changeOrigin: true },
      '/api': { target: TEST_AGENT, changeOrigin: true },
    },
  },
})
