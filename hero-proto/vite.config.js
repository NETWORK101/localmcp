import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  // GitHub Pages serves project sites under /<repo>/; Cloudflare serves at /. Set by the workflow.
  base: process.env.VITE_BASE || '/',
  plugins: [react()],
  server: { port: 5173 }
})
