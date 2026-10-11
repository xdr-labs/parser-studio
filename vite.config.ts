import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  // Dev-only same-origin proxy. Backend binds 127.0.0.1 and is never exposed directly.
  server: { proxy: { '/api/v1/parser-pairs': { target: 'http://127.0.0.1:4179', changeOrigin: false } } },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: { include: ['src/**/*.{ts,tsx}'] },
  },
});
