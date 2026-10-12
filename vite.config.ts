import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
// A fixed loopback-only development proxy, never a caller-supplied host.
// In a real deployment authorization must also be enforced by the server.
const candidatePort=Number(process.env.PARSER_STUDIO_BACKEND_PORT || 4179);
if(!Number.isSafeInteger(candidatePort)||candidatePort<1024||candidatePort>65535)
  throw new Error('Invalid isolated backend loopback port');
const backendOrigin='http://127.0.0.1:'+candidatePort;
const loopbackProxy={target:backendOrigin,changeOrigin:false};
export default defineConfig({
  plugins: [react()],
  // No raw customer sample is sent automatically. Restricted APIs deny by
  // default unless an authorized backend explicitly injects an owner grant.
  server: { proxy: {
    '/api/v1/parser-pairs': loopbackProxy,
    '/api/v1/test-lab': loopbackProxy,
  } },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: { include: ['src/**/*.{ts,tsx}'] },
  },
});
