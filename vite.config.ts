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
  server: { allowedHosts:['.trycloudflare.com'], proxy: {
    '/api/v1/parser-pairs': loopbackProxy,
    '/api/v1/test-lab': loopbackProxy,
    '/api/v1/multipass': {
      target:'http://127.0.0.1:4192',changeOrigin:false,
      configure(proxy){
        proxy.on('proxyReq',request=>request.setHeader('Origin','http://127.0.0.1:5180'));
      },
    },
  } },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: { include: ['src/**/*.{ts,tsx}'] },
  },
});
