import {defineConfig} from 'vitest/config';
export default defineConfig({
  test:{
    include:['poc/vendor_engine/**/*.test.ts'],
    environment:'node',
  },
});
