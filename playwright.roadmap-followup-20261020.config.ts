import {defineConfig} from '@playwright/test';
import baseline from './playwright.config';
export default defineConfig({...baseline,testMatch:['tests/roadmap-source-draft-20261020.isolated.ts','tests/roadmap-batch-ux-20261020.isolated.ts','tests/roadmap-text-recovery-20261020.isolated.ts','tests/roadmap-profile-format-transition-20261020.isolated.ts','tests/mixed-generic-profiles-20261020.isolated.ts','tests/audit-cross-engine-parity-20261103.isolated.ts'],workers:1,retries:0});
