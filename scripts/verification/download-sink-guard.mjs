// Fails when a Playwright spec can download files without the shared download
// sink recording them, so new E2E tests cannot opt out of artifact validation
// by accident (tests/support/downloadSink.ts, validate-downloaded-artifacts.ts).
import {readdirSync, readFileSync} from 'node:fs';
import {join, relative} from 'node:path';

const EXEMPT = [/(^|\/)tests\/support\//, /(^|\/)tests\/legacy-removed-ui\//];
const PLAYWRIGHT_TEST_IMPORT = /import\s*\{([^}]*)\}\s*from\s*['"]@playwright\/test['"]/g;

const importsTestFromPlaywright = text => {
  for (const match of text.matchAll(PLAYWRIGHT_TEST_IMPORT)) {
    if (match[1].split(',').map(n => n.trim()).includes('test')) return true;
  }
  return false;
};

export function checkDownloadSinkUsage(files) {
  const violations = [];
  for (const {path, text} of files) {
    const normalized = path.replace(/\\/g, '/');
    if (EXEMPT.some(rx => rx.test(normalized))) continue;
    if (importsTestFromPlaywright(text) && /download/i.test(text)) {
      violations.push({path, rule: 'DOWNLOAD_SINK_BYPASSED',
        message: "Specs that download files must import test from './support/downloadSink', not '@playwright/test'."});
      continue;
    }
    if (/downloadSink['"]/.test(text) && /\.newContext\(|launchPersistentContext\(|chromium\.launch\(/.test(text) && !/attachDownloadSink\(/.test(text)) {
      violations.push({path, rule: 'DOWNLOAD_SINK_OWN_CONTEXT',
        message: 'A browser context created inside the spec is invisible to the sink; call attachDownloadSink(context, test.info()).'});
    }
    for (const match of text.matchAll(/downloadSyntheticReason\s*:\s*(['"`])((?:(?!\1).)*)\1/gs)) {
      if (match[2].trim().length < 20) {
        violations.push({path, rule: 'DOWNLOAD_SYNTHETIC_REASON_TOO_SHORT',
          message: 'downloadSyntheticReason must explain why the download is synthetic (at least 20 characters).'});
      }
    }
  }
  return violations;
}

function listTests(root) {
  const out = [];
  const walk = dir => {
    for (const entry of readdirSync(dir, {withFileTypes: true})) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.ts$/.test(entry.name)) out.push({path: relative(process.cwd(), full), text: readFileSync(full, 'utf8')});
    }
  };
  walk(root);
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const files = listTests('tests');
  const violations = checkDownloadSinkUsage(files);
  if (violations.length) {
    for (const v of violations) console.error(`${v.rule} ${v.path}: ${v.message}`);
    process.exit(1);
  }
  const sink = files.filter(f => /downloadSink['"]/.test(f.text)).length;
  console.log(`DOWNLOAD_SINK_GUARD_PASS specs_using_sink=${sink} files_scanned=${files.length}`);
}
