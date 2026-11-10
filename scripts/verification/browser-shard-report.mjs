import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Fail closed on missing, malformed or incomplete Playwright JSON reporter evidence. */
export function validateBrowserShardReport(raw) {
  const report = JSON.parse(raw);
  if (!report || typeof report !== 'object' || Array.isArray(report))
    throw new Error('BROWSER_SHARD_REPORT_NOT_OBJECT');
  const s = report.stats;
  if (!s || !Number.isSafeInteger(s.expected) || s.expected <= 0 ||
      s.unexpected !== 0 || s.flaky !== 0 ||
      (report.errors !== undefined && (!Array.isArray(report.errors) || report.errors.length !== 0)))
    throw new Error('BROWSER_SHARD_REPORT_FAILED_OR_INCOMPLETE');
  return s;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (!process.argv[2]) throw new Error('BROWSER_SHARD_REPORT_PATH_MISSING');
    const stats = validateBrowserShardReport(readFileSync(resolve(process.argv[2]), 'utf8'));
    console.log('BROWSER_REGRESSION_SHARD_PASS', stats);
  } catch (error) {
    console.error('BROWSER_SHARD_REPORT_REJECTED:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
