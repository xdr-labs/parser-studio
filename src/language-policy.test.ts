import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

/**
 * Owner-approved language policy: project-authored UI, diagnostics, fixtures,
 * source comments and documentation must remain English-only. Unicode symbols
 * used by technical documentation are permitted; non-English UI copy is not.
 */
const NON_ENGLISH_SCRIPT = /[\uAC00-\uD7A3\u3040-\u30FF\u3400-\u9FFF]/u;
const EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.css', '.html',
  '.md', '.json', '.yaml', '.yml']);
const SKIP = new Set(['node_modules', 'dist', '.git', 'test-results',
  'playwright-report', 'coverage']);

function collect(root: string): string[] {
  // Git ignores optional local fixture directories. CI may not contain them.
  if (!existsSync(root)) return [];
  const result: string[] = [];
  for (const item of readdirSync(root, { withFileTypes: true })) {
    if (SKIP.has(item.name)) continue;
    const filename = path.join(root, item.name);
    if (item.isDirectory()) result.push(...collect(filename));
    else if (item.isFile() && EXTENSIONS.has(path.extname(filename))) {
      result.push(filename);
    }
  }
  return result;
}

describe('English-only product and development content', () => {
  it('contains no Korean, Japanese, or Han characters in code, tests, UI or documents', () => {
    const root = process.cwd();
    const paths = ['src', 'tests', 'e2e', 'docs', 'fixtures', '.engineering',
      '.github'].flatMap(dir => collect(path.join(root, dir)));
    paths.push(...['README.md', 'AGENTS.md', 'index.html'].map(p => path.join(root, p)));

    const violations: string[] = [];
    for (const filename of paths) {
      if (!statSync(filename).isFile()) continue;
      readFileSync(filename, 'utf8').split('\n').forEach((line, index) => {
        if (NON_ENGLISH_SCRIPT.test(line)) {
          violations.push(path.relative(root, filename) + ':' + (index + 1));
        }
      });
    }
    expect(violations, 'Non-English product content detected').toEqual([]);
  });

  it('uses an English UI locale instead of a Korean-first or bilingual presentation', () => {
    const root=process.cwd();
    const app=readFileSync(path.join(root,'src/App.tsx'),'utf8');
    expect(app).not.toContain("'ko-KR'");
    const auto=readFileSync(path.join(root,'src/guided/AutoParser.tsx'),'utf8');
    const assisted=readFileSync(path.join(root,'src/guided/ChatGPTAssist.tsx'),'utf8');
    expect(auto).toContain('Ask ChatGPT about an unfamiliar log');
    expect(assisted).toContain('ChatGPT Assisted Parser');
    expect(app).toContain('Auto Parser');
    expect(app).not.toContain("workspace==='guided'");
    expect(app).not.toContain("workspace==='expert'");
    const readme=readFileSync(path.join(root,'README.md'),'utf8');
    expect(readme).toContain('English-only Parser Studio');
    expect(readme).not.toContain('Korean-first');
  });

  it('sets the document language to English', () => {
    const html = readFileSync(path.join(process.cwd(), 'index.html'), 'utf8');
    expect(html).toContain('lang="en"');
  });
});
