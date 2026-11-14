#!/usr/bin/env node
/**
 * Derives backend/templates/ruby-forwarder-family.rb.tpl from backend/templates/ruby-fragment.rb.tpl.
 *
 * The forwarder-family template is the Fragment template plus the declared-relay unwrapping. It used to be a
 * second hand-maintained copy of every extractor (Syslog headers, key=value, CSV, JSON, CEF, LEEF). It is now
 * generated: the Fragment template is the only place an extractor is written, and the overlay
 * (backend/templates/ruby-forwarder-family.overlay.json) holds only what the forwarder variant adds.
 *
 *   node scripts/grammar/generate-forwarder-template.mjs --write    regenerate the derived template
 *   node scripts/grammar/generate-forwarder-template.mjs --verify   fail when the committed file differs
 *
 * Every overlay anchor must occur exactly once in the base template, so an edit of the base that moves or
 * removes an anchor fails here instead of silently producing a template without relay handling.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const OVERLAY_PATH = 'backend/templates/ruby-forwarder-family.overlay.json';

export function applyOverlay(base, overlay) {
  if (overlay.schema !== 'parserstudio.template-overlay.v1' || !Array.isArray(overlay.edits) || overlay.edits.length === 0)
    throw new Error('TEMPLATE_OVERLAY_SCHEMA');
  let out = base;
  for (const edit of overlay.edits) {
    const text = lines => { if (!Array.isArray(lines) || lines.some(line => typeof line !== 'string')) throw new Error(`TEMPLATE_OVERLAY_EDIT_INVALID ${edit.id}`); return lines.map(line => line + '\n').join(''); };
    const anchor = text(edit.anchor);
    const at = out.indexOf(anchor);
    if (at < 0 || out.indexOf(anchor, at + 1) >= 0) throw new Error(`TEMPLATE_OVERLAY_ANCHOR_NOT_UNIQUE ${edit.id}`);
    if (edit.op === 'insertAfter') out = out.slice(0, at + anchor.length) + text(edit.lines) + out.slice(at + anchor.length);
    else if (edit.op === 'replace') out = out.slice(0, at) + text(edit.lines) + out.slice(at + anchor.length);
    else throw new Error(`TEMPLATE_OVERLAY_OP_UNKNOWN ${edit.id}`);
  }
  return out;
}

export function generateForwarderTemplate(root = ROOT) {
  const overlay = JSON.parse(readFileSync(resolve(root, OVERLAY_PATH), 'utf8'));
  const base = readFileSync(resolve(root, 'backend/templates', overlay.base), 'utf8');
  return { path: 'backend/templates/' + overlay.output, text: applyOverlay(base, overlay) };
}

function main(argv) {
  const mode = argv[2];
  if (mode !== '--write' && mode !== '--verify') { process.stderr.write('usage: generate-forwarder-template.mjs --write|--verify\n'); return 2; }
  const generated = generateForwarderTemplate();
  if (mode === '--write') { writeFileSync(resolve(ROOT, generated.path), generated.text); process.stdout.write(`FORWARDER_TEMPLATE_GENERATED ${generated.path}\n`); return 0; }
  if (readFileSync(resolve(ROOT, generated.path), 'utf8') !== generated.text) {
    process.stderr.write(`FORWARDER_TEMPLATE_STALE ${generated.path}: run node scripts/grammar/generate-forwarder-template.mjs --write\n`);
    return 1;
  }
  process.stdout.write(`FORWARDER_TEMPLATE_VERIFIED ${generated.path}\n`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main(process.argv));
