// node --test scripts/grammar/generate-forwarder-template.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { OVERLAY_PATH, applyOverlay, generateForwarderTemplate } from './generate-forwarder-template.mjs';

const overlay = JSON.parse(readFileSync(OVERLAY_PATH, 'utf8'));
const base = readFileSync('backend/templates/' + overlay.base, 'utf8');

test('the committed forwarder-family template is exactly the Fragment template plus the overlay', () => {
  const generated = generateForwarderTemplate();
  assert.equal(readFileSync(generated.path, 'utf8'), generated.text);
});

test('the overlay only adds relay unwrapping: every extractor of the Fragment template is carried over unchanged', () => {
  const derived = applyOverlay(base, overlay);
  const definitions = text => [...text.matchAll(/^def (parserstudio_[a-z0-9_?]+)/gm)].map(match => match[1]);
  assert.deepEqual(definitions(derived).filter(name => name !== 'parserstudio_unwrap_declared_relays'), definitions(base));
  const body = (text, name) => text.slice(text.indexOf('def ' + name + '('), text.indexOf('\nend\n', text.indexOf('def ' + name + '(')));
  for (const name of ['parserstudio_key_values', 'parserstudio_cef_extensions', 'parserstudio_leef', 'parserstudio_syslog_rfc3164', 'parserstudio_csv'])
    assert.equal(body(derived, name), body(base, name), name);
  assert.ok(derived.length - base.length < 3000, 'the overlay stays small');
});

test('an anchor that is missing or no longer unique fails instead of dropping relay handling', () => {
  const edit = overlay.edits[0];
  assert.throws(() => applyOverlay(base.replace(edit.anchor[0], 'something else'), overlay), /ANCHOR_NOT_UNIQUE/);
  assert.throws(() => applyOverlay(base + edit.anchor[0] + '\n', overlay), /ANCHOR_NOT_UNIQUE/);
  assert.throws(() => applyOverlay(base, { ...overlay, edits: [{ ...edit, op: 'delete' }] }), /OP_UNKNOWN/);
  assert.throws(() => applyOverlay(base, { ...overlay, schema: 'x' }), /OVERLAY_SCHEMA/);
});
