// Approval gate of the Ruby template set (see ./template-set.ts and contracts/ruby-template-set.v1.json).
//
// The reviewed-template hash of the disposable POC path sees one artifact, compiled from a JSON sample project.
// These tests see every template file, every compiler-owned helper and the artifact of every compiler variant.
// They never add an approval: APPROVED_TEMPLATE_SET_SHA256 is set by the owner's review only.
import assert from 'node:assert/strict';
import {readdirSync, readFileSync} from 'node:fs';
import test from 'node:test';
import {
  currentTemplateSet, normalizedRuby, serializeManifest, TEMPLATE_SET_MANIFEST_PATH, templateSetDigest,
  type TemplateSetManifest,
} from './template-set.js';

// Owner approval of the template set. null means that no template set has been approved: the gate below then
// fails and prints the digest that needs a review. Do not copy a digest here without that review.
// Owner approval of 2026-11-25 for the template set of PR #316 at 2f85c6a
// (docs/verification/20261125-owner-template-approval.md).
const APPROVED_TEMPLATE_SET_SHA256: string | null = 'bb653102732e01001b5a30d4ac05b14917bb43dbe84eb484c88c409b261e0e8a';

const current = currentTemplateSet();
const committed = (): TemplateSetManifest => JSON.parse(readFileSync(TEMPLATE_SET_MANIFEST_PATH, 'utf8')) as TemplateSetManifest;

test('the committed manifest is what the current templates and compiler produce', () => {
  assert.equal(readFileSync(TEMPLATE_SET_MANIFEST_PATH, 'utf8'), serializeManifest(current.manifest),
    'the Ruby templates or the compiler changed: run scripts/verification/ruby-template-set.ts --write and request an owner review');
  assert.equal(committed().templateSetSha256, templateSetDigest(committed()), 'the recorded digest is not the digest of the recorded parts');
});

test('the set holds every template file and every compiler-owned helper', () => {
  assert.deepEqual(Object.keys(current.manifest.templates), readdirSync(new URL('../templates/', import.meta.url)).sort());
  // Text that only a compiler branch or a conditional template part emits. Each must be in the Ruby of at least
  // one variant, otherwise a change to it would not move any artifact hash.
  const helpers: Array<[string, string]> = [
    ['Generic Structural grammar', 'def psg_extract_generic_structural('],
    ['Generic Structural normalization', "normalized = {'parserstudio_source' => original}"],
    ['source-copy omission', 'def parserstudio_without_source_raw(value)'],
    ['Regex extraction helper', 'def parserstudio_regex('],
    ['canonical operators', 'def parserstudio_normalize(original)'],
    ['grammar runtime', 'def psg_units('],
    ['shared reader', 'def psg_read_event('],
    // Both texts of the one compiler branch that writes a value into the Regex helper.
    ['Regex with a static cost proof', 'def parserstudio_regex_cost_proven?\n  true\n'],
    ['Regex without a static cost proof', 'def parserstudio_regex_cost_proven?\n  false\n'],
  ];
  const texts = Object.values(current.ruby);
  for (const [name, marker] of helpers) assert.ok(texts.some(text => text.includes(marker)), name + ' is in no compiler variant');
  assert.ok(Object.keys(current.manifest.artifacts).length >= 90, 'the compiler variant enumeration shrank');
});

test('the digest moves with any template, artifact or case-fold change, and only with those', () => {
  const base = current.manifest;
  const firstTemplate = Object.keys(base.templates)[0]!;
  const firstVariant = Object.keys(base.artifacts)[0]!;
  const changed: Array<[string, Pick<TemplateSetManifest, 'templates' | 'unicodeCaseMapSha256' | 'artifacts'>]> = [
    ['a template file', { ...base, templates: { ...base.templates, [firstTemplate]: '0'.repeat(64) } }],
    ['a removed template file', { ...base, templates: Object.fromEntries(Object.entries(base.templates).slice(1)) }],
    ['the Ruby of one variant', { ...base, artifacts: { ...base.artifacts, [firstVariant]: { ...base.artifacts[firstVariant]!, ruby: '0'.repeat(64) } } }],
    ['the CONF of one variant', { ...base, artifacts: { ...base.artifacts, [firstVariant]: { ...base.artifacts[firstVariant]!, conf: '0'.repeat(64) } } }],
    ['a removed variant', { ...base, artifacts: Object.fromEntries(Object.entries(base.artifacts).slice(1)) }],
    ['the case-fold table', { ...base, unicodeCaseMapSha256: '0'.repeat(64) }],
  ];
  for (const [what, parts] of changed) assert.notEqual(templateSetDigest(parts), base.templateSetSha256, what);
  assert.equal(templateSetDigest({ ...base, artifacts: Object.fromEntries(Object.entries(base.artifacts).reverse()) }), base.templateSetSha256, 'key order');
  // The normalized Ruby ignores the project literal and the zlib bytes of the table, and nothing else.
  const ruby = "x = Base64.strict_decode64('QUJDREVGR0g=')\n@parserstudio_case_map = JSON.parse(Zlib::Inflate.inflate(Base64.strict_decode64('eJyrVkrLz1eyUkpKLFKqBQAdegQ0')))\n";
  const other = ruby.replace('QUJDREVGR0g=', 'SUpLTE1OT1A=');
  assert.equal(normalizedRuby(ruby).text, normalizedRuby(other).text);
  assert.notEqual(normalizedRuby(ruby + '# injected Ruby\n').text, normalizedRuby(ruby).text);
  assert.equal(normalizedRuby(ruby).caseMap, '{"foo":"bar"}');
  assert.throws(() => normalizedRuby(ruby + "y = Base64.strict_decode64('QUJDREVGR0hJSktM')\n"), /TEMPLATE_SET_SHAPE/);
});

test('the template set is owner-approved', () => {
  const digest = current.manifest.templateSetSha256;
  console.log('TEMPLATE_SET_STATUS sha256=' + digest + ' approved=' + String(digest === APPROVED_TEMPLATE_SET_SHA256));
  assert.equal(digest, APPROVED_TEMPLATE_SET_SHA256,
    'the Ruby template set has no owner approval: sha256=' + digest + ' needs an owner review (contracts/ruby-template-set.v1.json lists what it covers)');
});
