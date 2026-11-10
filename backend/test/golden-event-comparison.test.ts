// Unit tests for the independent golden-event comparison and the Ruby event
// runner it relies on. The inputs here are hand-written test data, not vendor
// logs; vendor-sourced cases live in evals/chatgpt/security-cases.json.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { compilePair } from '../src/compiler.js';
import {
  compareEventToGolden,
  type EmittedEvent,
  type GoldenValue,
  type MappingRow,
} from '../src/golden-event-comparison.js';
import { sampleProject } from './fixture.js';

const golden: GoldenValue[] = [
  { sourcePath: 'srcip', sourceValue: '10.1.100.11' },
  { sourcePath: 'srcport', sourceValue: '58012' },
  { sourcePath: 'service', sourceValue: 'HTTP' },
];
const rows: MappingRow[] = [
  { source: 'srcip', target: 'srcip', vendorNamespace: false },
  { source: 'srcport', target: 'srcport', vendorNamespace: false },
  { source: 'service', target: 'service', vendorNamespace: true },
];
const goodEvent: EmittedEvent = {
  time: null,
  record: { srcip: '10.1.100.11', srcport: 58012, fortinet: { service: 'HTTP' } },
};
const compare = (over: Partial<Parameters<typeof compareEventToGolden>[0]> = {}) =>
  compareEventToGolden({ golden, rows, required: ['srcip', 'srcport', 'service'], events: [goodEvent], ...over });
const codes = (result: ReturnType<typeof compare>) => result.problems.map(p => p.code);

test('values that round-trip from the documented log through mapping into the event pass', () => {
  const result = compare();
  assert.deepEqual(result.problems, []);
  assert.deepEqual(result.matched.map(m => m.sourcePath), ['srcip', 'srcport', 'service']);
});

test('a number in the event equals the documented string value', () => {
  assert.deepEqual(compare().problems, []);
  const wrong = compare({ events: [{ time: null, record: { srcip: '10.1.100.11', srcport: 58013, fortinet: { service: 'HTTP' } } }] });
  assert.deepEqual(codes(wrong), ['REQUIRED_FIELD_VALUE_MISMATCH']);
});

test('a wrong value in the emitted event is a mismatch', () => {
  const result = compare({ events: [{ time: null, record: { srcip: '10.1.100.99', srcport: 58012, fortinet: { service: 'HTTP' } } }] });
  assert.deepEqual(codes(result), ['REQUIRED_FIELD_VALUE_MISMATCH']);
});

test('a required field with no mapping row is reported, not skipped', () => {
  const result = compare({ rows: rows.filter(r => r.source !== 'srcport') });
  assert.deepEqual(codes(result), ['REQUIRED_FIELD_UNMAPPED']);
});

test('a mapped field that the event does not carry is reported', () => {
  const result = compare({ events: [{ time: null, record: { srcip: '10.1.100.11', fortinet: { service: 'HTTP' } } }] });
  assert.deepEqual(codes(result), ['REQUIRED_FIELD_MISSING_IN_EVENT']);
});

test('a manufacturer-namespace field must live under a nested namespace, not at the top level', () => {
  const result = compare({ events: [{ time: null, record: { srcip: '10.1.100.11', srcport: 58012, service: 'HTTP' } }] });
  assert.deepEqual(codes(result), ['REQUIRED_FIELD_MISSING_IN_EVENT']);
});

test('an official field must be at the top level, not hidden in a namespace', () => {
  const result = compare({ events: [{ time: null, record: { srcport: 58012, fortinet: { srcip: '10.1.100.11', service: 'HTTP' } } }] });
  assert.deepEqual(codes(result), ['REQUIRED_FIELD_MISSING_IN_EVENT']);
});

test('the same vendor field in two namespaces is ambiguous', () => {
  const result = compare({ events: [{ time: null, record: { srcip: '10.1.100.11', srcport: 58012, a: { service: 'HTTP' }, b: { service: 'HTTP' } } }] });
  assert.deepEqual(codes(result), ['AMBIGUOUS_VENDOR_NAMESPACE']);
});

test('zero or several emitted events fail instead of passing vacuously', () => {
  assert.deepEqual(codes(compare({ events: [] })), ['EVENT_COUNT']);
  assert.deepEqual(codes(compare({ events: [{ time: null, record: null }] })), ['EVENT_COUNT']);
  assert.deepEqual(codes(compare({ events: [goodEvent, goodEvent] })), ['EVENT_COUNT']);
});

test('a required path that is not in the documented values is a corpus error', () => {
  assert.deepEqual(codes(compare({ required: ['srcip', 'nope'] })), ['REQUIRED_NOT_IN_GOLDEN']);
});

test('generic structural source prefix is ignored when matching rows to documented paths', () => {
  const result = compare({ rows: rows.map(r => ({ ...r, source: 'parserstudio_source.' + r.source })) });
  assert.deepEqual(result.problems, []);
});

test('a Generic Structural key=value source path is matched by its documented key', () => {
  const result = compareEventToGolden({
    golden: [{ sourcePath: 'src', sourceValue: '192.0.2.1' }],
    rows: [{ source: 'parserstudio_source.generic.kv.src', target: 'srcip', vendorNamespace: false }],
    required: ['src'],
    events: [{ time: null, record: { srcip: '192.0.2.1' } }],
  });
  assert.deepEqual(result.problems, []);
});

test('a documented value is found through the first atom when the whole kv value absorbed trailing text', () => {
  const input = {
    golden: [{ sourcePath: 'dport', sourceValue: '53' }],
    rows: [
      { source: 'parserstudio_source.generic.kv.dport', target: 'dport', vendorNamespace: true },
      { source: 'parserstudio_source.generic.atoms.dport_001', target: 'dstport', vendorNamespace: false },
    ],
    required: ['dport'],
  };
  const good = compareEventToGolden({
    ...input,
    events: [{ time: null, record: { dstport: 53, cisco_meraki: { dport: '53 pattern: allow all' } } }],
  });
  assert.deepEqual(good.problems, []);
  assert.deepEqual(good.matched.map(m => m.target), ['dstport']);
  const wrong = compareEventToGolden({
    ...input,
    events: [{ time: null, record: { dstport: 80, cisco_meraki: { dport: '53 pattern: allow all' } } }],
  });
  assert.deepEqual(wrong.problems.map(p => p.code), ['REQUIRED_FIELD_VALUE_MISMATCH']);
});

test('only the first atom stands for the documented key', () => {
  const result = compareEventToGolden({
    golden: [{ sourcePath: 'dport', sourceValue: '53' }],
    rows: [{ source: 'parserstudio_source.generic.atoms.dport_002', target: 'dstport', vendorNamespace: false }],
    required: ['dport'],
    events: [{ time: null, record: { dstport: 53 } }],
  });
  assert.deepEqual(result.problems.map(p => p.code), ['REQUIRED_FIELD_UNMAPPED']);
});

test('dotted destination names resolve through nested objects', () => {
  const result = compareEventToGolden({
    golden: [{ sourcePath: 'alert.action', sourceValue: 'allowed' }],
    rows: [{ source: 'alert.action', target: 'log.action', vendorNamespace: false }],
    required: ['alert.action'],
    events: [{ time: null, record: { log: { action: 'allowed' } } }],
  });
  assert.deepEqual(result.problems, []);
});

test('documented values nobody required are listed as unmapped, not silently dropped', () => {
  const result = compare({ required: ['srcip'], rows: rows.filter(r => r.source === 'srcip') });
  assert.deepEqual(result.unrequiredUnmapped, ['srcport', 'service']);
});

const timestampCase = (expected: string, actual: unknown) => compareEventToGolden({
  golden: [{ sourcePath: 'eventTime', sourceValue: expected }],
  rows: [{ source: 'eventTime', target: 'timestamp', vendorNamespace: false }],
  required: ['eventTime'],
  events: [{ time: null, record: { timestamp: actual } }],
});

test('the same instant re-rendered with milliseconds or a colon offset is the same value', () => {
  assert.deepEqual(timestampCase('2014-07-16T15:49:27Z', '2014-07-16T15:49:27.000Z').problems, []);
  assert.deepEqual(timestampCase('2017-04-07T22:24:37.251547+0100', '2017-04-07T21:24:37.251Z').problems, []);
  assert.deepEqual(timestampCase('2017-04-07T22:24:37+0100', '2017-04-07T22:24:37+01:00').problems, []);
});

test('epoch milliseconds on the wire equal the documented instant, but only for that instant', () => {
  assert.deepEqual(timestampCase('2014-07-16T15:49:27Z', 1405525767000).problems, []);
  assert.deepEqual(timestampCase('2017-04-07T22:24:37.251547+0100', 1491600277251).problems, []);
  assert.deepEqual(codes(timestampCase('2014-07-16T15:49:27Z', 1405525768000) as never), ['REQUIRED_FIELD_VALUE_MISMATCH']);
  assert.deepEqual(codes(timestampCase('2014-07-16T15:49:27', 1405525767000) as never), ['REQUIRED_FIELD_VALUE_MISMATCH']);
  assert.deepEqual(codes(timestampCase('2014-07-16T15:49:27Z', 1405525767) as never), ['REQUIRED_FIELD_VALUE_MISMATCH']);
});

test('a different instant, a lost offset or an assumed time zone is not the same timestamp', () => {
  assert.deepEqual(codes(timestampCase('2014-07-16T15:49:27Z', '2014-07-16T15:49:28Z') as never), ['REQUIRED_FIELD_VALUE_MISMATCH']);
  assert.deepEqual(codes(timestampCase('2017-04-07T22:24:37+0100', '2017-04-07T22:24:37Z') as never), ['REQUIRED_FIELD_VALUE_MISMATCH']);
  assert.deepEqual(codes(timestampCase('2014-07-16T15:49:27', '2014-07-16T15:49:27Z') as never), ['REQUIRED_FIELD_VALUE_MISMATCH']);
  assert.deepEqual(codes(timestampCase('2014-02-31T15:49:27Z', '2014-03-03T15:49:27Z') as never), ['REQUIRED_FIELD_VALUE_MISMATCH']);
});

const RUNNER = resolve(import.meta.dirname, '../../scripts/verification/ruby-golden-event-runner.rb');
const runRuby = (cases: { id: string; ruby: string; raw: string }[]) =>
  spawnSync(process.env.PARSER_RUBY_BIN || 'ruby', [RUNNER], { input: JSON.stringify({ cases }), encoding: 'utf8', timeout: 30_000 });

test('the Ruby runner executes a compiled fragment and returns the emitted event', () => {
  const ruby = compilePair(sampleProject()).files.find(f => !f.name.endsWith('.conf'))!.content;
  const raw = JSON.stringify({ source: { ip: '192.0.2.10' }, destination: { ip: '198.51.100.5', port: 443 }, action: 'deny' });
  const run = runRuby([{ id: 'sample', ruby, raw }]);
  assert.equal(run.status, 0, run.stderr);
  const out = JSON.parse(run.stdout) as { ruby: string; results: Record<string, { calls: [unknown, Record<string, unknown>][] }> };
  const calls = out.results.sample!.calls;
  assert.equal(calls.length, 1);
  assert.equal(calls[0]![1].srcip, '192.0.2.10');
  assert.equal(calls[0]![1].dstport, 443);
  const result = compareEventToGolden({
    golden: [{ sourcePath: 'source.ip', sourceValue: '192.0.2.10' }, { sourcePath: 'destination.port', sourceValue: 443 }],
    rows: [
      { source: 'source.ip', target: 'srcip', vendorNamespace: false },
      { source: 'destination.port', target: 'dstport', vendorNamespace: false },
    ],
    required: ['source.ip', 'destination.port'],
    events: calls.map(([time, record]) => ({ time, record })),
  });
  assert.deepEqual(result.problems, []);
});

test('the Ruby runner fails loudly on a fragment that does not load', () => {
  const run = runRuby([{ id: 'broken', ruby: 'def parse(', raw: '{}' }]);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /FRAGMENT_LOAD_FAILED broken/);
});

test('the Ruby runner source stays Ruby 2.4 compatible (no endless def, no numbered params)', () => {
  const text = spawnSync('cat', [join(RUNNER)], { encoding: 'utf8' }).stdout;
  assert.doesNotMatch(text, /^\s*def [^\n]*\)\s*=\s/m);
  assert.doesNotMatch(text, /\b_1\b|\bit\b\./);
});
