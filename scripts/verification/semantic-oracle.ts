// Semantic Correctness Oracle with fault injection.
//
// Compares BOTH executors with independently authored expectations instead of
// with each other:
//   - hand-written goldens (contracts/semantic-goldens.v1.json),
//   - model-rendered property cases (src/grammar/syslogHeaderModel.ts),
// and then proves the gate can detect new defects by injecting faults into the
// product source (TypeScript) or into the generated artifact (Ruby) and
// requiring every injected fault to be reported.
//
//   semantic-oracle.ts ts      browser TypeScript executor
//   semantic-oracle.ts native  generated Ruby Fragment executed by `ruby`
//                              (must be Ruby 2.4.9 unless PARSER_STUDIO_EXPECT_RUBY overrides)
//
// A case tagged knownDefect is a strict expected failure for the engines listed
// in the registry: it must still fail (the defect is real and detected) and the
// gate fails when it starts to pass, so the tag cannot outlive the fix.
// Scope: Parser Studio output only; no Stellar Cyber import, reception or indexing.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { extractStructuredFamily } from '../../src/structuredFamilies';
import { parseSyslogEnvelope } from '../../src/syslogEnvelope';
import { classifyStructuredParse } from '../../src/grammar/parseStatus';
import { generateRfc3164KvCases, type OracleCase } from '../../src/grammar/syslogHeaderModel';
import { matchHeaderRule } from '../../src/grammar/syslogHeader';
import { SYSLOG_HEADER_RULES, type SyslogHeaderRuleName } from '../../src/grammar/syslogHeaderGrammar.generated';
// @ts-expect-error plain ESM generator without type declarations
import { CONTRACT_PATH, GENERATED_PYTHON_PATH, compileRule, generatePython, generateTypeScript, rubyGrammarPlaceholders } from '../grammar/generate-grammar.mjs';
import { compilePair } from '../../backend/src/compiler.js';
import { sampleProject } from '../../backend/test/fixture.js';

type Engine = 'ts' | 'ruby';
type Extract = (raw: string, grammar: string, body: string) => { fields: Record<string, unknown>; errors: string[] };
interface FieldSpec { [source: string]: [string, string] }
interface Profile { topFields: FieldSpec; vendorFields: FieldSpec; classification: unknown }
interface EnvelopeCase { id: string; raw: string; knownDefect?: string; expect: { variant?: string; variantNot?: string } }
interface Goldens {
  profiles: Record<string, Profile>;
  knownDefects: Record<string, { engines: Engine[] }>;
  cases: OracleCase[];
  envelopeCases: EnvelopeCase[];
}
interface RubyResult { calls?: Array<[unknown, Record<string, unknown> | null]>; raised?: string }
interface Mutant { id: string; file: string; find: string; replace: string }

const REPO = resolve('.');
const goldens = JSON.parse(readFileSync(join(REPO, 'contracts/semantic-goldens.v1.json'), 'utf8')) as Goldens;
const PROPERTY_SEED = 20261113;

const deepGet = (value: unknown, path: string): unknown =>
  path.split('.').reduce<unknown>((node, key) => (node !== null && typeof node === 'object' ? (node as Record<string, unknown>)[key] : undefined), value);
const same = (left: unknown, right: unknown) => JSON.stringify(left) === JSON.stringify(right);
const sortKeys = (value: Record<string, unknown> | null) =>
  value === null ? null : Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]));

/** The goldens must be readable off the raw line: an expected source value that is not in the raw text was not authored independently. */
function goldenSelfCheck(): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  for (const item of [...goldens.cases, ...goldens.envelopeCases]) {
    if (ids.has(item.id)) problems.push(`duplicate golden id ${item.id}`);
    ids.add(item.id);
    if (item.knownDefect && !goldens.knownDefects[item.knownDefect]) problems.push(`${item.id}: unknown defect ${item.knownDefect}`);
  }
  for (const item of goldens.cases) {
    if (!item.provenance) problems.push(`${item.id}: provenance missing`);
    for (const [path, value] of Object.entries(item.expect.source ?? {}))
      if (!item.raw.includes(String(value))) problems.push(`${item.id}: expected ${path} is not literal raw text`);
  }
  return problems;
}

function evaluateTs(item: OracleCase, extract: Extract): string[] {
  let outcome: { fields: Record<string, unknown>; errors: string[] } | { thrown: unknown };
  try { outcome = extract(item.raw, item.grammar, item.body); } catch (error) { outcome = { thrown: error }; }
  const verdict = classifyStructuredParse(item.raw, outcome, item.body);
  const expect = item.expect;
  if (expect.status === 'UNKNOWN') return verdict.status === 'UNKNOWN' ? [] : [`status ${verdict.status}, expected UNKNOWN`];
  const problems: string[] = [];
  if (verdict.status !== 'FULL') {
    if (expect.neverWrong && verdict.status === 'UNKNOWN') return [];
    problems.push(`status ${verdict.status}, expected FULL (${verdict.reasons.join('; ')})`);
    if (verdict.status !== 'PARTIAL') return problems;
  }
  const fields = 'fields' in outcome ? outcome.fields : {};
  for (const [path, want] of Object.entries(expect.source ?? {})) {
    const got = deepGet(fields, path);
    if (!same(got, want)) problems.push(`source ${path}=${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);
  }
  for (const path of expect.sourceAbsent ?? [])
    if (deepGet(fields, path) !== undefined) problems.push(`source ${path}=${JSON.stringify(deepGet(fields, path))} must be absent`);
  return problems;
}

function evaluateRuby(item: OracleCase, result: RubyResult | undefined): string[] {
  if (!result) return ['no result from the Ruby runner'];
  if (result.raised) return [`artifact raised ${result.raised}`];
  const events = (result.calls ?? []).filter(([time, record]) =>
    time !== null && record !== null && typeof record === 'object' && record.parser_err_msg === undefined);
  const expect = item.expect;
  if (expect.status === 'UNKNOWN' || expect.event === null)
    return events.length === 0 ? [] : [`emitted ${events.length} parsed event(s), expected none`];
  if (events.length === 0) return expect.neverWrong ? [] : ['no parsed event'];
  const problems: string[] = [];
  if (events.length !== 1) problems.push(`${events.length} parsed events, expected 1`);
  const record = events[0]![1];
  for (const [path, want] of Object.entries(expect.event ?? {})) {
    const got = deepGet(record, path);
    if (!same(got, want)) problems.push(`event ${path}=${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);
  }
  for (const path of expect.eventAbsent ?? [])
    if (deepGet(record, path) !== undefined) problems.push(`event ${path}=${JSON.stringify(deepGet(record, path))} must be absent`);
  return problems;
}

interface Score { failures: string[]; passed: number; expectedFailures: number }
function score(engine: Engine, cases: OracleCase[], evaluate: (item: OracleCase) => string[]): Score {
  const out: Score = { failures: [], passed: 0, expectedFailures: 0 };
  for (const item of cases) {
    const problems = evaluate(item);
    const expectedToFail = !!item.knownDefect && goldens.knownDefects[item.knownDefect]!.engines.includes(engine);
    if (expectedToFail) {
      if (problems.length === 0) out.failures.push(`XFAIL_NOW_PASSING ${item.id} (${item.knownDefect}): remove the knownDefect tag`);
      else out.expectedFailures += 1;
    } else if (problems.length > 0) out.failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
    else out.passed += 1;
  }
  return out;
}
const realFailures = (result: Score) => result.failures.filter(line => !line.startsWith('XFAIL_NOW_PASSING'));

function report(label: string, failures: string[]): void {
  for (const line of failures.slice(0, 25)) process.stderr.write(`${label}: ${line}\n`);
  if (failures.length > 25) process.stderr.write(`${label}: ... ${failures.length - 25} more\n`);
}

// ---------------------------------------------------------------- TypeScript
// A mutant either edits one product source file or, with file 'contract', edits the grammar contract and
// regenerates its consumers: the second kind proves that a wrong contract cannot ship either.
const CONTRACT_MUTANTS: Mutant[] = [
  // Re-introduces F-1: HOSTNAME may again swallow a key=value token.
  { id: 'contract-hostname-any-printable', file: 'contract', find: '"pattern": "(?!\\\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-9;<>-~]"', replace: '"pattern": "[!-~]{1,255}"' },
  // A TAG such as "kernel:" may again be read as the host name.
  { id: 'contract-hostname-trailing-colon', file: 'contract', find: '[!-<>-~]{0,254}[!-9;<>-~]"', replace: '[!-<>-~]{0,254}[!-<>-~]"' },
  { id: 'contract-rest-ascii-only', file: 'contract', find: '"REST": { "pattern": "[^\\\\r\\\\n]+"', replace: '"REST": { "pattern": "[!-~ ]+"' },
  { id: 'contract-hostless-rule-removed', file: 'contract', find: '[ "rfc3164_tagged", "rfc3164_tagless", "rfc3164_hostless" ]', replace: '[ "rfc3164_tagged", "rfc3164_tagless" ]' },
];
const TS_MUTANTS: Mutant[] = [
  ...CONTRACT_MUTANTS,
  { id: 'ts-hostname-wrong-capture', file: 'src/structuredFamilies.ts', find: 'syslog_hostname:header.hostname', replace: 'syslog_hostname:header.timestamp' },
  { id: 'ts-body-fields-dropped', file: 'src/structuredFamilies.ts', find: 'return body.errors.length?body:{fields:{...fields,...body.fields},errors:[]};', replace: 'return body.errors.length?body:{fields:{...fields},errors:[]};' },
  { id: 'ts-procid-wrong-capture', file: 'src/structuredFamilies.ts', find: 'syslog_procid:header.procid', replace: 'syslog_procid:header.tag' },
  { id: 'ts-tagged-first-field-lost', file: 'src/structuredFamilies.ts', find: ' const message=header.message;', replace: " const message=tagged?header.message.replace(/^\\S+ /,''):header.message;" },
  { id: 'ts-pri-range-dropped', file: 'src/grammar/syslogHeader.ts', find: 'pri !== undefined && pri > SYSLOG_HEADER_SEMANTICS.priMax', replace: 'false' },
  { id: 'ts-calendar-widened', file: 'src/grammar/syslogHeader.ts', find: 'day < 1 || day > days ||', replace: 'day < 1 || day > 31 ||' },
  { id: 'ts-rfc5424-any-version', file: 'src/grammar/syslogHeader.ts', find: 'if (!isSupportedRfc5424Version(captures.version!)) return', replace: 'if (false) return' },
  { id: 'ts-rfc5424-appname-procid-swapped', file: 'src/rfc5424Subset.ts', find: 'syslog_appname:header.appname,syslog_procid:header.procid,', replace: 'syslog_appname:header.procid,syslog_procid:header.appname,' },
];

function applyMutant(text: string, mutant: Mutant): string {
  if (text.split(mutant.find).length !== 2) throw new Error(`MUTANT_NOT_APPLICABLE ${mutant.id}: target text must occur exactly once in ${mutant.file}`);
  if (mutant.replace === mutant.find) throw new Error(`MUTANT_IS_IDENTITY ${mutant.id}`);
  return text.replace(mutant.find, () => mutant.replace);
}

/** Loads the product extractor from a private copy of src/, optionally with one injected fault. */
async function extractorFromCopy(mutant: Mutant | null): Promise<{ extract: Extract; dispose: () => void }> {
  const root = mkdtempSync(join(REPO, '.oracle-mutant-'));
  const source = join(REPO, 'src');
  cpSync(source, join(root, 'src'), {
    recursive: true,
    filter: path => {
      const rel = relative(source, path);
      if (rel === '') return true;
      if (statSync(path).isDirectory()) return rel === 'grammar';
      return /\.ts$/.test(path) && !/\.test\.ts$/.test(path);
    },
  });
  // src/ reaches shared contracts and backend/src modules through relative paths.
  for (const shared of ['contracts', 'backend']) symlinkSync(join(REPO, shared), join(root, shared));
  const dispose = () => rmSync(root, { recursive: true, force: true });
  try {
    if (mutant && mutant.file === 'contract') {
      const mutated = applyMutant(readFileSync(join(REPO, CONTRACT_PATH), 'utf8'), mutant);
      writeFileSync(join(root, 'src/grammar/syslogHeaderGrammar.generated.ts'), generateTypeScript(mutated) as string);
    } else if (mutant) {
      const target = join(root, mutant.file);
      writeFileSync(target, applyMutant(readFileSync(target, 'utf8'), mutant));
    }
    const module = await import(pathToFileURL(join(root, 'src/structuredFamilies.ts')).href) as { extractStructuredFamily: Extract };
    return { extract: module.extractStructuredFamily, dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}

async function runTs(): Promise<number> {
  const selfCheck = goldenSelfCheck();
  if (selfCheck.length) { report('GOLDEN_SELF_CHECK', selfCheck); return 1; }
  const properties = generateRfc3164KvCases(300, PROPERTY_SEED);
  const cases = [...goldens.cases, ...properties];
  const product = score('ts', cases, item => evaluateTs(item, extractStructuredFamily as Extract));
  const envelopeFailures: string[] = [];
  let envelopeExpected = 0;
  for (const item of goldens.envelopeCases) {
    const variant = parseSyslogEnvelope(item.raw)?.variant;
    const wrong = (item.expect.variant !== undefined && variant !== item.expect.variant) ||
      (item.expect.variantNot !== undefined && variant === item.expect.variantNot);
    const expectedToFail = !!item.knownDefect && goldens.knownDefects[item.knownDefect]!.engines.includes('ts');
    if (expectedToFail && !wrong) envelopeFailures.push(`XFAIL_NOW_PASSING ${item.id} (${item.knownDefect}): remove the knownDefect tag`);
    else if (expectedToFail) envelopeExpected += 1;
    else if (wrong) envelopeFailures.push(`${item.id}: envelope variant ${String(variant)}`);
  }
  report('SEMANTIC_ORACLE_TS', [...product.failures, ...envelopeFailures]);

  // Fault injection: an unmutated private copy must behave like the product, every mutant must be reported.
  const baseline = await extractorFromCopy(null);
  const baselineScore = score('ts', cases, item => evaluateTs(item, baseline.extract));
  baseline.dispose();
  const harnessBroken = !same(baselineScore, product);
  if (harnessBroken) process.stderr.write('FAULT_INJECTION_HARNESS_INVALID: the unmutated copy does not reproduce the product result\n');
  const survivors: string[] = [];
  for (const mutant of TS_MUTANTS) {
    const loaded = await extractorFromCopy(mutant);
    const mutated = score('ts', cases, item => evaluateTs(item, loaded.extract));
    loaded.dispose();
    const killed = realFailures(mutated).length > realFailures(product).length;
    process.stdout.write(`TS_MUTANT ${mutant.id} ${killed ? 'KILLED' : 'SURVIVED'} failing_cases=${realFailures(mutated).length}\n`);
    if (!killed) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  const ok = product.failures.length === 0 && envelopeFailures.length === 0 && !harnessBroken && survivors.length === 0;
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_TS_PASS' : 'SEMANTIC_ORACLE_TS_FAIL'} goldens=${goldens.cases.length} envelope=${goldens.envelopeCases.length} properties=${properties.length} passed=${product.passed} expected_failures=${product.expectedFailures + envelopeExpected} mutants_killed=${TS_MUTANTS.length - survivors.length}/${TS_MUTANTS.length}\n`);
  return ok ? 0 : 1;
}

// ---------------------------------------------------------------------- Ruby
const RUBY_MUTANTS: Array<Mutant & { grammar: OracleCase['grammar']; target?: string }> = [
  // Forwarder-family template: the relay probe must not reject a direct event that has no TAG.
  { id: 'rb-forwarder-probe-rejects-tagless', grammar: 'syslog_rfc3164', target: 'forwarder:syslog_rfc3164', file: 'fragment', find: "{'syslogBodyFormat'=>'raw','taglessStructuredRouter'=>true}", replace: "{'syslogBodyFormat'=>'raw'}" },
  ...CONTRACT_MUTANTS.map(mutant => ({ ...mutant, grammar: 'syslog_rfc3164' as const })),
  { id: 'rb-pri-range-widened', grammar: 'syslog_rfc3164', file: 'fragment', find: "'RFC3164 PRI out of range' if priority && !priority.between?(0, 191)", replace: "'RFC3164 PRI out of range' if priority && !priority.between?(0, 999)" },
  { id: 'rb-calendar-widened', grammar: 'syslog_rfc3164', file: 'fragment', find: 'day.between?(1, days) && hour.between?(0, 23)', replace: 'day.between?(1, 31) && hour.between?(0, 23)' },
  { id: 'rb-tagged-first-field-lost', grammar: 'syslog_rfc3164', file: 'fragment', find: "  message = header['message']\n", replace: "  message = tagged ? header['message'].sub(/\\A\\S+ /, '') : header['message']\n" },
  { id: 'rb-hostname-wrong-capture', grammar: 'syslog_rfc3164', file: 'fragment', find: "record['syslog_hostname'] = header['hostname'] if header['hostname']", replace: "record['syslog_hostname'] = header['month'] if header['hostname']" },
  { id: 'rb-rfc5424-any-version', grammar: 'syslog_rfc5424', file: 'fragment', find: "raise ArgumentError, 'Unsupported RFC5424 version' unless ['1'].include?(header['version'])", replace: "raise ArgumentError, 'Unsupported RFC5424 version' unless header['version']" },
];

/** Applies a mutant to a compiled Fragment; a contract mutant swaps the injected grammar for the mutated contract's grammar. */
function mutateFragment(fragment: string, mutant: Mutant): string {
  if (mutant.file !== 'contract') return applyMutant(fragment, mutant);
  const contractText = readFileSync(join(REPO, CONTRACT_PATH), 'utf8');
  const before = rubyGrammarPlaceholders(contractText) as Record<string, string>;
  const after = rubyGrammarPlaceholders(applyMutant(contractText, mutant)) as Record<string, string>;
  let out = fragment;
  let changed = 0;
  for (const [placeholder, source] of Object.entries(before)) {
    if (after[placeholder] === source || !out.includes(source)) continue;
    out = out.split(source).join(after[placeholder]!);
    changed += 1;
  }
  if (changed === 0) throw new Error(`MUTANT_NOT_APPLICABLE ${mutant.id}: the mutated contract does not change this Fragment`);
  return out;
}

function compileFragment(grammar: OracleCase['grammar'], forwarder = false): string {
  const profile = goldens.profiles['fw-kv']!;
  const fields = (spec: FieldSpec) => Object.fromEntries(Object.entries(spec).map(([source, [name, type]]) => [source, { normalized_name: name, data_type: type }]));
  const project = sampleProject() as unknown as Record<string, any>;
  // A declared forwarder selects the forwarder-family template; direct events must parse exactly the same.
  project.extraction = { format: grammar, syslogBodyFormat: 'kv', ...(forwarder ? { forwarder: { maxHops: 2, relayHosts: ['oracle-relay'] } } : {}) };
  project.normalization.topFields = fields(profile.topFields);
  project.normalization.nsFields = {};
  project.normalization.vendorFields = fields(profile.vendorFields);
  project.classification = profile.classification;
  const ruby = compilePair(project).files.find(file => !file.name.endsWith('.conf'));
  if (!ruby) throw new Error('compilePair returned no Ruby Fragment');
  return ruby.content;
}

function runNative(): number {
  const selfCheck = goldenSelfCheck();
  if (selfCheck.length) { report('GOLDEN_SELF_CHECK', selfCheck); return 1; }
  const expectedRuby = process.env.PARSER_STUDIO_EXPECT_RUBY ?? '2.4.9';
  const cases = [...goldens.cases, ...generateRfc3164KvCases(60, PROPERTY_SEED)];
  const mutantCases = [...goldens.cases, ...generateRfc3164KvCases(15, PROPERTY_SEED)];
  const fragments: Record<string, string> = {
    syslog_rfc3164: compileFragment('syslog_rfc3164'),
    syslog_rfc5424: compileFragment('syslog_rfc5424'),
  };
  const payloadCases = cases.map(item => ({ id: item.id, fragment: item.grammar, raw: item.raw }));
  for (const grammar of ['syslog_rfc3164', 'syslog_rfc5424'] as const) {
    fragments[`forwarder:${grammar}`] = compileFragment(grammar, true);
    if (fragments[`forwarder:${grammar}`] === fragments[grammar]) throw new Error('FORWARDER_TEMPLATE_NOT_SELECTED');
  }
  for (const item of cases) payloadCases.push({ id: `forwarder::${item.id}`, fragment: `forwarder:${item.grammar}`, raw: item.raw });
  for (const mutant of RUBY_MUTANTS) {
    fragments[mutant.id] = mutateFragment(fragments[mutant.target ?? mutant.grammar]!, mutant);
    for (const item of mutantCases)
      if (item.grammar === mutant.grammar) payloadCases.push({ id: `${mutant.id}::${item.id}`, fragment: mutant.id, raw: item.raw });
  }
  // Grammar dialect equivalence: the contract's Ruby regular expressions must capture exactly what its
  // ECMAScript regular expressions capture, on the target Ruby, for every golden and property line.
  const contract = JSON.parse(readFileSync(join(REPO, 'contracts/syslog-header-grammar.v1.json'), 'utf8'));
  const ruleNames = Object.keys(SYSLOG_HEADER_RULES) as SyslogHeaderRuleName[];
  const rubyRules = Object.fromEntries(ruleNames.map(name => [name, (compileRule(contract, name, 'ruby') as { source: string }).source]));
  const grammarLines = [...new Set([...cases.map(item => item.raw), ...goldens.envelopeCases.map(item => item.raw)])];
  const runner = readFileSync(join(REPO, 'scripts/verification/semantic-oracle-runner.rb'), 'utf8');
  const run = spawnSync('ruby', ['-e', runner], {
    input: JSON.stringify({ fragments, cases: payloadCases, grammar: { rules: rubyRules, lines: grammarLines } }),
    encoding: 'utf8', maxBuffer: 1 << 28, timeout: 240000,
  });
  if (run.status !== 0) {
    process.stderr.write(`SEMANTIC_ORACLE_RUBY_RUNNER_FAILED status=${String(run.status)} ${String(run.stderr).slice(0, 600)}\n`);
    return 1;
  }
  const output = JSON.parse(run.stdout) as { ruby: string; results: Record<string, RubyResult>; grammar: Record<string, Array<Record<string, string | null> | null>> };
  if (output.ruby !== expectedRuby) {
    process.stderr.write(`SEMANTIC_ORACLE_RUBY_VERSION_MISMATCH expected=${expectedRuby} actual=${output.ruby}\n`);
    return 1;
  }
  const dialectDrift: string[] = [];
  let dialectMatches = 0;
  for (const name of ruleNames) {
    grammarLines.forEach((line, index) => {
      const js = matchHeaderRule(name, line);
      const expected = js === null ? null : Object.fromEntries(Object.entries(js).map(([key, value]) => [key, value ?? null]));
      const actual = output.grammar[name]?.[index];
      if (actual === undefined || !same(sortKeys(expected), sortKeys(actual))) dialectDrift.push(`${name}: ${JSON.stringify(line).slice(0, 120)}`);
      else if (expected !== null) dialectMatches += 1;
    });
  }
  report('GRAMMAR_DIALECT_DRIFT', dialectDrift);
  const product = score('ruby', cases, item => evaluateRuby(item, output.results[item.id]));
  report('SEMANTIC_ORACLE_NATIVE', product.failures);
  const forwarder = score('ruby', cases, item => evaluateRuby(item, output.results[`forwarder::${item.id}`]));
  report('SEMANTIC_ORACLE_NATIVE_FORWARDER_TEMPLATE', forwarder.failures);
  const productFailing = new Set(cases.filter(item => evaluateRuby(item, output.results[item.id]).length > 0).map(item => item.id));
  const survivors: string[] = [];
  for (const mutant of RUBY_MUTANTS) {
    // Killed = at least one case that the unmutated artifact gets right is reported for the mutant.
    const reported = mutantCases.filter(item => item.grammar === mutant.grammar && !productFailing.has(item.id) &&
      evaluateRuby(item, output.results[`${mutant.id}::${item.id}`]).length > 0).length;
    process.stdout.write(`RUBY_MUTANT ${mutant.id} ${reported > 0 ? 'KILLED' : 'SURVIVED'} failing_cases=${reported}\n`);
    if (reported === 0) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  const ok = product.failures.length === 0 && forwarder.failures.length === 0 && survivors.length === 0 && dialectDrift.length === 0 && dialectMatches > 0;
  process.stdout.write(`FORWARDER_TEMPLATE_DIRECT_EVENTS passed=${forwarder.passed} failed=${forwarder.failures.length}\n`);
  process.stdout.write(`GRAMMAR_DIALECT_EQUIVALENCE ruby=${output.ruby} rules=${ruleNames.length} lines=${grammarLines.length} matches=${dialectMatches} drift=${dialectDrift.length}\n`);
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_NATIVE_PASS' : 'SEMANTIC_ORACLE_NATIVE_FAIL'} ruby=${output.ruby} goldens=${goldens.cases.length} properties=${cases.length - goldens.cases.length} passed=${product.passed} expected_failures=${product.expectedFailures} mutants_killed=${RUBY_MUTANTS.length - survivors.length}/${RUBY_MUTANTS.length}\n`);
  return ok ? 0 : 1;
}

// -------------------------------------------------------------------- Python
interface PythonEnvelope { syslog: Record<string, string>; start: number }
interface PythonOutput { python: string; envelope: Array<PythonEnvelope | null>; rfc5424: Record<string, Record<string, boolean>> }
const RFC5424_VERSION_PROBES = ['1', '2', '12', '999', '0', '01'];
const PYTHON_MUTANTS: Mutant[] = [
  ...CONTRACT_MUTANTS.filter(mutant => mutant.id.startsWith('contract-hostname')),
  { id: 'contract-version-2-supported', file: 'contract', find: '"rfc5424SupportedVersions": [ "1" ]', replace: '"rfc5424SupportedVersions": [ "1", "2" ]' },
];

/** The Multi-Pass envelope pass reads the header only: host name, PRI and where the structured payload starts. */
function evaluatePythonEnvelope(item: OracleCase, result: PythonEnvelope | null | undefined): string[] {
  if (result === undefined) return ['no result from the Python runner'];
  const expect = item.expect;
  if (expect.status === 'UNKNOWN') return result === null ? [] : [`envelope ${JSON.stringify(result.syslog)}, expected none`];
  const tagged = expect.source?.syslog_appname !== undefined;
  // A colon-terminated TAG followed by SP is handled by another pass; declining is correct, a wrong host is not.
  if (result === null) return tagged || expect.neverWrong ? [] : ['no envelope'];
  const problems: string[] = [];
  // A field is checked when the expectation states it, either as a value or as absent.
  const stated = (key: string) => expect.source?.[key] !== undefined || (expect.sourceAbsent ?? []).includes(key);
  const wantHost = expect.source?.syslog_hostname;
  if (stated('syslog_hostname') && result.syslog.hostname !== wantHost)
    problems.push(`hostname=${JSON.stringify(result.syslog.hostname)}, expected ${JSON.stringify(wantHost)}`);
  const wantPri = expect.source?.syslog_pri;
  const gotPri = result.syslog.pri === undefined ? undefined : Number(result.syslog.pri);
  if (stated('syslog_pri') && gotPri !== wantPri) problems.push(`pri=${String(gotPri)}, expected ${String(wantPri)}`);
  const firstBodyKey = Object.keys(expect.source ?? {}).find(key => key.startsWith('body.'));
  if (!tagged && firstBodyKey) {
    const wantStart = item.raw.indexOf(firstBodyKey.slice(5) + '=');
    if (result.start !== wantStart) problems.push(`payload starts at ${result.start}, expected ${wantStart}`);
  }
  return problems;
}

function pythonRun(moduleDir: string, cases: OracleCase[]): PythonOutput {
  const run = spawnSync('python3', [join(REPO, 'scripts/verification/semantic-oracle-python-runner.py')], {
    input: JSON.stringify({ moduleDir, lines: cases.map(item => item.raw), versions: RFC5424_VERSION_PROBES }),
    encoding: 'utf8', maxBuffer: 1 << 28, timeout: 120000,
  });
  if (run.status !== 0) throw new Error(`SEMANTIC_ORACLE_PYTHON_RUNNER_FAILED ${String(run.stderr).slice(-600)}`);
  return JSON.parse(run.stdout) as PythonOutput;
}

function pythonFailures(output: PythonOutput, cases: OracleCase[]): string[] {
  const failures = score('ruby', cases, (item) => evaluatePythonEnvelope(item, output.envelope[cases.indexOf(item)])).failures;
  const supported = (JSON.parse(readFileSync(join(REPO, CONTRACT_PATH), 'utf8')) as { semantics: { rfc5424SupportedVersions: string[] } }).semantics.rfc5424SupportedVersions;
  for (const version of RFC5424_VERSION_PROBES)
    for (const [entryPoint, accepted] of Object.entries(output.rfc5424[version] ?? {}))
      if (accepted !== supported.includes(version)) failures.push(`RFC 5424 VERSION ${version}: ${entryPoint} ${accepted ? 'accepted' : 'rejected'} it`);
  if (Object.keys(output.rfc5424).length !== RFC5424_VERSION_PROBES.length) failures.push('RFC 5424 VERSION probes missing');
  return failures;
}

function runPython(): number {
  const selfCheck = goldenSelfCheck();
  if (selfCheck.length) { report('GOLDEN_SELF_CHECK', selfCheck); return 1; }
  const cases = [...goldens.cases, ...generateRfc3164KvCases(120, PROPERTY_SEED)].filter(item => item.grammar === 'syslog_rfc3164');
  const index = new Map(cases.map((item, position) => [item, position]));
  const failuresOf = (output: PythonOutput) => {
    const failures = score('ruby', cases, item => evaluatePythonEnvelope(item, output.envelope[index.get(item)!])).failures;
    return [...failures, ...pythonFailures({ ...output, envelope: [] }, [])];
  };
  const moduleDir = join(REPO, 'runtime/multipass');
  const product = pythonRun(moduleDir, cases);
  const productFailures = failuresOf(product);
  report('SEMANTIC_ORACLE_PYTHON', productFailures);
  const survivors: string[] = [];
  for (const mutant of PYTHON_MUTANTS) {
    const root = mkdtempSync(join(REPO, '.oracle-mutant-'));
    try {
      cpSync(moduleDir, join(root, 'multipass'), { recursive: true, filter: path => !path.includes('__pycache__') });
      const mutated = applyMutant(readFileSync(join(REPO, CONTRACT_PATH), 'utf8'), mutant);
      writeFileSync(join(root, 'multipass', (GENERATED_PYTHON_PATH as string).split('/').pop()!), generatePython(mutated) as string);
      const failures = failuresOf(pythonRun(join(root, 'multipass'), cases));
      const killed = failures.length > productFailures.length;
      process.stdout.write(`PYTHON_MUTANT ${mutant.id} ${killed ? 'KILLED' : 'SURVIVED'} failing=${failures.length}\n`);
      if (!killed) survivors.push(mutant.id);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  const ok = productFailures.length === 0 && survivors.length === 0;
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_PYTHON_PASS' : 'SEMANTIC_ORACLE_PYTHON_FAIL'} python=${product.python} envelope_cases=${cases.length} version_probes=${RFC5424_VERSION_PROBES.length}x4 mutants_killed=${PYTHON_MUTANTS.length - survivors.length}/${PYTHON_MUTANTS.length}\n`);
  return ok ? 0 : 1;
}

const mode = process.argv[2];
if (mode === 'ts') process.exit(await runTs());
else if (mode === 'native') process.exit(runNative());
else if (mode === 'python') process.exit(runPython());
else { process.stderr.write('usage: semantic-oracle.ts ts|native|python\n'); process.exit(2); }
