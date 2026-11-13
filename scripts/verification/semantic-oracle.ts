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
import { compileRule } from '../grammar/generate-grammar.mjs';
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
const TS_MUTANTS: Mutant[] = [
  { id: 'ts-hostname-wrong-capture', file: 'src/structuredFamilies.ts', find: ' syslog_hostname:match[7],', replace: ' syslog_hostname:match[2],' },
  { id: 'ts-pri-range-dropped', file: 'src/structuredFamilies.ts', find: '(priority!==undefined&&priority>191)||', replace: '' },
  { id: 'ts-calendar-widened', file: 'src/structuredFamilies.ts', find: 'day>DAYS[month]', replace: 'day>31' },
  { id: 'ts-body-fields-dropped', file: 'src/structuredFamilies.ts', find: 'return body.errors.length?body:{fields:{...fields,...body.fields},errors:[]};', replace: 'return body.errors.length?body:{fields:{...fields},errors:[]};' },
  { id: 'ts-procid-wrong-capture', file: 'src/structuredFamilies.ts', find: 'syslog_procid:match[9]', replace: 'syslog_procid:match[8]' },
  { id: 'ts-tagged-first-field-lost', file: 'src/structuredFamilies.ts', find: 'const message=tagged?match[10]!:match[8]!;', replace: "const message=tagged?match[10]!.replace(/^\\S+ /,''):match[8]!;" },
  { id: 'ts-rfc5424-any-version', file: 'src/rfc5424Subset.ts', find: " || match[2]!=='1'", replace: '' },
  { id: 'ts-rfc5424-appname-procid-swapped', file: 'src/rfc5424Subset.ts', find: 'syslog_appname:match[5],syslog_procid:match[6],', replace: 'syslog_appname:match[6],syslog_procid:match[5],' },
];

function applyMutant(text: string, mutant: Mutant): string {
  if (text.split(mutant.find).length !== 2) throw new Error(`MUTANT_NOT_APPLICABLE ${mutant.id}: target text must occur exactly once in ${mutant.file}`);
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
    if (mutant) {
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
const RUBY_MUTANTS: Array<Mutant & { grammar: OracleCase['grammar'] }> = [
  { id: 'rb-pri-range-widened', grammar: 'syslog_rfc3164', file: 'fragment', find: '!priority.between?(0, 191)', replace: '!priority.between?(0, 999)' },
  { id: 'rb-calendar-widened', grammar: 'syslog_rfc3164', file: 'fragment', find: 'day.between?(1, days) && hour.between?(0, 23)', replace: 'day.between?(1, 31) && hour.between?(0, 23)' },
  { id: 'rb-tagged-first-field-lost', grammar: 'syslog_rfc3164', file: 'fragment', find: '    message = match[10]\n', replace: "    message = match[10].sub(/\\A\\S+ /, '')\n" },
  { id: 'rb-hostname-wrong-capture', grammar: 'syslog_rfc3164', file: 'fragment', find: "'syslog_hostname' => match[7]", replace: "'syslog_hostname' => match[2]" },
  { id: 'rb-rfc5424-any-version', grammar: 'syslog_rfc5424', file: 'fragment', find: "unless match[2] == '1'", replace: 'unless match[2] =~ /\\A[0-9]+\\z/' },
];

function compileFragment(grammar: OracleCase['grammar']): string {
  const profile = goldens.profiles['fw-kv']!;
  const fields = (spec: FieldSpec) => Object.fromEntries(Object.entries(spec).map(([source, [name, type]]) => [source, { normalized_name: name, data_type: type }]));
  const project = sampleProject() as unknown as Record<string, any>;
  project.extraction = { format: grammar, syslogBodyFormat: 'kv' };
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
  for (const mutant of RUBY_MUTANTS) {
    fragments[mutant.id] = applyMutant(fragments[mutant.grammar]!, mutant);
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
  const ok = product.failures.length === 0 && survivors.length === 0 && dialectDrift.length === 0 && dialectMatches > 0;
  process.stdout.write(`GRAMMAR_DIALECT_EQUIVALENCE ruby=${output.ruby} rules=${ruleNames.length} lines=${grammarLines.length} matches=${dialectMatches} drift=${dialectDrift.length}\n`);
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_NATIVE_PASS' : 'SEMANTIC_ORACLE_NATIVE_FAIL'} ruby=${output.ruby} goldens=${goldens.cases.length} properties=${cases.length - goldens.cases.length} passed=${product.passed} expected_failures=${product.expectedFailures} mutants_killed=${RUBY_MUTANTS.length - survivors.length}/${RUBY_MUTANTS.length}\n`);
  return ok ? 0 : 1;
}

const mode = process.argv[2];
if (mode === 'ts') process.exit(await runTs());
else if (mode === 'native') process.exit(runNative());
else { process.stderr.write('usage: semantic-oracle.ts ts|native\n'); process.exit(2); }
