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
import { extractGenericStructural } from '../../src/genericStructural';
import { classifyStructuredParse } from '../../src/grammar/parseStatus';
import { generateRfc3164KvCases, type OracleCase } from '../../src/grammar/syslogHeaderModel';
import { generateKvBodyCases } from '../../src/grammar/kvBodyModel';
import { generateCefLeefCases, type FamilyCase } from '../../src/grammar/cefLeefModel';
import { generateCsvCases, type CsvCase } from '../../src/grammar/csvModel';
import { extractFields } from '../../src/parser';
import { createDraft } from '../../src/model';
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
interface EnvelopeCase { id: string; raw: string; knownDefect?: string; expect: { variant?: string; variantNot?: string; message?: string } }
interface GenericCase { id: string; raw: string; provenance: string; expect: { fields?: Record<string, unknown>; reject?: boolean } }
interface Goldens {
  profiles: Record<string, Profile>;
  knownDefects: Record<string, { engines: Engine[] }>;
  /** A documented, owner-visible difference between engines; the oracle pins both sides exactly. */
  policyDivergences: Record<string, { engines: Engine[]; variant: string; statement: string }>;
  cases: OracleCase[];
  envelopeCases: EnvelopeCase[];
  genericCases: GenericCase[];
  familyCases: FamilyCase[];
  csvCases: CsvCase[];
}
interface RubyResult { calls?: Array<[unknown, Record<string, unknown> | null]>; raised?: string }
interface Mutant { id: string; file: string; find: string; replace: string; set?: { path: string[]; value: unknown } }

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
  for (const item of goldens.familyCases) if (!item.provenance) problems.push(`${item.id}: provenance missing`);
  for (const item of goldens.csvCases) if (!item.provenance) problems.push(`${item.id}: provenance missing`);
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
// Contract mutants set one JSON value of the grammar contract; the consumers are then regenerated from it.
const contractMutant = (id: string, path: string[], value: unknown): Mutant => ({ id, file: 'contract', find: '', replace: '', set: { path, value } });
const CONTRACT_MUTANTS: Mutant[] = [
  // Re-introduces F-1: HOSTNAME may again swallow a key=value token.
  contractMutant('contract-hostname-any-printable', ['tokens', 'BSD_HOSTNAME', 'pattern'], '[!-~]{1,255}'),
  // Re-introduces F-5: a TAG such as "kernel:" may again be read as the host name.
  contractMutant('contract-hostname-trailing-colon', ['tokens', 'BSD_HOSTNAME', 'pattern'], '(?!\\{|CEF:|LEEF:)[!-<>-~]{0,254}[!-<>-~]'),
  contractMutant('contract-rest-ascii-only', ['tokens', 'REST', 'pattern'], '[!-~ ]+'),
  contractMutant('contract-hostless-rule-removed', ['alternatives', 'rfc3164'], ['rfc3164_tagged', 'rfc3164_tagless']),
  // key=value body grammar
  contractMutant('contract-kv-quoted-value-without-escapes', ['tokens', 'KV_DQ', 'pattern'], '[^"\\\\]*'),
  contractMutant('contract-kv-bare-value-ascii-only', ['tokens', 'KV_BARE', 'pattern'], '(?:\\\\[^\\r\\n]|[!-&(-\\[\\]-~])+'),
  contractMutant('contract-kv-information-separator-is-value', ['tokens', 'KV_BARE', 'pattern'], '(?:\\\\[^\\r\\n]|[^ \\t\\n\\r\\f\\v"\'\\\\])+'),
  contractMutant('contract-kv-pair-limit-3', ['semantics', 'kvMaxPairs'], 3),
  contractMutant('contract-kv-nothing-unescaped', ['semantics', 'kvUnescapedAfterBackslash'], ['\\']),
];
/** Contract text with one mutant applied. */
function mutateContract(text: string, mutant: Mutant): string {
  if (!mutant.set) return applyMutant(text, mutant);
  const contract = JSON.parse(text) as Record<string, any>;
  let node = contract;
  for (const key of mutant.set.path.slice(0, -1)) node = node[key];
  const last = mutant.set.path[mutant.set.path.length - 1]!;
  if (node === undefined || !(last in node) || same(node[last], mutant.set.value)) throw new Error(`MUTANT_NOT_APPLICABLE ${mutant.id}`);
  node[last] = mutant.set.value;
  return JSON.stringify(contract, null, 2) + '\n';
}
const TS_MUTANTS: Mutant[] = [
  ...CONTRACT_MUTANTS,
  { id: 'ts-hostname-wrong-capture', file: 'src/structuredFamilies.ts', find: 'syslog_hostname:header.hostname', replace: 'syslog_hostname:header.timestamp' },
  { id: 'ts-body-fields-dropped', file: 'src/structuredFamilies.ts', find: 'return body.errors.length?body:withBodyKind({fields:{...fields,...body.fields},errors:[]},bodyKindOf(body));', replace: 'return body.errors.length?body:withBodyKind({fields:{...fields},errors:[]},bodyKindOf(body));' },
  { id: 'ts-procid-wrong-capture', file: 'src/structuredFamilies.ts', find: 'syslog_procid:header.procid', replace: 'syslog_procid:header.tag' },
  { id: 'ts-tagged-first-field-lost', file: 'src/structuredFamilies.ts', find: ' const message=header.message;', replace: " const message=tagged?header.message.replace(/^\\S+ /,''):header.message;" },
  { id: 'ts-pri-range-dropped', file: 'src/grammar/syslogHeader.ts', find: 'pri !== undefined && pri > SYSLOG_HEADER_SEMANTICS.priMax', replace: 'false' },
  { id: 'ts-calendar-widened', file: 'src/grammar/syslogHeader.ts', find: 'day < 1 || day > days ||', replace: 'day < 1 || day > 31 ||' },
  { id: 'ts-rfc5424-any-version', file: 'src/grammar/syslogHeader.ts', find: 'if (!isSupportedRfc5424Version(captures.version!)) return', replace: 'if (false) return' },
  { id: 'ts-kv-every-backslash-decoded', file: 'src/grammar/kvBody.ts', find: "out += UNESCAPED.includes(next) ? next : '\\\\' + next;", replace: 'out += next;' },
  { id: 'ts-kv-duplicate-key-overwrites', file: 'src/grammar/kvBody.ts', find: "if (seen.has(key)) return { ok: false, reason: 'DUPLICATE_KEY' };", replace: '' },
  { id: 'ts-rfc5424-appname-procid-swapped', file: 'src/rfc5424Subset.ts', find: 'syslog_appname:header.appname,syslog_procid:header.procid,', replace: 'syslog_appname:header.procid,syslog_procid:header.appname,' },
];

function applyMutant(text: string, mutant: Mutant): string {
  if (text.split(mutant.find).length !== 2) throw new Error(`MUTANT_NOT_APPLICABLE ${mutant.id}: target text must occur exactly once in ${mutant.file}`);
  if (mutant.replace === mutant.find) throw new Error(`MUTANT_IS_IDENTITY ${mutant.id}`);
  return text.replace(mutant.find, () => mutant.replace);
}

/** Loads the product extractor from a private copy of src/, optionally with one injected fault. */
async function extractorFromCopy(mutant: Mutant | null): Promise<{ extract: Extract; extractGeneric: GenericExtract; envelope: (raw: string) => { variant?: string } | null; dispose: () => void }> {
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
      const mutated = mutateContract(readFileSync(join(REPO, CONTRACT_PATH), 'utf8'), mutant);
      writeFileSync(join(root, 'src/grammar/syslogHeaderGrammar.generated.ts'), generateTypeScript(mutated) as string);
    } else if (mutant) {
      const target = join(root, mutant.file);
      writeFileSync(target, applyMutant(readFileSync(target, 'utf8'), mutant));
    }
    const module = await import(pathToFileURL(join(root, 'src/structuredFamilies.ts')).href) as { extractStructuredFamily: Extract };
    const generic = await import(pathToFileURL(join(root, 'src/genericStructural.ts')).href) as { extractGenericStructural: GenericExtract };
    const envelope = await import(pathToFileURL(join(root, 'src/syslogEnvelope.ts')).href) as { parseSyslogEnvelope: (raw: string) => { variant?: string } | null };
    return { extract: module.extractStructuredFamily, extractGeneric: generic.extractGenericStructural, envelope: envelope.parseSyslogEnvelope, dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}

type GenericExtract = (raw: string) => { fields: Record<string, unknown>; errors: string[] };
function genericTsFailures(extract: GenericExtract): string[] {
  const failures: string[] = [];
  for (const item of goldens.genericCases) {
    const result = extract(item.raw);
    const accepted = result.errors.length === 0 && Object.keys(result.fields).length > 0;
    if (item.expect.reject) { if (accepted) failures.push(`${item.id}: Generic Structural parsed it as ${JSON.stringify(deepGet(result.fields, 'generic.mode'))}`); continue; }
    if (!accepted) { failures.push(`${item.id}: Generic Structural rejected it`); continue; }
    for (const [path, want] of Object.entries(item.expect.fields ?? {}))
      if (!same(deepGet(result.fields, path), want)) failures.push(`${item.id}: ${path}=${JSON.stringify(deepGet(result.fields, path))}, expected ${JSON.stringify(want)}`);
  }
  return failures;
}
const TS_GENERIC_MUTANTS: Mutant[] = [
  { id: 'ts-generic-host-and-tag-swapped', file: 'src/genericStructural.ts', find: "time:match[4],hostname:match[5],app_tag:match[6]},\n    generic:{mode:'bsd_tagged_message'", replace: "time:match[4],hostname:match[6],app_tag:match[5]},\n    generic:{mode:'bsd_tagged_message'" },
  // Re-introduces the browser-only rejection of U+2028 in a BSD tagged message.
  { id: 'ts-generic-message-stops-at-u2028', file: 'src/genericStructural.ts', find: "+([^ \\t\\n\\r\\f\\v]{1,255}) +([A-Za-z0-9_.-]{1,128}): +([^\\n]+)$/.exec(raw);", replace: "+([^ \\t\\n\\r\\f\\v]{1,255}) +([A-Za-z0-9_.-]{1,128}): +(.+)$/.exec(raw);" },
  { id: 'ts-generic-any-rfc5424-version', file: 'src/syslogEnvelope.ts', find: 'if(!isSupportedRfc5424Version(version))return null;', replace: '' },
  { id: 'ts-generic-version-gate-removed', file: 'src/genericStructural.ts', find: 'if(unsupportedVersion!==null)', replace: 'if(false)' },
];

async function runTs(): Promise<number> {
  const selfCheck = goldenSelfCheck();
  if (selfCheck.length) { report('GOLDEN_SELF_CHECK', selfCheck); return 1; }
  const properties = [...generateRfc3164KvCases(300, PROPERTY_SEED), ...generateKvBodyCases(200, PROPERTY_SEED)];
  const cases = [...goldens.cases, ...properties];
  const product = score('ts', cases, item => evaluateTs(item, extractStructuredFamily as Extract));
  const envelopeFailures: string[] = [];
  let envelopeExpected = 0;
  for (const item of goldens.envelopeCases) {
    const envelope = parseSyslogEnvelope(item.raw);
    const variant = envelope?.variant;
    const wrong = (item.expect.variant !== undefined && variant !== item.expect.variant) ||
      (item.expect.variantNot !== undefined && variant === item.expect.variantNot) ||
      (item.expect.message !== undefined && envelope?.message !== item.expect.message);
    const expectedToFail = !!item.knownDefect && goldens.knownDefects[item.knownDefect]!.engines.includes('ts');
    if (expectedToFail && !wrong) envelopeFailures.push(`XFAIL_NOW_PASSING ${item.id} (${item.knownDefect}): remove the knownDefect tag`);
    else if (expectedToFail) envelopeExpected += 1;
    else if (wrong) envelopeFailures.push(`${item.id}: envelope variant ${String(variant)}`);
  }
  // Generic Structural extractor versus hand-authored goldens.
  envelopeFailures.push(...genericTsFailures(extractGenericStructural as GenericExtract));
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
  for (const mutant of TS_GENERIC_MUTANTS) {
    const loaded = await extractorFromCopy(mutant);
    const failing = genericTsFailures(loaded.extractGeneric).length +
      goldens.envelopeCases.filter(item => item.expect.variantNot !== undefined && loaded.envelope(item.raw)?.variant === item.expect.variantNot).length;
    loaded.dispose();
    process.stdout.write(`TS_MUTANT ${mutant.id} ${failing > 0 ? 'KILLED' : 'SURVIVED'} failing_cases=${failing}\n`);
    if (failing === 0) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  const family = await runFamilyTs();
  const csv = await runCsvTs();
  const ok = product.failures.length === 0 && envelopeFailures.length === 0 && !harnessBroken && survivors.length === 0 && family.ok && csv.ok;
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_TS_PASS' : 'SEMANTIC_ORACLE_TS_FAIL'} goldens=${goldens.cases.length} envelope=${goldens.envelopeCases.length} generic=${goldens.genericCases.length} properties=${properties.length} passed=${product.passed} expected_failures=${product.expectedFailures + envelopeExpected} mutants_killed=${TS_MUTANTS.length + TS_GENERIC_MUTANTS.length - survivors.length}/${TS_MUTANTS.length + TS_GENERIC_MUTANTS.length} ${family.summary} ${csv.summary}\n`);
  return ok ? 0 : 1;
}

// ---------------------------------------------------------------------- Ruby
const RUBY_MUTANTS: Array<Mutant & { grammar: OracleCase['grammar']; target?: string }> = [
  // Forwarder-family template: the relay probe must not reject a direct event that has no TAG.
  { id: 'rb-forwarder-probe-rejects-tagless', grammar: 'syslog_rfc3164', target: 'forwarder:syslog_rfc3164', file: 'fragment', find: "{'syslogBodyFormat'=>'raw','taglessStructuredRouter'=>true}", replace: "{'syslogBodyFormat'=>'raw'}" },
  ...CONTRACT_MUTANTS.filter(mutant => mutant.id !== 'contract-kv-pair-limit-3').map(mutant => ({ ...mutant, grammar: 'syslog_rfc3164' as const })),
  { id: 'rb-kv-pair-limit-3', grammar: 'syslog_rfc3164', file: 'fragment', find: "raise ArgumentError, 'Too many key value fields' if record.length >= 100", replace: "raise ArgumentError, 'Too many key value fields' if record.length >= 3" },
  { id: 'rb-pri-range-widened', grammar: 'syslog_rfc3164', file: 'fragment', find: "'RFC3164 PRI out of range' if priority && !priority.between?(0, 191)", replace: "'RFC3164 PRI out of range' if priority && !priority.between?(0, 999)" },
  { id: 'rb-calendar-widened', grammar: 'syslog_rfc3164', file: 'fragment', find: 'day.between?(1, days) && hour.between?(0, 23)', replace: 'day.between?(1, 31) && hour.between?(0, 23)' },
  { id: 'rb-tagged-first-field-lost', grammar: 'syslog_rfc3164', file: 'fragment', find: "  message = header['message']\n", replace: "  message = tagged ? header['message'].sub(/\\A\\S+ /, '') : header['message']\n" },
  { id: 'rb-hostname-wrong-capture', grammar: 'syslog_rfc3164', file: 'fragment', find: "record['syslog_hostname'] = header['hostname'] if header['hostname']", replace: "record['syslog_hostname'] = header['month'] if header['hostname']" },
  { id: 'rb-kv-every-backslash-decoded', grammar: 'syslog_rfc3164', file: 'fragment', find: '.include?(next_char) ? next_char : escaped', replace: '.include?(next_char) ? next_char : next_char' },
  { id: 'rb-kv-duplicate-key-overwrites', grammar: 'syslog_rfc3164', file: 'fragment', find: "    raise ArgumentError, 'Duplicate key value field' if record.key?(key)\n", replace: '' },
  { id: 'rb-rfc5424-any-version', grammar: 'syslog_rfc5424', file: 'fragment', find: "raise ArgumentError, 'Unsupported RFC5424 version' unless ['1'].include?(header['version'])", replace: "raise ArgumentError, 'Unsupported RFC5424 version' unless header['version']" },
];

const RUBY_GENERIC_MUTANTS: Mutant[] = [
  { id: 'rb-generic-host-and-tag-swapped', file: 'fragment', find: "          'hostname'=>match[5],'app_tag'=>match[6]}\n  syslog['pri']=match[1] if match[1]\n  {'syslog'=>syslog,\n   'generic'=>{'mode'=>'bsd_tagged_message'", replace: "          'hostname'=>match[6],'app_tag'=>match[5]}\n  syslog['pri']=match[1] if match[1]\n  {'syslog'=>syslog,\n   'generic'=>{'mode'=>'bsd_tagged_message'" },
  // The envelope-level VERSION check is covered by backend/test/generic-structural-helper.test.ts; at the
  // extractor level the gate below decides, so that is what is removed here.
  { id: 'rb-generic-version-gate-removed', file: 'fragment', find: "  raise ArgumentError, 'Unsupported RFC5424 version' if version_head &&\n    !['1'].include?(version_head[:version])\n", replace: '' },
];

/** Applies a mutant to a compiled Fragment; a contract mutant swaps the injected grammar for the mutated contract's grammar. */
function mutateFragment(fragment: string, mutant: Mutant): string {
  if (mutant.file !== 'contract') return applyMutant(fragment, mutant);
  const contractText = readFileSync(join(REPO, CONTRACT_PATH), 'utf8');
  const before = rubyGrammarPlaceholders(contractText) as Record<string, string>;
  const after = rubyGrammarPlaceholders(mutateContract(contractText, mutant)) as Record<string, string>;
  let out = fragment;
  let changed = 0;
  for (const [placeholder, source] of Object.entries(before)) {
    // A short scalar (a limit such as 100) is not unique text in a Fragment; those faults are injected as text mutants below.
    if (after[placeholder] === source || source.length < 12 || !out.includes(source)) continue;
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
  const cases = [...goldens.cases, ...generateRfc3164KvCases(60, PROPERTY_SEED), ...generateKvBodyCases(60, PROPERTY_SEED)];
  const mutantCases = [...goldens.cases, ...generateRfc3164KvCases(15, PROPERTY_SEED), ...generateKvBodyCases(25, PROPERTY_SEED)];
  const fragments: Record<string, string> = {
    syslog_rfc3164: compileFragment('syslog_rfc3164'),
    syslog_rfc5424: compileFragment('syslog_rfc5424'),
  };
  const payloadCases: Array<{ id: string; fragment: string; raw: string }> = cases.map(item => ({ id: item.id, fragment: item.grammar, raw: item.raw }));
  // Generic Structural goldens: every expected source path is mapped to a vendor field so the emitted event shows it.
  const genericPaths = [...new Set(goldens.genericCases.flatMap(item => Object.keys(item.expect.fields ?? {})))];
  const genericName = (path: string) => 'g_' + path.replace(/[^A-Za-z0-9]/g, '_');
  const genericProject = sampleProject() as unknown as Record<string, any>;
  genericProject.extraction = { format: 'generic_structural' };
  genericProject.normalization.topFields = {};
  genericProject.normalization.nsFields = {};
  genericProject.normalization.vendorFields = Object.fromEntries(genericPaths.map(path => [path, { normalized_name: genericName(path), data_type: 'string' }]));
  genericProject.classification = { defaultIndex: 'syslog', rules: [] };
  fragments.generic_structural = compilePair(genericProject).files.find(file => !file.name.endsWith('.conf'))!.content;
  for (const item of goldens.genericCases) payloadCases.push({ id: `generic::${item.id}`, fragment: 'generic_structural', raw: item.raw });
  for (const mutant of RUBY_GENERIC_MUTANTS) {
    fragments[mutant.id] = applyMutant(fragments.generic_structural, mutant);
    for (const item of goldens.genericCases) payloadCases.push({ id: `${mutant.id}::${item.id}`, fragment: mutant.id, raw: item.raw });
  }
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
  const evaluateFamily = prepareFamilyNative(fragments, payloadCases);
  const evaluateCsv = prepareCsvNative(fragments, payloadCases);
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
  const genericRubyFailures = (prefix: string): string[] => {
  const genericFailures: string[] = [];
  for (const item of goldens.genericCases) {
    const result = output.results[`${prefix}${item.id}`];
    const events = (result?.calls ?? []).filter(([time, record]) => time !== null && record !== null && record.parser_err_msg === undefined);
    if (!result || result.raised) { genericFailures.push(`${item.id}: ${result?.raised ? 'artifact raised ' + result.raised : 'no result'}`); continue; }
    if (item.expect.reject) { if (events.length) genericFailures.push(`${item.id}: emitted a parsed event, expected none`); continue; }
    if (events.length !== 1) { genericFailures.push(`${item.id}: ${events.length} parsed events, expected 1`); continue; }
    for (const [path, want] of Object.entries(item.expect.fields ?? {})) {
      const got = deepGet(events[0]![1], 'Synthetic.' + genericName(path));
      if (!same(got, want)) genericFailures.push(`${item.id}: ${path}=${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);
    }
  }
  return genericFailures;
  };
  const genericFailures = genericRubyFailures('generic::');
  report('SEMANTIC_ORACLE_NATIVE_GENERIC_STRUCTURAL', genericFailures);
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
  for (const mutant of RUBY_GENERIC_MUTANTS) {
    const reported = genericRubyFailures(`${mutant.id}::`).length;
    process.stdout.write(`RUBY_MUTANT ${mutant.id} ${reported > 0 ? 'KILLED' : 'SURVIVED'} failing_cases=${reported}\n`);
    if (reported === 0) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  process.stdout.write(`GENERIC_STRUCTURAL_GOLDENS passed=${goldens.genericCases.length - new Set(genericFailures.map(line => line.split(':')[0])).size} failed=${genericFailures.length}\n`);
  const family = evaluateFamily(output.results);
  const csv = evaluateCsv(output.results);
  const ok = product.failures.length === 0 && genericFailures.length === 0 && forwarder.failures.length === 0 && survivors.length === 0 && dialectDrift.length === 0 && dialectMatches > 0 && family.ok && csv.ok;
  process.stdout.write(`FORWARDER_TEMPLATE_DIRECT_EVENTS passed=${forwarder.passed} failed=${forwarder.failures.length}\n`);
  process.stdout.write(`GRAMMAR_DIALECT_EQUIVALENCE ruby=${output.ruby} rules=${ruleNames.length} lines=${grammarLines.length} matches=${dialectMatches} drift=${dialectDrift.length}\n`);
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_NATIVE_PASS' : 'SEMANTIC_ORACLE_NATIVE_FAIL'} ruby=${output.ruby} goldens=${goldens.cases.length} properties=${cases.length - goldens.cases.length} passed=${product.passed} expected_failures=${product.expectedFailures} mutants_killed=${RUBY_MUTANTS.length + RUBY_GENERIC_MUTANTS.length - survivors.length}/${RUBY_MUTANTS.length + RUBY_GENERIC_MUTANTS.length} ${family.summary} ${csv.summary}\n`);
  return ok ? 0 : 1;
}

// ------------------------------------------------------------ CEF and LEEF
// Standalone CEF/LEEF events: hand-written goldens (familyCases) plus bodies rendered from meant values
// (src/grammar/cefLeefModel.ts). Each engine reports whether it parsed the line and the value of a field;
// the same expectation is applied to the browser extractor, the generated Ruby and the Python preview.
// The Python preview also declines a line that claims to be CEF or LEEF and is not; for the browser and Ruby
// Generic Structural routes that is policy divergence D-2 (legacy V15 compatibility, owner decision pending).
interface FamilyObservation { parsed: boolean; value: (key: string) => unknown }
const familyCases = (properties: number): FamilyCase[] => [...goldens.familyCases, ...generateCefLeefCases(properties, PROPERTY_SEED)];
const familyKey = (path: string) => 'f_' + path.replace(/[^A-Za-z0-9]/g, '_');

function familyProblems(item: FamilyCase, got: FamilyObservation | undefined): string[] {
  if (!got) return ['no result'];
  if (item.expect.status === 'UNKNOWN') return got.parsed ? ['parsed, expected a declined line'] : [];
  if (!got.parsed) return item.expect.neverWrong ? [] : ['declined, expected a parse'];
  const problems: string[] = [];
  for (const [key, want] of Object.entries({ ...item.expect.header, ...item.expect.extension }))
    if (got.value(key) !== want) problems.push(`${key}=${JSON.stringify(got.value(key))}, expected ${JSON.stringify(want)}`);
  return problems;
}

function familyTsFailures(extract: Extract, cases: FamilyCase[]): string[] {
  const failures: string[] = [];
  for (const item of cases) {
    let out: { fields: Record<string, unknown>; errors: string[] };
    try { out = extract(item.raw, item.family, 'raw'); } catch (error) { failures.push(`${item.id}: extractor raised ${String(error)}`); continue; }
    const fields = out.fields;
    const problems = familyProblems(item, { parsed: out.errors.length === 0 && Object.keys(fields).length > 0, value: key => fields[key] });
    if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
  }
  return failures;
}
// Contract faults for the CEF/LEEF values every engine reads from the grammar contract.
const CEF_ESCAPE_CONTRACT_MUTANT = contractMutant('contract-cef-line-feed-escape-dropped', ['semantics', 'cefExtensionEscapes'], { r: '\r', '=': '=', '\\': '\\' });
const CEF_VERSION_CONTRACT_MUTANT = contractMutant('contract-cef-version-1-supported', ['semantics', 'cefSupportedVersions'], ['0', '1']);
const LEEF_VERSION_CONTRACT_MUTANT = contractMutant('contract-leef-version-3-supported', ['semantics', 'leefSupportedVersions'], ['1.0', '2.0', '3.0']);
const TS_FAMILY_MUTANTS: Mutant[] = [
  CEF_ESCAPE_CONTRACT_MUTANT, CEF_VERSION_CONTRACT_MUTANT, LEEF_VERSION_CONTRACT_MUTANT,
  { id: 'ts-cef-value-stops-at-first-space', file: 'src/structuredFamilies.ts', find: 'if(next&&next.index===runEnd){', replace: 'if(true){' },
  { id: 'ts-cef-header-fields-shifted', file: 'src/structuredFamilies.ts', find: 'cef_device_product: parts[1], cef_device_version: parts[2],', replace: 'cef_device_product: parts[2], cef_device_version: parts[1],' },
  { id: 'ts-cef-dot-excludes-line-separator', file: 'src/structuredFamilies.ts', find: '/^CEF:(\\d+)\\|(.*)$/s.exec(input)', replace: '/^CEF:(\\d+)\\|(.*)$/.exec(input)' },
  { id: 'ts-leef-value-cut-at-second-equals', file: 'src/structuredFamilies.ts', find: 'record[key] = part.slice(location + 1);', replace: "record[key] = part.slice(location + 1).split('=')[0]!;" },
  // Re-introduces F-11: header escapes decoded in the extension as well, so a value is decoded twice.
  { id: 'ts-family-extension-decoded-twice', file: 'src/structuredFamilies.ts', find: "if (output.length > splits) { output[output.length - 1] += char; continue; }", replace: '' },
];

async function runFamilyTs(): Promise<{ ok: boolean; summary: string }> {
  const cases = familyCases(150);
  const failures = familyTsFailures(extractStructuredFamily as Extract, cases);
  report('SEMANTIC_ORACLE_TS_FAMILY', failures);
  const survivors: string[] = [];
  for (const mutant of TS_FAMILY_MUTANTS) {
    const loaded = await extractorFromCopy(mutant);
    const failing = familyTsFailures(loaded.extract, cases).length;
    loaded.dispose();
    process.stdout.write(`TS_MUTANT ${mutant.id} ${failing > failures.length ? 'KILLED' : 'SURVIVED'} failing_cases=${failing}\n`);
    if (failing <= failures.length) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  return { ok: failures.length === 0 && survivors.length === 0, summary: `family_cases=${cases.length} family_mutants_killed=${TS_FAMILY_MUTANTS.length - survivors.length}/${TS_FAMILY_MUTANTS.length}` };
}

const RUBY_FAMILY_MUTANTS: Array<Mutant & { family: FamilyCase['family']; target: string }> = [
  { ...CEF_ESCAPE_CONTRACT_MUTANT, family: 'cef', target: 'family:cef' },
  // The version lists are short literals in the compiled Fragment, so these two contract faults are injected as text.
  { id: 'rb-cef-version-1-supported', family: 'cef', target: 'family:cef', file: 'fragment', find: "raise ArgumentError, 'Unsupported CEF version' unless ['0'].include?(match[1])", replace: "raise ArgumentError, 'Unsupported CEF version' unless ['0','1'].include?(match[1])" },
  { id: 'rb-leef-version-3-supported', family: 'leef', target: 'family:leef', file: 'fragment', find: "unless match && ['1.0','2.0'].include?(match[1])", replace: "unless match && ['1.0','2.0','3.0'].include?(match[1])" },
  { id: 'rb-cef-value-stops-at-first-space', family: 'cef', target: 'family:cef', file: 'fragment', find: 'if next_key && next_key.begin(0) == run_end', replace: 'if true' },
  { id: 'rb-cef-header-fields-shifted', family: 'cef', target: 'family:cef', file: 'fragment', find: "'cef_device_product' => fields[1],", replace: "'cef_device_product' => fields[2]," },
  { id: 'rb-leef-value-cut-at-second-equals', family: 'leef', target: 'family:leef', file: 'fragment', find: "key, value = piece.split('=', 2)", replace: "key, value = piece.split('=', 3)" },
  { id: 'rb-cef-extension-decoded-twice', family: 'cef', target: 'family:cef', file: 'fragment', find: "    if parts.length == maximum_splits\n      buffer << character\n    elsif escaped\n", replace: "    if escaped\n" },
];

function familyFragment(family: FamilyCase['family'], cases: FamilyCase[], forwarder = false): string {
  const paths = [...new Set(cases.filter(item => item.family === family).flatMap(item => Object.keys({ ...item.expect.header, ...item.expect.extension })))];
  const project = sampleProject() as unknown as Record<string, any>;
  // A declared forwarder selects the forwarder-family template; a direct event must parse exactly the same.
  project.extraction = { format: family, ...(forwarder ? { forwarder: { maxHops: 2, relayHosts: ['oracle-relay'] } } : {}) };
  project.normalization.topFields = {};
  project.normalization.nsFields = {};
  project.normalization.vendorFields = Object.fromEntries(paths.map(path => [path, { normalized_name: familyKey(path), data_type: 'string' }]));
  project.classification = { defaultIndex: 'syslog', rules: [] };
  return compilePair(project).files.find(file => !file.name.endsWith('.conf'))!.content;
}

/** Adds the family fragments and cases to the Ruby payload; returns the evaluation to run on the results. */
function prepareFamilyNative(fragments: Record<string, string>, payloadCases: Array<{ id: string; fragment: string; raw: string }>):
  (results: Record<string, RubyResult>) => { ok: boolean; summary: string } {
  const cases = familyCases(40);
  const mutantCases = familyCases(12);
  for (const family of ['cef', 'leef'] as const) {
    fragments[`family:${family}`] = familyFragment(family, cases);
    fragments[`familyforwarder:${family}`] = familyFragment(family, cases, true);
    if (fragments[`familyforwarder:${family}`] === fragments[`family:${family}`]) throw new Error('FORWARDER_TEMPLATE_NOT_SELECTED');
  }
  for (const item of cases) {
    payloadCases.push({ id: `family::${item.id}`, fragment: `family:${item.family}`, raw: item.raw });
    payloadCases.push({ id: `familyforwarder::${item.id}`, fragment: `familyforwarder:${item.family}`, raw: item.raw });
  }
  for (const mutant of RUBY_FAMILY_MUTANTS) {
    fragments[mutant.id] = mutant.file === 'contract' ? mutateFragment(fragments[mutant.target]!, mutant) : applyMutant(fragments[mutant.target]!, mutant);
    for (const item of mutantCases) if (item.family === mutant.family) payloadCases.push({ id: `${mutant.id}::${item.id}`, fragment: mutant.id, raw: item.raw });
  }
  const parsedEvents = (result: RubyResult | undefined) => (result?.calls ?? []).filter(([time, record]) => time !== null && record !== null && record.parser_err_msg === undefined);
  const observe = (result: RubyResult | undefined): FamilyObservation | undefined => {
    if (!result || result.raised) return undefined;
    const events = parsedEvents(result);
    return { parsed: events.length === 1, value: key => deepGet(events[0]![1], 'Synthetic.' + familyKey(key)) };
  };
  return results => {
    const failures: string[] = [];
    for (const item of cases) {
      const result = results[`family::${item.id}`];
      if (result?.raised) { failures.push(`${item.id}: artifact raised ${result.raised}`); continue; }
      const problems = familyProblems(item, observe(result));
      if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
      const forwarded = results[`familyforwarder::${item.id}`];
      const forwarderProblems = forwarded?.raised ? [`artifact raised ${forwarded.raised}`] : familyProblems(item, observe(forwarded));
      if (forwarderProblems.length) failures.push(`forwarder-family template, ${item.id}: ${forwarderProblems.slice(0, 3).join(' | ')}`);
    }
    report('SEMANTIC_ORACLE_NATIVE_FAMILY', failures);
    const survivors: string[] = [];
    for (const mutant of RUBY_FAMILY_MUTANTS) {
      const reported = mutantCases.filter(item => item.family === mutant.family &&
        familyProblems(item, observe(results[`${mutant.id}::${item.id}`])).length > 0).length;
      process.stdout.write(`RUBY_MUTANT ${mutant.id} ${reported > 0 ? 'KILLED' : 'SURVIVED'} failing_cases=${reported}\n`);
      if (reported === 0) survivors.push(mutant.id);
    }
    if (survivors.length) report('MUTANT_SURVIVED', survivors);
    return { ok: failures.length === 0 && survivors.length === 0, summary: `family_cases=${cases.length}x2_templates family_mutants_killed=${RUBY_FAMILY_MUTANTS.length - survivors.length}/${RUBY_FAMILY_MUTANTS.length}` };
  };
}

// The Python preview names header fields without the family prefix.
const PYTHON_FAMILY_HEADER: Record<string, string> = {
  cef_version: 'version', cef_device_vendor: 'vendor', cef_device_product: 'product', cef_device_version: 'device_version',
  cef_signature_id: 'signature_id', cef_name: 'name', cef_severity: 'severity',
  leef_version: 'version', leef_vendor: 'vendor', leef_product: 'product', leef_product_version: 'product_version', leef_event_id: 'event_id',
};
interface PythonFamily { status: string; header: Record<string, unknown>; extension: Record<string, unknown> }
function familyPythonFailures(cases: FamilyCase[], results: PythonFamily[]): string[] {
  const failures: string[] = [];
  cases.forEach((item, index) => {
    const result = results[index];
    const problems = familyProblems(item, result && {
      parsed: result.status === 'SOURCE_PARSED',
      value: key => (key in PYTHON_FAMILY_HEADER ? result.header[PYTHON_FAMILY_HEADER[key]!] : result.extension[key]),
    });
    if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
  });
  return failures;
}

// ---------------------------------------------------------------------- CSV
// Delimiter-separated rows: RFC 4180 goldens (csvCases) plus rows rendered from meant values
// (src/grammar/csvModel.ts), applied to the browser tokenizer, the generated Ruby (CSV.parse_line on the
// target Ruby) and the Python preview. The Python preview reads comma rows only and never knows the
// expected column count, so it is held to the comma cases and to "never a different value".
interface CsvObservation { parsed: boolean; value: (index: number) => unknown }
const csvCases = (properties: number): CsvCase[] => [...goldens.csvCases, ...generateCsvCases(properties, PROPERTY_SEED)];
const csvColumnNames = (count: number) => Array.from({ length: count }, (_unused, at) => 'c' + at);

function csvProblems(item: CsvCase, got: CsvObservation | undefined): string[] {
  if (!got) return ['no result'];
  if (item.expect.status === 'UNKNOWN') return got.parsed ? ['parsed, expected a declined row'] : [];
  if (!got.parsed) return ['declined, expected a parse'];
  const problems: string[] = [];
  (item.expect.values ?? []).forEach((want, index) => {
    const value = got.value(index);
    // An empty field is "no value": an empty string and an absent field both state that.
    if (!(value === want || (want === '' && (value === null || value === undefined))))
      problems.push(`field ${index}=${JSON.stringify(value)}, expected ${JSON.stringify(want)}`);
  });
  return problems;
}

type CsvExtract = (raw: string, delimiter: string, columns: number) => { fields: Record<string, unknown>; errors: string[] };
const csvExtractWith = (extract: typeof extractFields, draft: typeof createDraft): CsvExtract => (raw, delimiter, columns) =>
  extract(raw, 'csv', { ...draft(), format: 'csv', csvColumns: csvColumnNames(columns).join(','), csvDelimiter: delimiter as ',' | ';' | '\t' });

function csvTsFailures(extract: CsvExtract, cases: CsvCase[]): string[] {
  const failures: string[] = [];
  for (const item of cases) {
    let out: { fields: Record<string, unknown>; errors: string[] };
    try { out = extract(item.raw, item.delimiter, item.columns); } catch (error) { failures.push(`${item.id}: extractor raised ${String(error)}`); continue; }
    const fields = out.fields;
    const problems = csvProblems(item, { parsed: out.errors.length === 0 && Object.keys(fields).length > 0, value: index => fields['c' + index] });
    if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
  }
  return failures;
}
const TS_CSV_MUTANTS: Mutant[] = [
  { id: 'ts-csv-doubled-quote-kept', file: 'src/parser.ts', find: "if (raw[i + 1] === '\"') { token += '\"'; i++; }", replace: "if (raw[i + 1] === '\"') { token += '\"\"'; i++; }" },
  { id: 'ts-csv-quote-inside-bare-field-accepted', file: 'src/parser.ts', find: "if (state !== 'start') return null;", replace: "if (state !== 'start') { token += c; continue; }" },
  { id: 'ts-csv-column-count-unchecked', file: 'src/parser.ts', find: 'if (values.length !== names.length) {', replace: 'if (false) {' },
];

/** Loads the whole preview pipeline (src/parser.ts and what it imports) from a private copy with one injected fault. */
async function parserFromCopy(mutant: Mutant): Promise<{ extract: CsvExtract; dispose: () => void }> {
  const root = mkdtempSync(join(REPO, '.oracle-mutant-'));
  const source = join(REPO, 'src');
  cpSync(source, join(root, 'src'), { recursive: true, filter: path => statSync(path).isDirectory() || (/\.(ts|tsx|json)$/.test(path) && !/\.test\.tsx?$/.test(path)) });
  for (const shared of ['contracts', 'backend']) symlinkSync(join(REPO, shared), join(root, shared));
  const dispose = () => rmSync(root, { recursive: true, force: true });
  try {
    const target = join(root, mutant.file);
    writeFileSync(target, applyMutant(readFileSync(target, 'utf8'), mutant));
    const parser = await import(pathToFileURL(join(root, 'src/parser.ts')).href) as { extractFields: typeof extractFields };
    const model = await import(pathToFileURL(join(root, 'src/model.ts')).href) as { createDraft: typeof createDraft };
    return { extract: csvExtractWith(parser.extractFields, model.createDraft), dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}

async function runCsvTs(): Promise<{ ok: boolean; summary: string }> {
  const cases = csvCases(300);
  const failures = csvTsFailures(csvExtractWith(extractFields, createDraft), cases);
  report('SEMANTIC_ORACLE_TS_CSV', failures);
  const survivors: string[] = [];
  for (const mutant of TS_CSV_MUTANTS) {
    const loaded = await parserFromCopy(mutant);
    const failing = csvTsFailures(loaded.extract, cases).length;
    loaded.dispose();
    process.stdout.write(`TS_MUTANT ${mutant.id} ${failing > failures.length ? 'KILLED' : 'SURVIVED'} failing_cases=${failing}\n`);
    if (failing <= failures.length) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  return { ok: failures.length === 0 && survivors.length === 0, summary: `csv_cases=${cases.length} csv_mutants_killed=${TS_CSV_MUTANTS.length - survivors.length}/${TS_CSV_MUTANTS.length}` };
}

const RUBY_CSV_MUTANTS: Mutant[] = [
  { id: 'rb-csv-liberal-parsing', file: 'fragment', find: 'liberal_parsing: false', replace: 'liberal_parsing: true' },
  { id: 'rb-csv-column-count-unchecked', file: 'fragment', find: "  raise ArgumentError, 'CSV column count mismatch' unless row.length == fields.length\n", replace: '' },
];

// The product does not combine a declared forwarder with CSV (validation code forwarder_format), so there is
// no forwarder-family variant to run here.
function csvFragment(delimiter: string, columns: number): string {
  const names = csvColumnNames(columns);
  const project = sampleProject() as unknown as Record<string, any>;
  project.extraction = { format: 'csv', csvColumns: names, csvDelimiter: delimiter };
  project.normalization.topFields = {};
  project.normalization.nsFields = {};
  project.normalization.vendorFields = Object.fromEntries(names.map(name => [name, { normalized_name: familyKey(name), data_type: 'string' }]));
  project.classification = { defaultIndex: 'syslog', rules: [] };
  return compilePair(project).files.find(file => !file.name.endsWith('.conf'))!.content;
}

/** Adds the CSV fragments and cases to the Ruby payload; returns the evaluation to run on the results. */
function prepareCsvNative(fragments: Record<string, string>, payloadCases: Array<{ id: string; fragment: string; raw: string }>):
  (results: Record<string, RubyResult>) => { ok: boolean; summary: string } {
  const cases = csvCases(90);
  const mutantCases = csvCases(30);
  const keyOf = (item: CsvCase) => `csv:${item.delimiter.charCodeAt(0)}:${item.columns}`;
  for (const item of cases) {
    const key = keyOf(item);
    if (!fragments[key]) fragments[key] = csvFragment(item.delimiter, item.columns);
    payloadCases.push({ id: `csv::${item.id}`, fragment: key, raw: item.raw });
  }
  for (const mutant of RUBY_CSV_MUTANTS)
    for (const item of mutantCases) {
      const key = `${mutant.id}:${keyOf(item)}`;
      if (!fragments[key]) {
        // The compiled Fragment may carry the statement more than once (direct and routed CSV); every copy is mutated.
        const original = fragments[keyOf(item)]!;
        if (!original.includes(mutant.find)) throw new Error(`MUTANT_NOT_APPLICABLE ${mutant.id}`);
        fragments[key] = original.split(mutant.find).join(mutant.replace);
      }
      payloadCases.push({ id: `${mutant.id}::${item.id}`, fragment: key, raw: item.raw });
    }
  const observe = (result: RubyResult | undefined): CsvObservation | undefined => {
    if (!result || result.raised) return undefined;
    const events = (result.calls ?? []).filter(([time, record]) => time !== null && record !== null && record.parser_err_msg === undefined);
    return { parsed: events.length === 1, value: index => deepGet(events[0]![1], 'Synthetic.' + familyKey('c' + index)) };
  };
  return results => {
    const failures: string[] = [];
    for (const item of cases) {
      const result = results[`csv::${item.id}`];
      const problems = result?.raised ? [`artifact raised ${result.raised}`] : csvProblems(item, observe(result));
      if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
    }
    report('SEMANTIC_ORACLE_NATIVE_CSV', failures);
    const survivors: string[] = [];
    for (const mutant of RUBY_CSV_MUTANTS) {
      const reported = mutantCases.filter(item => csvProblems(item, observe(results[`${mutant.id}::${item.id}`])).length > 0).length;
      process.stdout.write(`RUBY_MUTANT ${mutant.id} ${reported > 0 ? 'KILLED' : 'SURVIVED'} failing_cases=${reported}\n`);
      if (reported === 0) survivors.push(mutant.id);
    }
    if (survivors.length) report('MUTANT_SURVIVED', survivors);
    return { ok: failures.length === 0 && survivors.length === 0, summary: `csv_cases=${cases.length} csv_mutants_killed=${RUBY_CSV_MUTANTS.length - survivors.length}/${RUBY_CSV_MUTANTS.length}` };
  };
}

interface PythonCsv { candidate: boolean; values: unknown[] }
/**
 * Comma rows only. The preview detects the format by itself, so it may read a valid row as another format
 * (a row whose first field is "k=v" is also a key=value line); it is held to: a row it offers as CSV carries
 * exactly the meant values, a malformed row is never offered, and most valid rows are offered.
 */
function csvPythonFailures(cases: CsvCase[], results: PythonCsv[]): string[] {
  const failures: string[] = [];
  let valid = 0, offered = 0;
  cases.forEach((item, index) => {
    if (item.expect.rejected === 'column-count') return;
    const result = results[index];
    if (!result) { failures.push(`${item.id}: no result`); return; }
    if (item.expect.status === 'FULL') {
      valid += 1;
      if (!result.candidate) return;
      offered += 1;
    }
    const problems = csvProblems(item, { parsed: result.candidate, value: at => result.values[at] });
    if (item.expect.status === 'FULL' && result.values.length !== item.columns) problems.push(`${result.values.length} fields, expected ${item.columns}`);
    if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
  });
  if (offered * 10 < valid * 8) failures.push(`only ${offered} of ${valid} valid comma rows were offered as CSV`);
  return failures;
}

// -------------------------------------------------------------------- Python
interface PythonEnvelope { syslog: Record<string, string>; start: number }
interface PythonKv { status: string; body: Record<string, unknown> }
interface PythonOutput { python: string; envelope: Array<PythonEnvelope | null>; rfc5424: Record<string, Record<string, boolean>>; kv: PythonKv[]; family: PythonFamily[]; csv: PythonCsv[] }
const RFC5424_VERSION_PROBES = ['1', '2', '12', '999', '0', '01'];
const PYTHON_MUTANTS: Mutant[] = [
  ...CONTRACT_MUTANTS.filter(mutant => mutant.id.startsWith('contract-hostname') || mutant.id.startsWith('contract-kv')),
  contractMutant('contract-version-2-supported', ['semantics', 'rfc5424SupportedVersions'], ['1', '2']),
  { id: 'py-kv-unicode-white-space-separates', file: 'source_kv.py', find: "PAIR=re.compile(FRAGMENTS['kv_pair']['source'])", replace: "PAIR=re.compile(FRAGMENTS['kv_pair']['source'].replace('[^ ','[^\\u00a0\\u2028 '))" },
  { id: 'py-kv-escapes-not-decoded', file: 'source_kv.py', find: 'value=unescape_kv_value(match[group])', replace: 'value=match[group]' },
  { id: 'py-kv-repeated-key-overwrites', file: 'source_kv.py', find: 'else:out.fields[key]=[previous,value]', replace: 'else:out.fields[key]=value' },
  { id: 'py-kv-forbidden-key-accepted', file: 'source_kv.py', find: 'if key in UNSAFE:', replace: 'if False:' },
  CEF_ESCAPE_CONTRACT_MUTANT, CEF_VERSION_CONTRACT_MUTANT,
  { id: 'py-cef-value-stops-at-first-space', file: 'security_cef.py', find: 'next_key=KEY.match(raw,run_end)', replace: 'next_key=True' },
  { id: 'py-cef-escapes-not-decoded', file: 'security_cef.py', find: 'if nxt in ESCAPES:decoded.append(ESCAPES[nxt])', replace: 'if nxt in ESCAPES:decoded.append(raw[cursor:cursor+2])' },
  { id: 'py-csv-doubled-quote-kept', file: 'engine.py', find: "chars.append('\"');pos+=2", replace: "chars.append('\"\"');pos+=2" },
  // Re-introduces F-12: csv.reader alone accepts a double quote inside a bare field.
  { id: 'py-csv-quote-inside-bare-field-accepted', file: 'engine.py', find: "if '\"' in value:", replace: 'if False:' },
  { id: 'py-generic-family-claim-gate-removed', file: 'generic_structural_poc.py', find: "if STRUCTURED_FAMILY_CLAIM.match(raw) is not None and standard.status!='SOURCE_PARSED':", replace: 'if False:' },
];

/** The Python preview must report the meant value of every pair, or decline; a repeated key follows policy divergence D-1. */
function evaluatePythonKv(item: OracleCase, result: PythonKv | undefined): string[] {
  if (result === undefined) return ['no result from the Python runner'];
  const expect = item.expect;
  const parsed = result.status === 'SOURCE_PARSED';
  const divergence = Object.values(goldens.policyDivergences).find(entry => entry.engines.includes('python') && item.id.endsWith('-' + entry.variant));
  if (divergence) {
    const repeated = Object.values(result.body).filter(value => Array.isArray(value));
    return parsed && repeated.length === 1 && (repeated[0] as unknown[]).length === 2 && (repeated[0] as unknown[])[1] === 'again'
      ? [] : [`status ${result.status}, repeated=${JSON.stringify(repeated)}; D-1 requires both occurrences in order`];
  }
  if (expect.status === 'UNKNOWN') return parsed ? [`status SOURCE_PARSED with ${JSON.stringify(result.body).slice(0, 120)}, expected a declined line`] : [];
  if (!parsed) return expect.neverWrong ? [] : [`status ${result.status}, expected SOURCE_PARSED`];
  const problems: string[] = [];
  for (const [path, want] of Object.entries(expect.source ?? {}))
    if (path.startsWith('body.') && result.body[path.slice(5)] !== want)
      problems.push(`${path}=${JSON.stringify(result.body[path.slice(5)])}, expected ${JSON.stringify(want)}`);
  return problems;
}

/** The Multi-Pass envelope pass reads the header only: host name, PRI and where the structured payload starts. */
function evaluatePythonEnvelope(item: OracleCase, result: PythonEnvelope | null | undefined): string[] {
  if (result === undefined) return ['no result from the Python runner'];
  const expect = item.expect;
  // A line declined because of its body still has a well-formed header; the header pass is not what must refuse it.
  if (expect.status === 'UNKNOWN') return result === null || item.rejectedAt === 'body' ? [] : [`envelope ${JSON.stringify(result.syslog)}, expected none`];
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

const PYTHON_FAMILY_CASES = familyCases(60);
const PYTHON_CSV_CASES = csvCases(180).filter(item => item.delimiter === ',');
function pythonRun(moduleDir: string, cases: OracleCase[], kvCases: OracleCase[]): PythonOutput {
  const run = spawnSync('python3', [join(REPO, 'scripts/verification/semantic-oracle-python-runner.py')], {
    input: JSON.stringify({ moduleDir, lines: cases.map(item => item.raw), kvLines: kvCases.map(item => item.raw), familyLines: PYTHON_FAMILY_CASES.map(item => ({ family: item.family, raw: item.raw })), csvLines: PYTHON_CSV_CASES.map(item => item.raw), versions: RFC5424_VERSION_PROBES }),
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
  // key=value bodies: goldens with a key=value body under an RFC 3164 header, plus the model-rendered bodies.
  const kvCases = [...goldens.cases.filter(item => item.grammar === 'syslog_rfc3164' && item.expect.source?.syslog_appname === undefined && !item.expect.neverWrong),
    ...generateKvBodyCases(40, PROPERTY_SEED)];
  const kvIndex = new Map(kvCases.map((item, position) => [item, position]));
  const failuresOf = (output: PythonOutput) => {
    const failures = score('ruby', cases, item => evaluatePythonEnvelope(item, output.envelope[index.get(item)!])).failures;
    const kvFailures = score('ruby', kvCases, item => evaluatePythonKv(item, output.kv[kvIndex.get(item)!])).failures;
    return [...failures, ...kvFailures, ...familyPythonFailures(PYTHON_FAMILY_CASES, output.family), ...csvPythonFailures(PYTHON_CSV_CASES, output.csv), ...pythonFailures({ ...output, envelope: [] }, [])];
  };
  const moduleDir = join(REPO, 'runtime/multipass');
  const product = pythonRun(moduleDir, cases, kvCases);
  const productFailures = failuresOf(product);
  report('SEMANTIC_ORACLE_PYTHON', productFailures);
  const survivors: string[] = [];
  for (const mutant of PYTHON_MUTANTS) {
    const root = mkdtempSync(join(REPO, '.oracle-mutant-'));
    try {
      cpSync(moduleDir, join(root, 'multipass'), { recursive: true, filter: path => !path.includes('__pycache__') });
      if (mutant.file === 'contract') {
        const mutated = mutateContract(readFileSync(join(REPO, CONTRACT_PATH), 'utf8'), mutant);
        writeFileSync(join(root, 'multipass', (GENERATED_PYTHON_PATH as string).split('/').pop()!), generatePython(mutated) as string);
      } else {
        const target = join(root, 'multipass', mutant.file);
        writeFileSync(target, applyMutant(readFileSync(target, 'utf8'), mutant));
      }
      const failures = failuresOf(pythonRun(join(root, 'multipass'), cases, kvCases));
      const killed = failures.length > productFailures.length;
      process.stdout.write(`PYTHON_MUTANT ${mutant.id} ${killed ? 'KILLED' : 'SURVIVED'} failing=${failures.length}\n`);
      if (!killed) survivors.push(mutant.id);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  const ok = productFailures.length === 0 && survivors.length === 0;
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_PYTHON_PASS' : 'SEMANTIC_ORACLE_PYTHON_FAIL'} python=${product.python} envelope_cases=${cases.length} kv_cases=${kvCases.length} family_cases=${PYTHON_FAMILY_CASES.length} csv_cases=${PYTHON_CSV_CASES.length} version_probes=${RFC5424_VERSION_PROBES.length}x5 mutants_killed=${PYTHON_MUTANTS.length - survivors.length}/${PYTHON_MUTANTS.length}\n`);
  return ok ? 0 : 1;
}

const mode = process.argv[2];
if (mode === 'ts') process.exit(await runTs());
else if (mode === 'native') process.exit(runNative());
else if (mode === 'python') process.exit(runPython());
else { process.stderr.write('usage: semantic-oracle.ts ts|native|python\n'); process.exit(2); }
