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
import { classifyGenericStructural } from '../../src/grammar/genericParseStatus';
import { classifyStructuredParse } from '../../src/grammar/parseStatus';
import { generateRfc3164KvCases, type OracleCase } from '../../src/grammar/syslogHeaderModel';
import { generateKvBodyCases } from '../../src/grammar/kvBodyModel';
import { generateRfc5424KvCases } from '../../src/grammar/rfc5424Model';
import { generateCefLeefCases, type FamilyCase } from '../../src/grammar/cefLeefModel';
import { generateCsvCases, type CsvCase } from '../../src/grammar/csvModel';
import { generateJsonCases, type JsonCase, type JsonValue } from '../../src/grammar/jsonModel';
import { extractFields, preview, tokenizeCSV } from '../../src/parser';
import { createDraft } from '../../src/model';
import { matchHeaderRule } from '../../src/grammar/syslogHeader';
import { SYSLOG_HEADER_RULES, type SyslogHeaderRuleName } from '../../src/grammar/syslogHeaderGrammar.generated';
// @ts-expect-error plain ESM generator without type declarations
import { CONTRACT_PATH, GENERATED_PYTHON_PATH, compileRule, generatePython, generateTypeScript, rubyGrammarPlaceholders } from '../grammar/generate-grammar.mjs';
import { compilePair } from '../../backend/src/compiler.js';
import { analyzeRuby24RegexCost } from '../../backend/src/ruby24-regex-cost.js';
import { sampleProject } from '../../backend/test/fixture.js';
import { prepareFaultInjector } from './translation-faults';

type Engine = 'ts' | 'ruby';
type Extract = (raw: string, grammar: string, body: string) => { fields: Record<string, unknown>; errors: string[] };
interface FieldSpec { [source: string]: [string, string] }
interface Profile { topFields: FieldSpec; vendorFields: FieldSpec; classification: unknown }
interface EnvelopeCase { id: string; raw: string; knownDefect?: string; expect: { variant?: string; variantNot?: string; message?: string } }
/** familyGrammar 'dedicated' is what every newly created Generic Structural parser carries (owner policy D-2); absent is the V15 legacy route. */
interface GenericCase { id: string; raw: string; provenance: string; familyGrammar?: 'dedicated'; expect: { fields?: Record<string, unknown>; /** Source paths the result must not have. */ absent?: string[]; reject?: boolean; status?: 'FULL' | 'PARTIAL' } }
interface Goldens {
  profiles: Record<string, Profile>;
  knownDefects: Record<string, { engines: Engine[] }>;
  /** A decision the owner has made; the oracle enforces it in every engine. */
  ownerPolicies: Record<string, { decidedOn: string; statement: string; enforcedBy: string[] }>;
  /** A documented, owner-visible difference between engines; the oracle pins both sides exactly. */
  policyDivergences: Record<string, { engines: Engine[]; variant: string; statement: string }>;
  cases: OracleCase[];
  envelopeCases: EnvelopeCase[];
  genericCases: GenericCase[];
  familyCases: FamilyCase[];
  csvCases: CsvCase[];
  jsonCases: JsonCase[];
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
  for (const item of goldens.genericCases) {
    if (!item.provenance) problems.push(`${item.id}: provenance missing`);
    if (ids.has(item.id)) problems.push(`duplicate golden id ${item.id}`);
    ids.add(item.id);
  }
  for (const item of goldens.csvCases) if (!item.provenance) problems.push(`${item.id}: provenance missing`);
  for (const item of goldens.jsonCases) if (!item.provenance) problems.push(`${item.id}: provenance missing`);
  for (const item of goldens.cases) {
    if (!item.provenance) problems.push(`${item.id}: provenance missing`);
    for (const [path, value] of Object.entries(item.expect.source ?? {}))
      if (!item.raw.includes(String(value))) problems.push(`${item.id}: expected ${path} is not literal raw text`);
  }
  return problems;
}

/** Owner policy D-1: a rejection is useful to the reviewer only when it says which field is repeated. */
const namesRepeatedField = (messages: string[], repeated: Record<string, string[]>): boolean =>
  messages.some(message => /duplicate/i.test(message) && Object.keys(repeated).some(key => message.includes('"' + key + '"')));

function evaluateTs(item: OracleCase, extract: Extract): string[] {
  let outcome: { fields: Record<string, unknown>; errors: string[] } | { thrown: unknown };
  try { outcome = extract(item.raw, item.grammar, item.body); } catch (error) { outcome = { thrown: error }; }
  const verdict = classifyStructuredParse(item.raw, outcome, item.body);
  const expect = item.expect;
  if (expect.repeated) {
    // Owner policy D-1: declined, and the reviewer is told which field is repeated.
    const errors = 'errors' in outcome ? outcome.errors : [];
    return [...(verdict.status === 'UNKNOWN' ? [] : [`status ${verdict.status}, expected UNKNOWN`]),
      ...(namesRepeatedField(errors, expect.repeated) ? [] : [`the rejection does not name a repeated field: ${JSON.stringify(errors).slice(0, 160)}`])];
  }
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
  // Re-introduces the audit finding of 2026-11-15: a backslash takes the following SP with it, and the next pair with that.
  contractMutant('contract-kv-backslash-carries-space', ['tokens', 'KV_BARE', 'pattern'], '(?:\\\\[^\\n\\r\\f\\v\\x1c-\\x1f]|[^ \\t\\n\\r\\f\\v\\x1c-\\x1f"\'\\\\])+'),
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
  { id: 'ts-body-fields-dropped', file: 'src/structuredFamilies.ts', find: 'const result=withBodyKind({fields:{...fields,...body.fields},errors:[]},bodyKindOf(body));', replace: 'const result=withBodyKind({fields:{...fields},errors:[]},bodyKindOf(body));' },
  { id: 'ts-procid-wrong-capture', file: 'src/structuredFamilies.ts', find: 'syslog_procid:header.procid', replace: 'syslog_procid:header.tag' },
  { id: 'ts-tagged-first-field-lost', file: 'src/structuredFamilies.ts', find: ' const message=header.message;', replace: " const message=tagged?header.message.replace(/^\\S+ /,''):header.message;" },
  { id: 'ts-pri-range-dropped', file: 'src/grammar/syslogHeader.ts', find: 'pri !== undefined && pri > SYSLOG_HEADER_SEMANTICS.priMax', replace: 'false' },
  { id: 'ts-calendar-widened', file: 'src/grammar/syslogHeader.ts', find: 'day < 1 || day > days ||', replace: 'day < 1 || day > 31 ||' },
  { id: 'ts-rfc5424-any-version', file: 'src/grammar/syslogHeader.ts', find: 'if (!isSupportedRfc5424Version(captures.version!)) return', replace: 'if (false) return' },
  { id: 'ts-kv-every-backslash-decoded', file: 'src/grammar/kvBody.ts', find: "out += UNESCAPED.includes(next) ? next : '\\\\' + next;", replace: 'out += next;' },
  { id: 'ts-kv-unquoted-value-decoded', file: 'src/grammar/kvBody.ts', find: "quoted === undefined ? (match.groups!.bare ?? '') : unescapeKvValue(quoted)", replace: "unescapeKvValue(quoted ?? match.groups!.bare ?? '')" },
  { id: 'ts-kv-duplicate-key-overwrites', file: 'src/grammar/kvBody.ts', find: "if (seen.has(key)) return { ok: false, reason: 'DUPLICATE_KEY', key };", replace: '' },
  // Owner policy D-1: the rejection must say which field is repeated.
  { id: 'ts-kv-duplicate-key-not-named', file: 'src/structuredFamilies.ts', find: 'DUPLICATE_KEY: duplicateFieldMessage(String(body.key)),', replace: "DUPLICATE_KEY: 'Unsafe or duplicate extension field'," },
  { id: 'ts-rfc5424-appname-procid-swapped', file: 'src/rfc5424Subset.ts', find: 'syslog_appname:header.appname,syslog_procid:header.procid,', replace: 'syslog_appname:header.procid,syslog_procid:header.appname,' },
];

// The Ruby grammar of an artifact is generated from the TypeScript the browser executes, so the realistic
// defect on the Ruby side is a wrong translation (scripts/verification/translation-faults.ts): a mutant with
// file 'translation' injects one such fault, named by its `find`, into the generated grammar of the artifact.
const injectTranslationFault = ['native', 'differential'].includes(process.argv[2] ?? '') ? await prepareFaultInjector() : null;
const translationFault = (fault: string, scope = ''): Mutant => ({ id: `rb-${scope ? scope + '-' : ''}${fault}`, file: 'translation', find: fault, replace: '' });

function applyMutant(text: string, mutant: Mutant): string {
  if (mutant.file === 'translation') return injectTranslationFault!(text, mutant.find);
  if (text.split(mutant.find).length !== 2) throw new Error(`MUTANT_NOT_APPLICABLE ${mutant.id}: target text must occur exactly once in ${mutant.file}`);
  if (mutant.replace === mutant.find) throw new Error(`MUTANT_IS_IDENTITY ${mutant.id}`);
  return text.replace(mutant.find, () => mutant.replace);
}

/** Loads the product extractor from a private copy of src/, optionally with one injected fault. */
async function extractorFromCopy(mutant: Mutant | null): Promise<{ extract: Extract; extractGeneric: GenericExtract; classifyGeneric: GenericClassify; envelope: (raw: string) => { variant?: string } | null; dispose: () => void }> {
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
    const verdict = await import(pathToFileURL(join(root, 'src/grammar/genericParseStatus.ts')).href) as { classifyGenericStructural: GenericClassify };
    return { extract: module.extractStructuredFamily, extractGeneric: generic.extractGenericStructural, classifyGeneric: verdict.classifyGenericStructural, envelope: envelope.parseSyslogEnvelope, dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}

type GenericExtract = (raw: string, profile?: string, familyGrammar?: 'dedicated') => { fields: Record<string, unknown>; errors: string[] };
type GenericClassify = (raw: string, outcome: { fields: Record<string, unknown>; errors: string[] }) => { status: string };
function genericTsFailures(extract: GenericExtract, classify: GenericClassify): string[] {
  const failures: string[] = [];
  for (const item of goldens.genericCases) {
    const result = extract(item.raw, undefined, item.familyGrammar);
    const accepted = result.errors.length === 0 && Object.keys(result.fields).length > 0;
    if (item.expect.reject) { if (accepted) failures.push(`${item.id}: Generic Structural parsed it as ${JSON.stringify(deepGet(result.fields, 'generic.mode'))}`); continue; }
    if (!accepted) { failures.push(`${item.id}: Generic Structural rejected it`); continue; }
    for (const [path, want] of Object.entries(item.expect.fields ?? {}))
      if (!same(deepGet(result.fields, path), want)) failures.push(`${item.id}: ${path}=${JSON.stringify(deepGet(result.fields, path))}, expected ${JSON.stringify(want)}`);
    for (const path of item.expect.absent ?? [])
      if (deepGet(result.fields, path) !== undefined) failures.push(`${item.id}: ${path}=${JSON.stringify(deepGet(result.fields, path))}, expected no such field`);
    // Owner policy D-2: the verdict the product shows for this result (never FULL on the legacy CEF/LEEF route).
    const status = classify(item.raw, result).status;
    if (item.expect.status !== undefined && status !== item.expect.status) failures.push(`${item.id}: verdict ${status}, expected ${item.expect.status}`);
  }
  return failures;
}
const TS_GENERIC_MUTANTS: Mutant[] = [
  // A JSON body inside Generic Structural with an integer beyond 2^53 is parsed (and silently rounded) again.
  { id: 'ts-generic-json-unsafe-integer-accepted', file: 'src/genericStructural.ts', find: 'return hasDuplicateJsonObjectKeys(text)||hasUnsafeJsonNumbers(text)||', replace: 'return hasDuplicateJsonObjectKeys(text)||' },
  // '.' instead of [^\\n] after PRI: the browser stops at U+2028 and reads the line through another route.
  { id: 'ts-generic-pri-space-kv-stops-at-u2028', file: 'src/genericStructural.ts', find: ">([^\\n]+)$`,'u');", replace: ">(.+)$`,'u');" },
  // Owner policy D-2: a new parser reads a CEF/LEEF claim through the generic key=value routes again.
  { id: 'ts-generic-dedicated-gate-removed', file: 'src/genericStructural.ts', find: "const claim=familyGrammar==='dedicated'?structuredFamilyClaim(raw):null;", replace: 'const claim=null as string|null;' },
  // Owner policy D-2: the legacy route's result for a CEF/LEEF claim is shown as a complete parse.
  { id: 'ts-generic-claim-verdict-full', file: 'src/grammar/genericParseStatus.ts', find: 'if (claim && !GENERIC_FAMILY_MODES.includes(mode))', replace: 'if (false)' },
  { id: 'ts-generic-host-and-tag-swapped', file: 'src/genericStructural.ts', find: "time:match[4],hostname:match[5],app_tag:match[6]},\n    generic:{mode:'bsd_tagged_message'", replace: "time:match[4],hostname:match[6],app_tag:match[5]},\n    generic:{mode:'bsd_tagged_message'" },
  // Re-introduces the browser-only rejection of U+2028 in a BSD tagged message.
  { id: 'ts-generic-message-stops-at-u2028', file: 'src/genericStructural.ts', find: "+([^ \\t\\n\\r\\f\\v]{1,255}) +([A-Za-z0-9_.-]{1,128}): +([^\\n]+)$`,'u');", replace: "+([^ \\t\\n\\r\\f\\v]{1,255}) +([A-Za-z0-9_.-]{1,128}): +(.+)$`,'u');" },
  { id: 'ts-generic-any-rfc5424-version', file: 'src/syslogEnvelope.ts', find: 'if(!isSupportedRfc5424Version(version))return null;', replace: '' },
  { id: 'ts-generic-version-gate-removed', file: 'src/genericStructural.ts', find: 'if(unsupportedVersion!==null)', replace: 'if(false)' },
  // A JSON message the contract declines is read as the free text of a tagged message again (new parsers).
  { id: 'ts-generic-envelope-json-claim-removed', file: 'src/genericStructural.ts', find: "if(familyGrammar==='dedicated'&&envelopedJsonDeclined(raw))", replace: 'if(false)' },
  // ... and on the legacy route its verdict is shown as a complete parse.
  { id: 'ts-generic-envelope-json-verdict-full', file: 'src/grammar/genericParseStatus.ts', find: 'if (envelopedJsonDeclined(raw))', replace: 'if (false)' },
];

async function runTs(): Promise<number> {
  const selfCheck = goldenSelfCheck();
  if (selfCheck.length) { report('GOLDEN_SELF_CHECK', selfCheck); return 1; }
  const properties = [...generateRfc3164KvCases(300, PROPERTY_SEED), ...generateKvBodyCases(200, PROPERTY_SEED), ...generateRfc5424KvCases(150, PROPERTY_SEED)];
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
  envelopeFailures.push(...genericTsFailures(extractGenericStructural as GenericExtract, classifyGenericStructural as GenericClassify));
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
    const failing = genericTsFailures(loaded.extractGeneric, loaded.classifyGeneric).length +
      goldens.envelopeCases.filter(item => item.expect.variantNot !== undefined && loaded.envelope(item.raw)?.variant === item.expect.variantNot).length;
    loaded.dispose();
    process.stdout.write(`TS_MUTANT ${mutant.id} ${failing > 0 ? 'KILLED' : 'SURVIVED'} failing_cases=${failing}\n`);
    if (failing === 0) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  const family = await runFamilyTs();
  const csv = await runCsvTs();
  const jsonResult = await runJsonTs();
  const ok = product.failures.length === 0 && envelopeFailures.length === 0 && !harnessBroken && survivors.length === 0 && family.ok && csv.ok && jsonResult.ok;
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_TS_PASS' : 'SEMANTIC_ORACLE_TS_FAIL'} goldens=${goldens.cases.length} envelope=${goldens.envelopeCases.length} generic=${goldens.genericCases.length} properties=${properties.length} passed=${product.passed} expected_failures=${product.expectedFailures + envelopeExpected} mutants_killed=${TS_MUTANTS.length + TS_GENERIC_MUTANTS.length - survivors.length}/${TS_MUTANTS.length + TS_GENERIC_MUTANTS.length} ${family.summary} ${csv.summary} ${jsonResult.summary}\n`);
  return ok ? 0 : 1;
}

// ---------------------------------------------------------------------- Ruby
// Faults of the translation the Syslog goldens and properties must notice (the run-time contract is in
// place; `unguarded` shows the oracle notices the fault by itself when the contract would turn it into error records).
const RUBY_MUTANTS: Array<Mutant & { grammar: OracleCase['grammar']; target?: string; unguarded?: boolean }> = [
  { ...translationFault('translation-regex-sticky-unanchored', 'syslog_rfc3164'), grammar: 'syslog_rfc3164', unguarded: true },
  { ...translationFault('translation-truthiness-ruby', 'syslog_rfc3164'), grammar: 'syslog_rfc3164' },
  { ...translationFault('runtime-zero-is-true', 'syslog_rfc3164'), grammar: 'syslog_rfc3164' },
  // A defect of one generated method: every RFC 5424 VERSION is taken for supported.
  { id: 'rb-rfc5424-any-version', grammar: 'syslog_rfc5424', file: 'fragment',
    find: 'def psg_is_supported_rfc5424_version(version)\n', replace: 'def psg_is_supported_rfc5424_version(version)\n  return true\n' },
];
const RUBY_GENERIC_MUTANTS: Mutant[] = [
  'translation-truthiness-ruby', 'translation-null-is-nil', 'runtime-empty-string-is-true', 'runtime-zero-is-true', 'runtime-large-number-not-an-integer',
].map(fault => translationFault(fault, 'generic'));

/** Applies a mutant to a compiled Fragment; a contract mutant swaps the injected grammar for the mutated contract's grammar. */
// Grammar faults that lose a key=value pair without any error, and the one-line removal of the run-time guard.
const RUNTIME_GUARD_REMOVED: Mutant = { id: 'runtime-guard-removed', file: 'fragment',
  // The guard hands over a FULL reading, a Generic Structural PARTIAL one, and a PARTIAL one whose Syslog message only
  // claims CEF/LEEF and is kept whole as text (owner decision D-2, textKept).
  find: "  unless reading['status'] == 'FULL' || (reading['status'] == 'PARTIAL' &&\n    (settings['format'] == 'generic_structural' || reading['textKept'] == true))\n",
  replace: "  unless reading['errors'].empty?\n" };
// A defect that loses the first key=value pair of a body without any error: the generated key=value reader
// is handed the body from its second token on.
const KV_READER_SKIPS_FIRST_PAIR = (grammar: string): Mutant => ({ id: `rb-${grammar}-body-skips-first-pair`, file: 'fragment',
  find: 'def psg_strict_key_values(input)\n', replace: "def psg_strict_key_values(input)\n  input = input.sub(/\\A[^ ]+ +/, '')\n" });
const RUNTIME_LOSS_FAULTS: Array<{ id: string; grammar: OracleCase['grammar']; mutant: Mutant }> = [
  { id: 'rfc3164-body-skips-first-pair', grammar: 'syslog_rfc3164', mutant: KV_READER_SKIPS_FIRST_PAIR('syslog_rfc3164') },
  { id: 'rfc5424-body-skips-first-pair', grammar: 'syslog_rfc5424', mutant: KV_READER_SKIPS_FIRST_PAIR('syslog_rfc5424') },
];
/** True when the artifact emitted a parsed event whose fields differ from the expectation (declining is not wrong). */
function emitsWrongEvent(item: OracleCase, result: RubyResult | undefined): boolean {
  const events = (result?.calls ?? []).filter(([time, record]) =>
    time !== null && record !== null && typeof record === 'object' && record.parser_err_msg === undefined);
  if (events.length === 0) return false;
  if (item.expect.status === 'UNKNOWN' || item.expect.event === null) return true;
  const record = events[0]![1];
  return events.length !== 1 ||
    Object.entries(item.expect.event ?? {}).some(([path, want]) => !same(deepGet(record, path), want)) ||
    (item.expect.eventAbsent ?? []).some(path => deepGet(record, path) !== undefined);
}

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
  const cases = [...goldens.cases, ...generateRfc3164KvCases(60, PROPERTY_SEED), ...generateKvBodyCases(60, PROPERTY_SEED), ...generateRfc5424KvCases(40, PROPERTY_SEED)];
  const mutantCases = [...goldens.cases, ...generateRfc3164KvCases(15, PROPERTY_SEED), ...generateKvBodyCases(25, PROPERTY_SEED), ...generateRfc5424KvCases(10, PROPERTY_SEED)];
  const fragments: Record<string, string> = {
    syslog_rfc3164: compileFragment('syslog_rfc3164'),
    syslog_rfc5424: compileFragment('syslog_rfc5424'),
  };
  const payloadCases: Array<{ id: string; fragment: string; raw: string }> = cases.map(item => ({ id: item.id, fragment: item.grammar, raw: item.raw }));
  // Generic Structural goldens: every expected source path is mapped to a vendor field so the emitted event shows it.
  const genericPaths = [...new Set(goldens.genericCases.flatMap(item => [...Object.keys(item.expect.fields ?? {}), ...(item.expect.absent ?? [])]))];
  const genericName = (path: string) => 'g_' + path.replace(/[^A-Za-z0-9]/g, '_');
  const genericProject = sampleProject() as unknown as Record<string, any>;
  genericProject.extraction = { format: 'generic_structural' };
  genericProject.normalization.topFields = {};
  genericProject.normalization.nsFields = {};
  genericProject.normalization.vendorFields = Object.fromEntries(genericPaths.map(path => [path, { normalized_name: genericName(path), data_type: 'string' }]));
  genericProject.classification = { defaultIndex: 'syslog', rules: [] };
  fragments.generic_structural = compilePair(genericProject).files.find(file => !file.name.endsWith('.conf'))!.content;
  // Owner policy D-2: the same project as a newly created parser (dedicated CEF/LEEF grammar); a case runs
  // against the artifact of the route it names.
  genericProject.extraction = { format: 'generic_structural', genericStructuralFamilyGrammar: 'dedicated' };
  fragments['generic_structural@dedicated'] = compilePair(genericProject).files.find(file => !file.name.endsWith('.conf'))!.content;
  if (fragments['generic_structural@dedicated'] === fragments.generic_structural) throw new Error('GENERIC_DEDICATED_MARKER_NOT_COMPILED');
  const genericFragment = (item: GenericCase, base: string) => item.familyGrammar === 'dedicated' ? `${base}@dedicated` : base;
  for (const item of goldens.genericCases) payloadCases.push({ id: `generic::${item.id}`, fragment: genericFragment(item, 'generic_structural'), raw: item.raw });
  for (const mutant of RUBY_GENERIC_MUTANTS) {
    fragments[mutant.id] = applyMutant(fragments.generic_structural, mutant);
    fragments[`${mutant.id}@dedicated`] = applyMutant(fragments['generic_structural@dedicated'], mutant);
    for (const item of goldens.genericCases) payloadCases.push({ id: `${mutant.id}::${item.id}`, fragment: genericFragment(item, mutant.id), raw: item.raw });
  }
  for (const grammar of ['syslog_rfc3164', 'syslog_rfc5424'] as const) {
    fragments[`forwarder:${grammar}`] = compileFragment(grammar, true);
    if (fragments[`forwarder:${grammar}`] === fragments[grammar]) throw new Error('FORWARDER_TEMPLATE_NOT_SELECTED');
  }
  for (const item of cases) payloadCases.push({ id: `forwarder::${item.id}`, fragment: `forwarder:${item.grammar}`, raw: item.raw });
  for (const mutant of RUBY_MUTANTS) {
    fragments[mutant.id] = mutateFragment(fragments[mutant.target ?? mutant.grammar]!, mutant);
    // A fault the run-time guard turns into error records is no longer visible in the output; the oracle
    // is then shown to detect the faulty grammar on its own, with that guard removed.
    if (mutant.unguarded) fragments[mutant.id] = applyMutant(fragments[mutant.id]!, RUNTIME_GUARD_REMOVED);
    for (const item of mutantCases)
      if (item.grammar === mutant.grammar) payloadCases.push({ id: `${mutant.id}::${item.id}`, fragment: mutant.id, raw: item.raw });
  }
  // Run-time field-loss guard (W7). The same grammar fault is compiled twice: with the guard the generated
  // Ruby carries (parserstudio_assert_no_field_loss) and with that one call removed. The guard is proven when
  // the guarded Fragment never emits a parsed event with a wrong or missing field while the unguarded one does.
  for (const fault of RUNTIME_LOSS_FAULTS) {
    const faulty = mutateFragment(fragments[fault.grammar]!, fault.mutant);
    fragments[`guarded:${fault.id}`] = faulty;
    fragments[`unguarded:${fault.id}`] = applyMutant(faulty, RUNTIME_GUARD_REMOVED);
    for (const item of mutantCases) if (item.grammar === fault.grammar)
      for (const variant of ['guarded', 'unguarded']) payloadCases.push({ id: `${variant}:${fault.id}::${item.id}`, fragment: `${variant}:${fault.id}`, raw: item.raw });
  }
  const evaluateFamily = prepareFamilyNative(fragments, payloadCases);
  const evaluateCsv = prepareCsvNative(fragments, payloadCases);
  const evaluateJson = prepareJsonNative(fragments, payloadCases);
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
    for (const path of item.expect.absent ?? []) {
      const got = deepGet(events[0]![1], 'Synthetic.' + genericName(path));
      if (got !== undefined) genericFailures.push(`${item.id}: ${path}=${JSON.stringify(got)}, expected no such field`);
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
  const guardFailures: string[] = [];
  for (const fault of RUNTIME_LOSS_FAULTS) {
    const selected = mutantCases.filter(item => item.grammar === fault.grammar);
    const wrong = (variant: string) => selected.filter(item => emitsWrongEvent(item, output.results[`${variant}:${fault.id}::${item.id}`]));
    const guarded = wrong('guarded'), unguarded = wrong('unguarded');
    process.stdout.write(`RUNTIME_FIELD_LOSS_GUARD ${fault.id} wrong_events_without_guard=${unguarded.length} wrong_events_with_guard=${guarded.length}\n`);
    if (unguarded.length === 0) guardFailures.push(`${fault.id}: the injected fault produced no wrong event, so the guard is not exercised`);
    for (const item of guarded.slice(0, 5)) guardFailures.push(`${fault.id}: ${item.id} still emitted a parsed event with a wrong or missing field`);
  }
  report('RUNTIME_FIELD_LOSS_GUARD', guardFailures);
  const family = evaluateFamily(output.results);
  const csv = evaluateCsv(output.results);
  const jsonResult = evaluateJson(output.results);
  const ok = guardFailures.length === 0 && product.failures.length === 0 && genericFailures.length === 0 && forwarder.failures.length === 0 && survivors.length === 0 && dialectDrift.length === 0 && dialectMatches > 0 && family.ok && csv.ok && jsonResult.ok;
  process.stdout.write(`FORWARDER_TEMPLATE_DIRECT_EVENTS passed=${forwarder.passed} failed=${forwarder.failures.length}\n`);
  process.stdout.write(`GRAMMAR_DIALECT_EQUIVALENCE ruby=${output.ruby} rules=${ruleNames.length} lines=${grammarLines.length} matches=${dialectMatches} drift=${dialectDrift.length}\n`);
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_NATIVE_PASS' : 'SEMANTIC_ORACLE_NATIVE_FAIL'} ruby=${output.ruby} goldens=${goldens.cases.length} properties=${cases.length - goldens.cases.length} passed=${product.passed} expected_failures=${product.expectedFailures} mutants_killed=${RUBY_MUTANTS.length + RUBY_GENERIC_MUTANTS.length - survivors.length}/${RUBY_MUTANTS.length + RUBY_GENERIC_MUTANTS.length} ${family.summary} ${csv.summary} ${jsonResult.summary}\n`);
  return ok ? 0 : 1;
}

// ------------------------------------------------------------ CEF and LEEF
// Standalone CEF/LEEF events: hand-written goldens (familyCases) plus bodies rendered from meant values
// (src/grammar/cefLeefModel.ts). Each engine reports whether it parsed the line and the value of a field;
// the same expectation is applied to the browser extractor, the generated Ruby and the Python preview.
// The Python preview also declines a line that claims to be CEF or LEEF and is not; for the browser and Ruby
// Generic Structural routes that is owner policy D-2: declined by a new parser, PARTIAL on the legacy route (genericCases).
interface FamilyObservation {
  parsed: boolean; value: (key: string) => unknown;
  /** Browser extractor: its error messages. */
  errors?: string[];
  /** Python preview: its issue codes. */
  issues?: string[];
}
const familyCases = (properties: number): FamilyCase[] => [...goldens.familyCases, ...generateCefLeefCases(properties, PROPERTY_SEED)];
const familyKey = (path: string) => 'f_' + path.replace(/[^A-Za-z0-9]/g, '_');

function familyProblems(item: FamilyCase, got: FamilyObservation | undefined): string[] {
  if (!got) return ['no result'];
  if (item.expect.repeated) {
    // Owner policy D-1: never a complete parse. The browser names the field; the preview keeps every value in order.
    const problems = got.parsed ? ['reported as completely parsed although a field is repeated'] : [];
    if (got.errors && !namesRepeatedField(got.errors, item.expect.repeated)) problems.push(`the rejection does not name a repeated field: ${JSON.stringify(got.errors).slice(0, 160)}`);
    if (got.issues) {
      if (!got.issues.includes('DUPLICATE_SOURCE_FIELD')) problems.push(`issues ${JSON.stringify(got.issues)}, expected DUPLICATE_SOURCE_FIELD`);
      for (const [key, want] of Object.entries(item.expect.repeated))
        if (JSON.stringify(got.value(key)) !== JSON.stringify(want)) problems.push(`${key}=${JSON.stringify(got.value(key))}, expected every value in order ${JSON.stringify(want)}`);
    }
    return problems;
  }
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
    const problems = familyProblems(item, { parsed: out.errors.length === 0 && Object.keys(fields).length > 0, value: key => fields[key], errors: out.errors });
    if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
  }
  return failures;
}
// Contract faults for the CEF/LEEF values every engine reads from the grammar contract.
const CEF_ESCAPE_CONTRACT_MUTANT = contractMutant('contract-cef-line-feed-escape-dropped', ['semantics', 'cefExtensionEscapes'], { r: '\r', '=': '=', '\\': '\\' });
const CEF_VERSION_CONTRACT_MUTANT = contractMutant('contract-cef-version-1-supported', ['semantics', 'cefSupportedVersions'], ['0', '1']);
const LEEF_VERSION_CONTRACT_MUTANT = contractMutant('contract-leef-version-3-supported', ['semantics', 'leefSupportedVersions'], ['1.0', '2.0', '3.0']);
// The CEF pair expression and the LEEF delimiter rules are contract fragments compiled by every engine, so a
// fault in them is a contract fault: one mutant, three engines.
const CEF_WS_RUN = { token: 'CEF_WS_RUN' };
const FAMILY_CONTRACT_MUTANTS: Mutant[] = [
  // White space is never value data: a value with a space in it no longer parses.
  contractMutant('contract-cef-value-stops-at-first-space', ['fragments', 'cef_pair', 'sequence', '3', 'group', '0', 'repeat', '0', 'alt', '2'],
    [CEF_WS_RUN, { followedBy: [{ token: 'CEF_NOT_WS' }] }, { notFollowedBy: [{ token: 'CEF_NOT_WS' }] }]),
  // White space before the next KEY= is value data: a value swallows the pairs after it.
  contractMutant('contract-cef-next-key-swallowed', ['fragments', 'cef_pair', 'sequence', '3', 'group', '0', 'repeat', '0', 'alt', '2'],
    [CEF_WS_RUN, { followedBy: [{ token: 'CEF_NOT_WS' }] }]),
  // A backslash takes the following SP or TAB with it: the pair after a path that ends in a backslash is lost.
  contractMutant('contract-cef-backslash-carries-space', ['tokens', 'CEF_ESCAPE', 'pattern'], '\\\\(?:[^\\\\]|\\\\)'),
  // A TAB no longer separates pairs.
  contractMutant('contract-cef-tab-is-value-data', ['tokens', 'CEF_WS', 'pattern'], '[ ]'),
  // SP becomes an acceptable LEEF attribute delimiter.
  contractMutant('contract-leef-space-delimiter-accepted', ['tokens', 'LEEF_DELIMITER_LITERAL', 'pattern'], '[\\t -<>-\\[\\]-~]'),
  // The x prefix of the hexadecimal delimiter spelling is dropped (only 0x remains).
  contractMutant('contract-leef-x-prefix-dropped', ['fragments', 'leef_delimiter', 'sequence', '0', 'alt', '1', '0'], { lit: '0x' }),
];
const TS_FAMILY_MUTANTS: Mutant[] = [
  CEF_ESCAPE_CONTRACT_MUTANT, CEF_VERSION_CONTRACT_MUTANT, LEEF_VERSION_CONTRACT_MUTANT, ...FAMILY_CONTRACT_MUTANTS,
  contractMutant('contract-leef-broken-bar-delimiter-dropped', ['semantics', 'leefDelimiterExtraCodePoints'], []),
  { id: 'ts-cef-escapes-not-decoded', file: 'src/structuredFamilies.ts', find: 'Object.prototype.hasOwnProperty.call(CEF_ESCAPES,pair[1]!)?CEF_ESCAPES[pair[1]!]!:pair);', replace: 'pair);' },
  { id: 'ts-leef-value-cut-at-second-equals', file: 'src/structuredFamilies.ts', find: "record[key] = part.slice(matchEnd(attribute));", replace: "record[key] = part.slice(matchEnd(attribute)).split('=')[0]!;" },
  { id: 'ts-leef-empty-attribute-skipped', file: 'src/structuredFamilies.ts', find: "for (const part of parts[parts.length - 1].split(delimiter)) {", replace: "for (const part of parts[parts.length - 1].split(delimiter).filter(Boolean)) {" },
  // Owner policy D-1: a repeated extension field is declined, never overwritten.
  { id: 'ts-cef-duplicate-field-overwrites', file: 'src/structuredFamilies.ts', find: 'if(Object.prototype.hasOwnProperty.call(values,key))return failure(duplicateFieldMessage(key));', replace: '' },
  { id: 'ts-leef-duplicate-field-overwrites', file: 'src/structuredFamilies.ts', find: 'if (Object.prototype.hasOwnProperty.call(record, key)) return failure(duplicateFieldMessage(key));', replace: '' },
  { id: 'ts-cef-header-fields-shifted', file: 'src/structuredFamilies.ts', find: 'cef_device_product: parts[1], cef_device_version: parts[2],', replace: 'cef_device_product: parts[2], cef_device_version: parts[1],' },
  { id: 'ts-cef-dot-excludes-line-separator', file: 'src/structuredFamilies.ts', find: "/^CEF: ?(\\d+)\\|(.*)$/su.exec(input)", replace: "/^CEF: ?(\\d+)\\|(.*)$/u.exec(input)" },
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

// translation-split-ruby is not listed for LEEF: Ruby's split drops the empty attribute after a trailing delimiter
// and the faulty reader then accepts the line, but the loss accounting of the Parsing Success Contract
// (src/grammar/lossGuard.ts) finds the delimiter that no attribute holds and the artifact declines the event, as
// the browser does. The fault can no longer produce a wrong event; the conformance probes still detect it.
const RUBY_FAMILY_MUTANTS: Array<Mutant & { family: FamilyCase['family']; target: string }> = ([
  ['cef', 'translation-truthiness-ruby'], ['cef', 'runtime-zero-is-true'],
  ['leef', 'translation-truthiness-ruby'], ['leef', 'translation-null-is-nil'], ['leef', 'runtime-zero-is-true'],
] as const).map(([family, fault]) => ({ ...translationFault(fault, family), family, target: `family:${family}` }));

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
interface PythonFamily { status: string; issues: string[]; header: Record<string, unknown>; extension: Record<string, unknown> }
function familyPythonFailures(cases: FamilyCase[], results: PythonFamily[]): string[] {
  const failures: string[] = [];
  cases.forEach((item, index) => {
    const result = results[index];
    const problems = familyProblems(item, result && {
      parsed: result.status === 'SOURCE_PARSED', issues: result.issues,
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
  { id: 'ts-csv-doubled-quote-kept', file: 'src/grammar/extractEvent.ts', find: "if (raw[i + 1] === '\"') { token += '\"'; i++; from = i + 1; }", replace: "if (raw[i + 1] === '\"') { token += '\"\"'; i++; from = i + 1; }" },
  { id: 'ts-csv-quote-inside-bare-field-accepted', file: 'src/grammar/extractEvent.ts', find: "if (state !== 'start') return null;", replace: "if (state !== 'start') { token += c; continue; }" },
  { id: 'ts-csv-column-count-unchecked', file: 'src/grammar/extractEvent.ts', find: "  if (values.length !== columns.length)\n", replace: "  if (false)\n" },
];

/** Loads the whole preview pipeline (src/parser.ts and what it imports) from a private copy with one injected fault. */
async function pipelineFromCopy(mutant: Mutant): Promise<{ extractFields: typeof extractFields; preview: typeof preview; tokenizeCSV: typeof tokenizeCSV; createDraft: typeof createDraft; dispose: () => void }> {
  const root = mkdtempSync(join(REPO, '.oracle-mutant-'));
  const source = join(REPO, 'src');
  cpSync(source, join(root, 'src'), { recursive: true, filter: path => statSync(path).isDirectory() || (/\.(ts|tsx|json)$/.test(path) && !/\.test\.tsx?$/.test(path)) });
  for (const shared of ['contracts', 'backend']) symlinkSync(join(REPO, shared), join(root, shared));
  const dispose = () => rmSync(root, { recursive: true, force: true });
  try {
    const target = join(root, mutant.file);
    writeFileSync(target, applyMutant(readFileSync(target, 'utf8'), mutant));
    const parser = await import(pathToFileURL(join(root, 'src/parser.ts')).href) as { extractFields: typeof extractFields; preview: typeof preview; tokenizeCSV: typeof tokenizeCSV };
    const model = await import(pathToFileURL(join(root, 'src/model.ts')).href) as { createDraft: typeof createDraft };
    return { extractFields: parser.extractFields, preview: parser.preview, tokenizeCSV: parser.tokenizeCSV, createDraft: model.createDraft, dispose };
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
    const loaded = await pipelineFromCopy(mutant);
    const failing = csvTsFailures(csvExtractWith(loaded.extractFields, loaded.createDraft), cases).length;
    loaded.dispose();
    process.stdout.write(`TS_MUTANT ${mutant.id} ${failing > failures.length ? 'KILLED' : 'SURVIVED'} failing_cases=${failing}\n`);
    if (failing <= failures.length) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  return { ok: failures.length === 0 && survivors.length === 0, summary: `csv_cases=${cases.length} csv_mutants_killed=${TS_CSV_MUTANTS.length - survivors.length}/${TS_CSV_MUTANTS.length}` };
}

const RUBY_CSV_MUTANTS: Mutant[] = [
  'translation-truthiness-ruby', 'runtime-zero-is-true',
].map(fault => translationFault(fault, 'csv'));

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
        fragments[key] = applyMutant(fragments[keyOf(item)]!, mutant);
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

// --------------------------------------------------------------------- JSON
// A JSON object event: RFC 8259 goldens (jsonCases) plus objects rendered from meant values in several
// spellings the RFC defines as equal (src/grammar/jsonModel.ts), applied to the browser extractor, the
// generated Ruby and the Python preview. Numbers are compared by value and booleans by truth, so an
// engine that maps them to text is not penalised; null and "absent" are the same statement.
interface JsonObservation { parsed: boolean; value: (path: string) => unknown }
const jsonCases = (properties: number): JsonCase[] => [...goldens.jsonCases, ...generateJsonCases(properties, PROPERTY_SEED)];

function jsonSame(got: unknown, want: JsonValue, emptyTextMayBeAbsent: boolean): boolean {
  if (want === null) return got === null || got === undefined;
  if (typeof want === 'number') return typeof got === 'number' ? got === want : typeof got === 'string' && got.trim() !== '' && Number(got) === want;
  if (typeof want === 'boolean') return got === want || got === String(want);
  return got === want || (emptyTextMayBeAbsent && want === '' && got === undefined);
}

function jsonProblems(item: JsonCase, got: JsonObservation | undefined, emptyTextMayBeAbsent = false): string[] {
  if (!got) return ['no result'];
  if (item.expect.status === 'UNKNOWN') return got.parsed ? ['parsed, expected a declined event'] : [];
  if (!got.parsed) return item.expect.neverWrong ? [] : ['declined, expected a parse'];
  const problems: string[] = [];
  for (const [path, want] of Object.entries(item.expect.values ?? {}))
    if (!jsonSame(got.value(path), want, emptyTextMayBeAbsent)) problems.push(`${path}=${JSON.stringify(got.value(path))}, expected ${JSON.stringify(want)}`);
  for (const [path, digits] of Object.entries(item.expect.exactDigits ?? {}))
    if (String(got.value(path)) !== digits) problems.push(`${path}=${String(got.value(path))}, expected exactly ${digits}`);
  return problems;
}

type JsonExtract = (raw: string) => { fields: Record<string, unknown>; errors: string[] };
const jsonExtractWith = (extract: typeof extractFields, draft: typeof createDraft): JsonExtract => raw => extract(raw, 'json', { ...draft(), format: 'json' });
function jsonTsFailures(extract: JsonExtract, cases: JsonCase[]): string[] {
  const failures: string[] = [];
  for (const item of cases) {
    let out: { fields: Record<string, unknown>; errors: string[] };
    try { out = extract(item.raw); } catch (error) { failures.push(`${item.id}: extractor raised ${String(error)}`); continue; }
    const fields = out.fields;
    // Parsing Success Contract: an event from which no field was extracted (an empty object) is not a parsed event.
    const problems = jsonProblems(item, { parsed: out.errors.length === 0 && Object.keys(fields).length > 0, value: path => deepGet(fields, path) });
    if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
  }
  return failures;
}
const TS_JSON_MUTANTS: Mutant[] = [
  { id: 'ts-json-repeated-name-accepted', file: 'src/grammar/extractEvent.ts', find: "if (hasDuplicateJsonObjectKeys(raw)) return failure(", replace: "if (false) return failure(" },
  // Without the guard JSON.parse rounds 12345678901234567890 to 12345678901234567000.
  { id: 'ts-json-large-integer-rounded', file: 'src/grammar/extractEvent.ts', find: "if (hasUnsafeJsonNumbers(raw)) return failure(", replace: "if (false) return failure(" },
  // Without the comparison 0.1234567890123456789 is reported as 0.12345678901234568.
  { id: 'ts-json-inexact-decimal-read', file: 'src/jsonNumberSafety.ts', find: "if (decimalIdentity(token) !== decimalIdentity(String(value))) return true;", replace: "if (false) return true;" },
  // Counting digits instead of comparing declines 1731719701.123456, the ts of a Zeek record.
  { id: 'ts-json-decimal-declined-by-digit-count', file: 'src/jsonNumberSafety.ts', find: "if (decimalIdentity(token) !== decimalIdentity(String(value))) return true;", replace: "if (token.replace(/[^0-9]/gu, '').length > 15) return true;" },
];

async function runJsonTs(): Promise<{ ok: boolean; summary: string }> {
  const cases = jsonCases(200);
  const failures = jsonTsFailures(jsonExtractWith(extractFields, createDraft), cases);
  report('SEMANTIC_ORACLE_TS_JSON', failures);
  const survivors: string[] = [];
  for (const mutant of TS_JSON_MUTANTS) {
    const loaded = await pipelineFromCopy(mutant);
    const failing = jsonTsFailures(jsonExtractWith(loaded.extractFields, loaded.createDraft), cases).length;
    loaded.dispose();
    process.stdout.write(`TS_MUTANT ${mutant.id} ${failing > failures.length ? 'KILLED' : 'SURVIVED'} failing_cases=${failing}\n`);
    if (failing <= failures.length) survivors.push(mutant.id);
  }
  if (survivors.length) report('MUTANT_SURVIVED', survivors);
  return { ok: failures.length === 0 && survivors.length === 0, summary: `json_cases=${cases.length} json_mutants_killed=${TS_JSON_MUTANTS.length - survivors.length}/${TS_JSON_MUTANTS.length}` };
}

const RUBY_JSON_MUTANTS: Mutant[] = [
  'translation-truthiness-ruby', 'translation-number-to-i', 'runtime-zero-is-true', 'runtime-large-number-not-an-integer',
].map(fault => translationFault(fault, 'json'));

function jsonFragment(paths: string[]): string {
  const project = sampleProject() as unknown as Record<string, any>;
  project.extraction = { format: 'json' };
  project.normalization.topFields = {};
  project.normalization.nsFields = {};
  project.normalization.vendorFields = Object.fromEntries(paths.map(path => [path, { normalized_name: familyKey(path), data_type: 'string' }]));
  project.classification = { defaultIndex: 'syslog', rules: [] };
  return compilePair(project).files.find(file => !file.name.endsWith('.conf'))!.content;
}

/** Adds the JSON fragment and cases to the Ruby payload; returns the evaluation to run on the results. */
function prepareJsonNative(fragments: Record<string, string>, payloadCases: Array<{ id: string; fragment: string; raw: string }>):
  (results: Record<string, RubyResult>) => { ok: boolean; summary: string } {
  const cases = jsonCases(50);
  const mutantCases = jsonCases(15);
  const paths = [...new Set(cases.flatMap(item => [...Object.keys(item.expect.values ?? {}), ...Object.keys(item.expect.exactDigits ?? {})]))];
  fragments.json = jsonFragment(paths);
  for (const item of cases) payloadCases.push({ id: `json::${item.id}`, fragment: 'json', raw: item.raw });
  for (const mutant of RUBY_JSON_MUTANTS) {
    fragments[mutant.id] = applyMutant(fragments.json, mutant);
    for (const item of mutantCases) payloadCases.push({ id: `${mutant.id}::${item.id}`, fragment: mutant.id, raw: item.raw });
  }
  const observe = (result: RubyResult | undefined): JsonObservation | undefined => {
    if (!result || result.raised) return undefined;
    const events = (result.calls ?? []).filter(([time, record]) => time !== null && record !== null && record.parser_err_msg === undefined);
    return { parsed: events.length === 1, value: path => deepGet(events[0]![1], 'Synthetic.' + familyKey(path)) };
  };
  return results => {
    const failures: string[] = [];
    for (const item of cases) {
      const result = results[`json::${item.id}`];
      // The event shows mapped vendor fields; an empty text value is not emitted as a field by the mapping stage.
      const problems = result?.raised ? [`artifact raised ${result.raised}`] : jsonProblems(item, observe(result), true);
      if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
    }
    report('SEMANTIC_ORACLE_NATIVE_JSON', failures);
    const survivors: string[] = [];
    for (const mutant of RUBY_JSON_MUTANTS) {
      const reported = mutantCases.filter(item => jsonProblems(item, observe(results[`${mutant.id}::${item.id}`]), true).length > 0).length;
      process.stdout.write(`RUBY_MUTANT ${mutant.id} ${reported > 0 ? 'KILLED' : 'SURVIVED'} failing_cases=${reported}\n`);
      if (reported === 0) survivors.push(mutant.id);
    }
    if (survivors.length) report('MUTANT_SURVIVED', survivors);
    return { ok: failures.length === 0 && survivors.length === 0, summary: `json_cases=${cases.length} json_mutants_killed=${RUBY_JSON_MUTANTS.length - survivors.length}/${RUBY_JSON_MUTANTS.length}` };
  };
}

interface PythonJson { status: string; fields: Record<string, unknown> }
function jsonPythonFailures(cases: JsonCase[], results: PythonJson[]): string[] {
  const failures: string[] = [];
  cases.forEach((item, index) => {
    const result = results[index];
    const problems = jsonProblems(item, result && { parsed: result.status === 'SOURCE_PARSED' && Object.keys(result.fields ?? {}).length > 0, value: path => deepGet(result.fields, path) });
    if (problems.length) failures.push(`${item.id}: ${problems.slice(0, 3).join(' | ')}`);
  });
  return failures;
}

// -------------------------------------------------------------------- Python
interface PythonEnvelope { syslog: Record<string, string>; start: number }
interface PythonKv { status: string; issues: string[]; body: Record<string, unknown> }
interface PythonOutput { python: string; envelope: Array<PythonEnvelope | null>; rfc5424: Record<string, Record<string, boolean>>; kv: PythonKv[]; family: PythonFamily[]; csv: PythonCsv[]; json: PythonJson[] }
const RFC5424_VERSION_PROBES = ['1', '2', '12', '999', '0', '01'];
const PYTHON_MUTANTS: Mutant[] = [
  ...CONTRACT_MUTANTS.filter(mutant => mutant.id.startsWith('contract-hostname') || mutant.id.startsWith('contract-kv')),
  contractMutant('contract-version-2-supported', ['semantics', 'rfc5424SupportedVersions'], ['1', '2']),
  { id: 'py-kv-unicode-white-space-separates', file: 'source_kv.py', find: "PAIR=re.compile(FRAGMENTS['kv_pair']['source'])", replace: "PAIR=re.compile(FRAGMENTS['kv_pair']['source'].replace('[^ ','[^\\u00a0\\u2028 '))" },
  { id: 'py-kv-escapes-not-decoded', file: 'source_kv.py', find: "value=match[group] if group=='bare' else unescape_kv_value(match[group])", replace: 'value=match[group]' },
  { id: 'py-kv-unquoted-value-decoded', file: 'source_kv.py', find: "value=match[group] if group=='bare' else unescape_kv_value(match[group])", replace: 'value=unescape_kv_value(match[group])' },
  { id: 'py-kv-repeated-key-overwrites', file: 'source_kv.py', find: 'else:out.fields[key]=[previous,value]', replace: 'else:out.fields[key]=value' },
  // Owner policy D-1: a repeated field is never a complete parse, in the key=value preview as in CEF and LEEF.
  { id: 'py-kv-repeated-key-reported-as-parsed', file: 'source_kv.py', find: "if 'DUPLICATE_SOURCE_FIELD' not in out.issues:out.issues.append('DUPLICATE_SOURCE_FIELD')", replace: 'pass' },
  { id: 'py-kv-repeated-key-keeps-first-only', file: 'source_kv.py', find: 'else:out.fields[key]=[previous,value]', replace: 'else:out.fields[key]=previous' },
  // LEEF attributes go through this one place. (For CEF two merged candidates each report the issue, so removing one is not observable.)
  { id: 'py-leef-repeated-field-reported-as-parsed', file: 'structured_source.py', find: '        issues.append("DUPLICATE_SOURCE_FIELD")', replace: '        pass' },
  // G-5: a reserved source name is kept under its reversible field name; keeping it raw is the fault.
  { id: 'py-kv-reserved-name-kept-raw', file: 'source_kv.py', find: "key=source_field_name(match['key'])", replace: "key=match['key']" },
  CEF_ESCAPE_CONTRACT_MUTANT, CEF_VERSION_CONTRACT_MUTANT, LEEF_VERSION_CONTRACT_MUTANT, ...FAMILY_CONTRACT_MUTANTS,
  contractMutant('contract-leef-broken-bar-delimiter-dropped', ['semantics', 'leefDelimiterExtraCodePoints'], []),
  // The header rule (only the pipe and the backslash are escapes) falls back to the extension-style decoder.
  { id: 'py-header-escapes-decoded-like-values', file: 'structured_source.py', find: '_unescape_header(raw[start:i])', replace: '_unescape(raw[start:i])' },
  { id: 'py-cef-escapes-not-decoded', file: 'structured_source.py', find: 'CEF_ESCAPES.get(found[0][1],found[0])', replace: 'found[0]' },
  { id: 'py-leef-value-cut-at-second-equals', file: 'structured_source.py', find: '_pair(ext.fields,key,raw[matched.end():end],ext.issues)', replace: "_pair(ext.fields,key,raw[matched.end():end].split('=')[0],ext.issues)" },
  { id: 'py-leef-empty-attribute-skipped', file: 'structured_source.py', find: 'if end==i and skip_empty:', replace: 'if end==i:' },
  { id: 'py-csv-doubled-quote-kept', file: 'engine.py', find: "chars.append('\"');pos+=2", replace: "chars.append('\"\"');pos+=2" },
  // Re-introduces F-12: csv.reader alone accepts a double quote inside a bare field.
  { id: 'py-csv-quote-inside-bare-field-accepted', file: 'engine.py', find: "if '\"' in value:", replace: 'if False:' },
  { id: 'py-json-repeated-name-accepted', file: 'engine.py', find: '                    if key in out:\n                        raise ValueError("JSON_DUPLICATE_OR_UNSAFE_KEY")', replace: '                    if False:\n                        raise ValueError("JSON_DUPLICATE_OR_UNSAFE_KEY")' },
  { id: 'py-json-depth-limit-widened', file: 'engine.py', find: 'MAX_JSON_DEPTH = 8', replace: 'MAX_JSON_DEPTH = 40' },
  { id: 'py-json-text-after-object-accepted', file: 'engine.py', find: 'raise ValueError("JSON_TRAILING_DATA")', replace: 'pass' },
  // Re-audit of 2026-11-15: Python's decoder keeps an unpaired surrogate escape as a lone surrogate.
  { id: 'py-json-unpaired-surrogate-accepted', file: 'engine.py', find: 'if isinstance(value,str) and _has_unpaired_surrogate(value):', replace: 'if False:' },
  { id: 'py-generic-family-claim-gate-removed', file: 'generic_structural_poc.py', find: "if STRUCTURED_FAMILY_CLAIM.match(raw) is not None and standard.status!='SOURCE_PARSED':", replace: 'if False:' },
];

/** The Python preview must report the meant value of every pair, or decline; a repeated key follows owner policy D-1. */
function evaluatePythonKv(item: OracleCase, result: PythonKv | undefined): string[] {
  if (result === undefined) return ['no result from the Python runner'];
  const expect = item.expect;
  const parsed = result.status === 'SOURCE_PARSED';
  if (expect.repeated) {
    // Owner policy D-1: every value kept in wire order, and never reported as a complete parse.
    const problems = parsed ? ['status SOURCE_PARSED although a field is repeated'] : [];
    if (!result.issues.includes('DUPLICATE_SOURCE_FIELD')) problems.push(`issues ${JSON.stringify(result.issues)}, expected DUPLICATE_SOURCE_FIELD`);
    for (const [key, want] of Object.entries(expect.repeated))
      if (JSON.stringify(result.body[key]) !== JSON.stringify(want)) problems.push(`${key}=${JSON.stringify(result.body[key])}, expected every value in order ${JSON.stringify(want)}`);
    return problems;
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
const PYTHON_JSON_CASES = jsonCases(40);
function pythonRun(moduleDir: string, cases: OracleCase[], kvCases: OracleCase[]): PythonOutput {
  const run = spawnSync('python3', [join(REPO, 'scripts/verification/semantic-oracle-python-runner.py')], {
    input: JSON.stringify({ moduleDir, lines: cases.map(item => item.raw), kvLines: kvCases.map(item => item.raw), familyLines: PYTHON_FAMILY_CASES.map(item => ({ family: item.family, raw: item.raw })), csvLines: PYTHON_CSV_CASES.map(item => item.raw), jsonLines: PYTHON_JSON_CASES.map(item => item.raw), versions: RFC5424_VERSION_PROBES }),
    encoding: 'utf8', maxBuffer: 1 << 28, timeout: 120000,
  });
  if (run.status !== 0) throw new Error(`SEMANTIC_ORACLE_PYTHON_RUNNER_FAILED ${String(run.stderr).slice(-600)}`);
  return JSON.parse(run.stdout) as PythonOutput;
}

// ------------------------------------------------------------------ three-way: Python preview, browser, Ruby
// The Python preview detects the format of a line by itself. Whenever it reports a line as completely parsed
// (SOURCE_PARSED) in one of the formats the parser has too, the browser must read the same line, in that format,
// to the same fields. The generated Ruby is held to the browser on these very lines by the format differential,
// so the three agree. A line the preview does not parse is not a wrong value; how many of the lines the browser
// parses the preview parses too is reported and must stay high. One documented divergence: the preview holds a
// JSON integer beyond 2^53 exactly, the parser declines the event (it cannot carry the integer).
interface PythonPreview { status: string; syntax: string; issues: string[]; fields: Record<string, unknown> }
const THREE_WAY_FORMATS: Record<string, string> = { KV: 'kv', JSON: 'json', CEF: 'cef', LEEF: 'leef' };
const THREE_WAY_LINES_PER_FORMAT = 700;
function pythonPreviewRun(moduleDir: string, lines: string[]): PythonPreview[] {
  const run = spawnSync('python3', [join(REPO, 'scripts/verification/semantic-oracle-python-runner.py')], {
    input: JSON.stringify({ moduleDir, lines: [], kvLines: [], versions: [], previewLines: lines }), encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  if (run.status !== 0) throw new Error('PYTHON_RUNNER_FAILED ' + String(run.stderr).slice(0, 600));
  return (JSON.parse(run.stdout) as { preview: PythonPreview[] }).preview;
}
/** The fields of a preview result in the shape the parser gives the same format. */
function previewFieldsAsParser(syntax: string, fields: Record<string, unknown>): Record<string, unknown> {
  if (syntax !== 'CEF' && syntax !== 'LEEF') return fields;
  const family = syntax.toLowerCase();
  const header = (fields[family + '_header'] ?? {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, name] of Object.entries(PYTHON_FAMILY_HEADER)) if (key.startsWith(family + '_')) out[key] = header[name];
  return { ...out, ...((fields[family + '_extension'] ?? {}) as Record<string, unknown>) };
}
function pythonThreeWay(moduleDir: string): { failures: string[]; summary: string } {
  const failures: string[] = [];
  const browser = (raw: string, format: string) => {
    const events = preview(raw, { ...createDraft(), format } as ReturnType<typeof createDraft>).events;
    return events.length === 1 ? events[0]! : null;
  };
  const totals: string[] = [];
  for (const config of formatConfigs().filter(item => ['kv', 'json', 'cef', 'leef'].includes(item.name))) {
    const lines = formatLines(config.seeds, FORMAT_STREAM, THREE_WAY_LINES_PER_FORMAT);
    const results = pythonPreviewRun(moduleDir, lines);
    let same = 0, browserFull = 0, exactDigits = 0, notParsed = 0;
    lines.forEach((raw, index) => {
      const result = results[index];
      if (!result) { failures.push(`${config.name}#${index}: no result from the Python preview`); return; }
      const parsed = result.status === 'SOURCE_PARSED';
      const format = THREE_WAY_FORMATS[result.syntax];
      const own = browser(raw, config.name);
      const ownFull = own !== null && own.parseStatus === 'FULL';
      if (ownFull) browserFull += 1;
      if (parsed && format) {
        const event = format === config.name ? own : browser(raw, format);
        const full = event !== null && event.parseStatus === 'FULL';
        if (full) {
          if (canonicalTree(event!.fields) !== canonicalTree(previewFieldsAsParser(result.syntax, result.fields)))
            failures.push(`${config.name}#${index}: read as ${result.syntax} by the Python preview with other values than the browser: ${JSON.stringify(raw).slice(0, 140)}`);
          else if (format === config.name) same += 1;
        } else if (format === 'json' && JSON.stringify(result.fields).includes('"__digits"')) exactDigits += 1;
        else failures.push(`${config.name}#${index}: completely parsed as ${result.syntax} by the Python preview, ${event ? String(event.parseStatus) : 'no single event'} in the browser: ${JSON.stringify(raw).slice(0, 140)}`);
      } else if (ownFull) notParsed += 1;
    });
    // The preview is a subset by design; a subset that shrinks to a few lines would compare nothing.
    if (same * 10 < browserFull * 8) failures.push(`${config.name}: the Python preview parses only ${same} of the ${browserFull} lines the browser parses completely`);
    totals.push(`${config.name}:lines=${lines.length},browser_full=${browserFull},same=${same},preview_not_parsed=${notParsed},exact_digits=${exactDigits}`);
  }
  return { failures, summary: `PYTHON_THREE_WAY ${totals.join(' ')} differences=${failures.length}` };
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
    ...generateKvBodyCases(40, PROPERTY_SEED), ...generateRfc5424KvCases(40, PROPERTY_SEED)];
  const kvIndex = new Map(kvCases.map((item, position) => [item, position]));
  const failuresOf = (output: PythonOutput) => {
    const failures = score('ruby', cases, item => evaluatePythonEnvelope(item, output.envelope[index.get(item)!])).failures;
    const kvFailures = score('ruby', kvCases, item => evaluatePythonKv(item, output.kv[kvIndex.get(item)!])).failures;
    return [...failures, ...kvFailures, ...familyPythonFailures(PYTHON_FAMILY_CASES, output.family), ...csvPythonFailures(PYTHON_CSV_CASES, output.csv), ...jsonPythonFailures(PYTHON_JSON_CASES, output.json), ...pythonFailures({ ...output, envelope: [] }, [])];
  };
  const moduleDir = join(REPO, 'runtime/multipass');
  const product = pythonRun(moduleDir, cases, kvCases);
  const productFailures = failuresOf(product);
  report('SEMANTIC_ORACLE_PYTHON', productFailures);
  // Three-way comparison on the lines of the browser/Ruby format differential (the product only; the faults
  // above are judged on the model cases).
  const threeWay = pythonThreeWay(moduleDir);
  report('PYTHON_THREE_WAY', threeWay.failures.slice(0, 40));
  process.stdout.write(threeWay.summary + '\n');
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
  const ok = productFailures.length === 0 && survivors.length === 0 && threeWay.failures.length === 0;
  process.stdout.write(`${ok ? 'SEMANTIC_ORACLE_PYTHON_PASS' : 'SEMANTIC_ORACLE_PYTHON_FAIL'} python=${product.python} envelope_cases=${cases.length} kv_cases=${kvCases.length} family_cases=${PYTHON_FAMILY_CASES.length} csv_cases=${PYTHON_CSV_CASES.length} json_cases=${PYTHON_JSON_CASES.length} version_probes=${RFC5424_VERSION_PROBES.length}x5 mutants_killed=${PYTHON_MUTANTS.length - survivors.length}/${PYTHON_MUTANTS.length}\n`);
  return ok ? 0 : 1;
}

// ------------------------------------------------------------ Generic Structural: browser versus generated Ruby
// The sub-profile bodies of Generic Structural are written twice by hand (src/genericStructural.ts and
// backend/templates/generic-structural-helper.rb.tpl). This stage holds the two to each other: for every seed
// line and every derived variant, both engines must take the same decision (parsed or declined) and, when they
// parse, return the same field tree. It then injects faults into each side and requires the difference to be
// reported. Which behaviour is right is decided by the hand-authored goldens, not here.
const GENERIC_PROFILES = ['syslog_prefix_kv', 'leef2_implicit_tab', 'syslog_prefix_kv_leef2_implicit_tab_v1'] as const;
interface DifferentialCase { id: string; raw: string; familyGrammar?: 'dedicated'; /** A Generic Structural profile (src/genericStructuralProfiles.ts). */ profile?: string }
const DIFFERENTIAL_SEPARATORS = [' ', ' ', ' ', '\u0085', '　', '﻿', '\u000b'];
function differentialVariants(raw: string): string[] {
  const out = new Set<string>([raw]);
  const add = (value: string) => { if (value.length > 0 && value.length <= 20000) out.add(value); };
  const pri = /^<(\d{1,3})>/.exec(raw);
  if (pri) {
    const rest = raw.slice(pri[0].length);
    for (const value of ['0', '191', '192', '999', '1000', '', '٣']) add('<' + value + '>' + rest);
    add(rest);
    const version = /^(\d{1,3}) /.exec(rest);
    if (version) for (const value of ['2', '12', '0']) add(pri[0] + value + rest.slice(version[1]!.length));
  } else add('<13>' + raw);
  const month = /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b/.exec(raw);
  if (month) for (const value of ['JAN', 'jan', 'Sept']) add(raw.slice(0, month.index) + value + raw.slice(month.index + 3));
  const tokens = raw.split(' ');
  for (let index = 0; index < Math.min(tokens.length, 6); index += 1) {
    const token = tokens[index]!;
    if (!token || token.includes('=')) continue;
    for (const value of [token + 'é', token + '\u007f', token + ':', 'h'.repeat(255), 'h'.repeat(256), '[::1]', '12:34:56', 'fe80::1'])
      add([...tokens.slice(0, index), value, ...tokens.slice(index + 1)].join(' '));
  }
  // An address token anywhere in the line: the two engines must agree on what an IP address is.
  tokens.map((token, index) => (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(token) ? index : -1)).filter(index => index >= 0).slice(0, 2).forEach(index => {
    for (const value of ['12:34:56', '[::1]', 'fe80::1', '2001:db8::1', '1:2:3:4:5:6:7:8', '1:2:3', '256.1.1.1', '::ffff:192.0.2.1'])
      add([...tokens.slice(0, index), value, ...tokens.slice(index + 1)].join(' '));
  });
  const key = /([A-Za-z_][A-Za-z0-9_.-]*)=/.exec(raw);
  if (key) for (const value of ['k'.repeat(96), 'k'.repeat(97), '9key', 'kéy']) add(raw.slice(0, key.index) + value + raw.slice(key.index + key[1]!.length));
  const spaces = [...raw.matchAll(/ /g)].map(match => match.index!);
  const alnum = [...raw.matchAll(/[A-Za-z0-9]/g)].map(match => match.index!);
  DIFFERENTIAL_SEPARATORS.forEach((ch, n) => {
    if (spaces.length) {
      const first = spaces[0]!, middle = spaces[Math.floor(spaces.length / 2)]!;
      add(raw.slice(0, first) + ch + raw.slice(first + 1));
      add(raw.slice(0, middle) + ch + raw.slice(middle + 1));
      add(raw.slice(0, middle + 1) + ch + raw.slice(middle + 1));
    }
    if (alnum.length) {
      const at = alnum[(n * 7 + 3) % alnum.length]!, last = alnum[alnum.length - 1]!;
      add(raw.slice(0, at) + ch + raw.slice(at));
      add(raw.slice(0, last + 1) + ch + raw.slice(last + 1));
    }
  });
  for (const value of [raw + ' ', raw + ' x', ' ' + raw, raw + ' ', raw + '\t', raw + '\n', raw + '\nx=1', raw + '\u0000', raw.replace(' ', '  '), raw.replace(' ', '\t')]) add(value);
  add(raw.replace(/\d{4}\/\d{2}\/\d{2}/, '2026/02/30'));
  add(raw.replace(/\d{4}-\d{2}-\d{2}/, '2026-02-30'));
  add(raw.replace(/\d{4}-\d{2}-\d{2}/, '2025-02-29'));
  // Century years: 1900 and 2100 have no 29 February, 2000 has (second re-audit: a fault in the 100/400 rule went unreported).
  for (const year of ['1900', '2000', '2100']) {
    add(raw.replace(/\d{4}-\d{2}-\d{2}/, year + '-02-29'));
    add(raw.replace(/\d{4}\/\d{2}\/\d{2}/, year + '/02/29'));
  }
  add(raw.replace(/\b\d{2}:\d{2}:\d{2}\b/, '24:00:00'));
  add(raw.replace(/\b\d{2}:\d{2}:\d{2}\b/, '23:59:60'));
  add(raw.replace(/[A-Z][a-z]{2} +\d{1,2} /, 'Feb 30 '));
  // Re-audit of 2026-11-15. Time zone and fraction of a second directly after the first clock time: every
  // spelling the recognizers admit, and the ones just outside (minute 60, hour 24, ten fraction digits).
  const clock = /\d{2}:\d{2}:\d{2}/.exec(raw);
  if (clock) {
    const end = clock.index + 8;
    for (const value of ['.915', '.123456789', '.1234567890', ' Z', ' +0200', ' -0000', ' +02:00', ' +0260', ' +2400', 'Z', '+0530', '+05:30', '+0560'])
      add(raw.slice(0, end) + value + raw.slice(end));
  }
  const zone = /(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:\d{2})/.exec(raw);
  if (zone) for (const value of ['+0530', '-0000', '+0560', '+24:00', ''])
    add(raw.slice(0, zone.index) + zone[1]! + value + raw.slice(zone.index + zone[0].length));
  // JSON token rules: escapes, surrogates, comments, nesting, repeated names and numbers, as a first member.
  const brace = raw.indexOf('{"');
  if (brace >= 0) {
    const B = '\\';
    for (const value of [`"x":"${B}q",`, `"x":"${B}x41",`, `"x":"${B}ud83d",`, `"x":"${B}ude00",`, `"x":"${B}ud83d${B}ud83d",`, `"x":"${B}ud83d${B}ude00",`,
      '"x":[[[[[[[[1]]]]]]]],', '"x":[[[[[[[1]]]]]]],', '/* c */', '"x":1,"x":2,', '"x":9007199254740993,', '"x":NaN,', "'x':1,", '"x":"a\tb",'])
      add(raw.slice(0, brace + 1) + value + raw.slice(brace + 1));
    add(raw + ' // c');
    add(raw + '/* c */');
  }
  // CSV quoting (RFC 4180) on the fourth field of a comma-separated row.
  const commas = [...raw.matchAll(/,/g)].map(match => match.index!);
  if (commas.length >= 5) {
    const start = commas[2]! + 1, end = commas[3]!;
    const field = raw.slice(start, end);
    for (const value of [`"${field}"`, `"${field}""x"`, `${field}""x`, `"${field}"x`, ` "${field}"`, `"${field}" `, `"${field}`, `${field}"`, '"a,b"', '""', '""' + field + '""', '"""' + field + '"""'])
      add(raw.slice(0, start) + value + raw.slice(end));
  }
  // The 8192-byte bound of the envelope routes, from both sides.
  const bytes = Buffer.byteLength(raw, 'utf8');
  if (bytes < 8000) for (const total of [8192, 8193]) add(raw + ' ' + 'x'.repeat(total - bytes - 1));
  return [...out];
}

/**
 * A fixed pseudo-random stream (xorshift32, so every run sees the same lines) of what the hand-written variants
 * above do not enumerate: a special token inserted, a character deleted or replaced, a word taken from another
 * seed, a word dropped or doubled, and the head of one seed joined to the tail of another. The independent
 * re-audit of 2026-11-15 found 378 browser/Ruby differences in 84,000 such lines while the enumerated variants
 * reported none; the same generator is now part of the gate.
 */
const DIFFERENTIAL_SPECIAL = ['"', "'", '\\', '=', ':', ',', ';', '[', ']', '{', '}', '|', '<', '>', '(', ')', '/', '-', '.', '0', '9', 'a', 'Z', ' ', '\t', '%', '^', '#', '@', '+', '*', '?', '!', '~', '`', '$', '&', '_',
  '\\"', '\\\\', '""', "''", '==', ': ', ', ', '; ', ' = ', '=""', '="', "='", '[]', '{}', '()', '::', '..', '--', '\u00e9', '\u4e2d', '\ud83d\ude00', 'e\u0301', '0x', '1e5', '-1', '1.5', 'null', 'true',
  'CEF:0|', 'LEEF:2.0|', '{"a":1}', 'a=b', '<13>', 'Oct 1 00:00:00 ', '%ASA-1-1: ', '\\n', '\\t', '\\u0041', '\\x41', '\u007f', '\u001b'];
function differentialRandomLines(seedLines: string[], seed: number, count: number): string[] {
  let state = seed >>> 0;
  const random = () => { state ^= state << 13; state >>>= 0; state ^= state >>> 17; state ^= state << 5; state >>>= 0; return state / 4294967296; };
  const pick = <T,>(list: T[]): T => list[Math.floor(random() * list.length)]!;
  const lines = new Set<string>();
  while (lines.size < count) {
    let raw = pick(seedLines);
    const operations = 1 + Math.floor(random() * 3);
    for (let operation = 0; operation < operations; operation += 1) {
      const points = [...raw];
      const at = Math.floor(random() * (points.length + 1));
      const kind = random();
      if (kind < 0.35) points.splice(at, 0, pick(DIFFERENTIAL_SPECIAL));
      else if (kind < 0.55) points.splice(at, 1);
      else if (kind < 0.7) points.splice(at, 1, pick(DIFFERENTIAL_SPECIAL));
      else {
        const words = raw.split(' ');
        const index = Math.floor(random() * words.length);
        if (kind < 0.8) { words[index] = pick(pick(seedLines).split(' ')); raw = words.join(' '); }
        else if (kind < 0.88) { words.splice(index, 1); raw = words.join(' '); }
        else if (kind < 0.94) { words.splice(index, 0, words[index] ?? ''); raw = words.join(' '); }
        else { const other = pick(seedLines); const cut = Math.floor(random() * raw.length); raw = raw.slice(0, cut) + other.slice(Math.floor(random() * other.length)); }
        continue;
      }
      raw = points.join('');
    }
    if (raw.length > 0 && !/[\n\r]/.test(raw) && !loneSurrogate(raw)) lines.add(raw);
  }
  return [...lines];
}
/** A surrogate code unit without its partner cannot be handed to the generated Ruby as UTF-8; a pair (an astral character) can. */
const loneSurrogate = (raw: string): boolean => [...raw].some(ch => ch.length === 1 && ch >= '\ud800' && ch <= '\udfff');
const DIFFERENTIAL_RANDOM_STREAMS = [101, 102, 103];
const DIFFERENTIAL_RANDOM_LINES_PER_STREAM = 3000;
const canonicalTree = (value: unknown): string => JSON.stringify(value, (_key, node: unknown) =>
  node !== null && typeof node === 'object' && !Array.isArray(node)
    ? Object.fromEntries(Object.entries(node as Record<string, unknown>).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)))
    : node);
interface RubyExtract { value?: unknown; declined?: string; raised?: string }
function differentialProblems(extract: GenericExtract, cases: DifferentialCase[], results: Record<string, RubyExtract>, prefix: string): { problems: string[]; parsed: number; declined: number } {
  const problems: string[] = [];
  let parsed = 0, declined = 0;
  for (const item of cases) {
    const ruby = results[prefix + item.id];
    if (!ruby || ruby.raised) { problems.push(`${item.id}: the generated Ruby ${ruby ? 'raised ' + ruby.raised : 'returned nothing'}`); continue; }
    let browser: { fields: Record<string, unknown>; errors: string[] };
    try { browser = extract(item.raw, item.profile, item.familyGrammar); } catch (error) { problems.push(`${item.id}: the browser extractor raised ${String(error).slice(0, 80)}`); continue; }
    const browserParsed = browser.errors.length === 0 && Object.keys(browser.fields).length > 0;
    const rubyParsed = ruby.value !== undefined && ruby.value !== null;
    if (browserParsed !== rubyParsed) problems.push(`${item.id}: parsed only by ${browserParsed ? 'the browser' : 'the generated Ruby'}: ${JSON.stringify(item.raw).slice(0, 160)}`);
    else if (browserParsed && canonicalTree(browser.fields) !== canonicalTree(ruby.value)) problems.push(`${item.id}: different field tree: ${JSON.stringify(item.raw).slice(0, 160)}`);
    else if (browserParsed) parsed += 1; else declined += 1;
  }
  return { problems, parsed, declined };
}
const DIFFERENTIAL_TS_FAULTS: Mutant[] = [
  // JavaScript's trim() also removes NBSP, U+2028 and U+FEFF, which the generated Ruby keeps as data.
  { id: 'ts-diff-unicode-trim', file: 'src/genericStructural.ts', find: "const ASCII_EDGE_SPACE=/^[ \\t\\n\\v\\f\\r]+|[ \\t\\n\\v\\f\\r]+$/gu;", replace: "const ASCII_EDGE_SPACE=/^\\s+|\\s+$/gu;" },
  // The calendar check of the shared timestamp rule is removed: 30 February is accepted by the browser only.
  { id: 'ts-diff-impossible-date-accepted', file: 'src/genericStructural.ts', find: '  if(day>[31,leap?29:28,31,30,31,30,31,31,30,31,30,31][month-1]!)return false;\n  if(Number(match[4])>23', replace: '  if(Number(match[4])>23' },
  // The browser's JSON bodies accept an integer beyond 2^53 again.
  { id: 'ts-diff-json-unsafe-integer', file: 'src/genericStructural.ts', find: 'return hasDuplicateJsonObjectKeys(text)||hasUnsafeJsonNumbers(text)||', replace: 'return hasDuplicateJsonObjectKeys(text)||' },
  // The browser's IP token takes a clock time (12:34:56) as an address again.
  { id: 'ts-diff-ip-token-clock-time', file: 'src/genericStructural.ts', find: '  return sides.length===2?groups.length<=7:groups.length===8;', replace: '  return groups.length>=2;' },
  // The browser's shared timestamp rule forgets that a century year is a leap year only when divisible by 400.
  { id: 'ts-diff-century-leap-year', file: 'src/genericStructural.ts', find: "  const leap=year%4===0&&(year%100!==0||year%400===0);\n  if(day>[31,leap?29:28,31,30,31,30,31,31,30,31,30,31][month-1]!)return false;\n  if(Number(match[4])>23", replace: "  const leap=year%4===0;\n  if(day>[31,leap?29:28,31,30,31,30,31,31,30,31,30,31][month-1]!)return false;\n  if(Number(match[4])>23" },
  // Re-audit I-7: a quotation mark inside an unquoted CSV field is taken as data by the browser only.
  { id: 'ts-diff-csv-quote-in-unquoted-field', file: 'src/genericStructural.ts', find: "        if(text[index]==='\"')return null;\n", replace: '' },
  // Re-audit I-4 and I-5: the browser's Generic Structural JSON drops the JSON source contract (8 levels, paired surrogates).
  { id: 'ts-diff-json-source-contract-removed', file: 'src/genericStructural.ts', find: '||!jsonSourceValueValid(value)?undefined:value;', replace: '?undefined:value;' },
];
// The translation and runtime faults that change what a Generic Structural artifact returns for a generated
// line. The other faults of scripts/verification/translation-faults.ts (number-to-i, regex-line-anchors,
// runtime-json-null-is-absent, runtime-split-drops-trailing-fields) leave every result of this stage unchanged
// and are detected by the translation conformance probes, which is where a gate on them belongs.
const DIFFERENTIAL_RUBY_FAULTS: Mutant[] = [
  'translation-regex-sticky-unanchored', 'translation-truthiness-ruby', 'translation-null-is-nil', 'translation-length-in-characters',
  'translation-split-ruby', 'runtime-undefined-exported-as-null', 'runtime-empty-string-is-true', 'runtime-zero-is-true',
  'runtime-large-number-not-an-integer', 'runtime-length-in-characters',
].map(fault => translationFault(fault, 'diff'));

/**
 * Runs extraction cases on the target Ruby in batches, each batch in a process of its own with only the Fragments
 * it needs. The CI interpreter is a container with 512 MB and one CPU; one process that holds the result tree of
 * every case of this stage does not fit.
 */
const RUBY_BATCH = 6000;
const FAULT_BATCH = 3000;
function rubyExtractBatches(label: string, fragments: Record<string, string>, payload: Array<Record<string, string>>, expectedRuby: string): Record<string, RubyExtract> | null {
  const runner = readFileSync(join(REPO, 'scripts/verification/semantic-oracle-runner.rb'), 'utf8');
  const results: Record<string, RubyExtract> = {};
  for (let start = 0; start < payload.length; start += RUBY_BATCH) {
    const batch = payload.slice(start, start + RUBY_BATCH);
    const used = Object.fromEntries([...new Set(batch.map(item => item.fragment!))].map(name => [name, fragments[name]!]));
    const run = spawnSync('ruby', ['-e', runner], { input: JSON.stringify({ fragments: used, cases: batch }), encoding: 'utf8', maxBuffer: 1 << 30, timeout: 600000 });
    if (run.status !== 0) { process.stderr.write(`${label}_RUBY_RUNNER_FAILED status=${String(run.status)} ${String(run.stderr).slice(0, 600)}\n`); return null; }
    const output = JSON.parse(run.stdout) as { ruby: string; results: Record<string, RubyExtract> };
    if (output.ruby !== expectedRuby) { process.stderr.write(`${label}_RUBY_VERSION_MISMATCH expected=${expectedRuby} actual=${output.ruby}\n`); return null; }
    Object.assign(results, output.results);
  }
  return results;
}

async function runDifferential(): Promise<number> {
  const expectedRuby = process.env.PARSER_STUDIO_EXPECT_RUBY ?? '2.4.9';
  const seeds = (JSON.parse(readFileSync(join(REPO, 'contracts/generic-differential-seeds.v1.json'), 'utf8')) as { seeds: Array<{ id: string; raw: string }> }).seeds;
  const lines = new Map<string, string>();
  for (const seed of [...seeds, ...goldens.genericCases.map(item => ({ id: 'golden-' + item.id, raw: item.raw }))])
    differentialVariants(seed.raw).forEach((raw, index) => { if (!loneSurrogate(raw)) lines.set(`${seed.id}#${index}`, raw); });
  const cases: DifferentialCase[] = [];
  for (const [id, raw] of lines) { cases.push({ id: id + '@legacy', raw }); cases.push({ id: id + '@dedicated', raw, familyGrammar: 'dedicated' }); }
  // The pseudo-random stream is compared on the product only; the injected faults are judged on the enumerated variants.
  const randomCases: DifferentialCase[] = [];
  const seedLines = [...new Set([...seeds.map(seed => seed.raw), ...goldens.genericCases.map(item => item.raw)])];
  for (const stream of DIFFERENTIAL_RANDOM_STREAMS)
    differentialRandomLines(seedLines, stream, DIFFERENTIAL_RANDOM_LINES_PER_STREAM).forEach((raw, index) => {
      randomCases.push({ id: `random-${stream}#${index}@legacy`, raw });
      randomCases.push({ id: `random-${stream}#${index}@dedicated`, raw, familyGrammar: 'dedicated' });
    });
  // The Generic Structural profiles (a selected sub-grammar in front of the standard routes), on one stream each
  // and on lines of their own families, with the family grammar every new parser carries.
  const profileSeeds = [...seedLines,
    'LEEF:2.0|Acme|Gateway|1|event|first=one\tsecond=two words\tthird=three', 'LEEF:2.0|Acme|Gateway|1|event|^|first=one^second=two',
    'LEEF:2.0|Acme|Gateway|1|event|src=10.0.0.1\tdst=10.0.0.2\tmsg=a b=c\tusrName=kim', 'LEEF:1.0|Acme|Gateway|1|event|src=10.0.0.1\tdst=10.0.0.2',
    'Oct 11 22:14:15 fw01 traffic allowed: srcip=10.1.1.1 dstip=10.2.2.2 action=accept', 'fw01 session opened user=kim srcip=10.1.1.1 dstip=10.2.2.2 proto=tcp',
    '<13>Oct 11 22:14:15 fw01 app: start srcip=10.1.1.1 dstip=10.2.2.2 dstport=443 proto=tcp action=accept'];
  for (const profile of GENERIC_PROFILES)
    differentialRandomLines(profileSeeds, DIFFERENTIAL_RANDOM_STREAMS[0]!, DIFFERENTIAL_RANDOM_LINES_PER_STREAM).forEach((raw, index) =>
      randomCases.push({ id: `profile-${profile}#${index}@dedicated`, raw, familyGrammar: 'dedicated', profile }));
  const project = sampleProject() as unknown as Record<string, any>;
  project.normalization.topFields = {};
  project.normalization.nsFields = {};
  project.normalization.vendorFields = { 'generic.mode': { normalized_name: 'differential_mode', data_type: 'string' } };
  project.classification = { defaultIndex: 'syslog', rules: [] };
  const fragments: Record<string, string> = {};
  project.extraction = { format: 'generic_structural' };
  fragments.legacy = compilePair(project).files.find(file => !file.name.endsWith('.conf'))!.content;
  project.extraction = { format: 'generic_structural', genericStructuralFamilyGrammar: 'dedicated' };
  fragments.dedicated = compilePair(project).files.find(file => !file.name.endsWith('.conf'))!.content;
  for (const profile of GENERIC_PROFILES) {
    project.extraction = { format: 'generic_structural', genericStructuralProfile: profile, genericStructuralFamilyGrammar: 'dedicated' };
    fragments[`profile:${profile}`] = compilePair(project).files.find(file => !file.name.endsWith('.conf'))!.content;
  }
  const fragmentOf = (item: DifferentialCase) => (item.profile ? `profile:${item.profile}` : item.familyGrammar === 'dedicated' ? 'dedicated' : 'legacy');
  const toPayload = (item: DifferentialCase, fragment: string, prefix = '') => ({ id: prefix + item.id, fragment, raw: item.raw, call: 'generic_extract' });
  const results = rubyExtractBatches('GENERIC_DIFFERENTIAL', fragments, [...cases, ...randomCases].map(item => toPayload(item, fragmentOf(item))), expectedRuby);
  if (!results) return 1;
  const product = differentialProblems(extractGenericStructural as GenericExtract, cases, results, '');
  report('GENERIC_DIFFERENTIAL', product.problems.slice(0, 40));
  const random = differentialProblems(extractGenericStructural as GenericExtract, randomCases, results, '');
  report('GENERIC_DIFFERENTIAL_RANDOM', random.problems.slice(0, 40));
  for (const profile of GENERIC_PROFILES) {
    const own = differentialProblems(extractGenericStructural as GenericExtract, randomCases.filter(item => item.profile === profile), results, '');
    process.stdout.write(`GENERIC_DIFFERENTIAL_PROFILE ${profile} parsed_identically=${own.parsed} declined_by_both=${own.declined} differences=${own.problems.length}\n`);
    if (own.parsed === 0 || own.declined === 0) { report('GENERIC_DIFFERENTIAL_VACUOUS_PROFILE', [profile]); return 1; }
  }
  const undetected: string[] = [];
  // A fault in the compiled Ruby is run batch by batch, until a batch reports more differences than the product
  // does on the same cases; a fault that no batch reveals is undetected.
  for (const fault of DIFFERENTIAL_RUBY_FAULTS) {
    const faulty: Record<string, string> = {};
    for (const route of ['legacy', 'dedicated']) faulty[`${fault.id}@${route}`] = applyMutant(fragments[route]!, fault);
    let found = 0, ran = 0;
    for (let start = 0; start < cases.length && found === 0; start += FAULT_BATCH) {
      const batch = cases.slice(start, start + FAULT_BATCH);
      const faultResults = rubyExtractBatches('GENERIC_DIFFERENTIAL', faulty, batch.map(item => toPayload(item, `${fault.id}@${fragmentOf(item)}`, `${fault.id}::`)), expectedRuby);
      if (!faultResults) return 1;
      ran += batch.length;
      found = differentialProblems(extractGenericStructural as GenericExtract, batch, faultResults, `${fault.id}::`).problems.length -
        differentialProblems(extractGenericStructural as GenericExtract, batch, results, '').problems.length;
    }
    process.stdout.write(`DIFFERENTIAL_FAULT ${fault.id} ${found > 0 ? 'DETECTED' : 'UNDETECTED'} new_differences=${found} cases_run=${ran}\n`);
    if (found <= 0) undetected.push(fault.id);
  }
  for (const fault of DIFFERENTIAL_TS_FAULTS) {
    const loaded = await extractorFromCopy(fault);
    const found = differentialProblems(loaded.extractGeneric, cases, results, '').problems.length - product.problems.length;
    loaded.dispose();
    process.stdout.write(`DIFFERENTIAL_FAULT ${fault.id} ${found > 0 ? 'DETECTED' : 'UNDETECTED'} new_differences=${found} cases_run=${cases.length}\n`);
    if (found <= 0) undetected.push(fault.id);
  }
  if (undetected.length) report('DIFFERENTIAL_FAULT_UNDETECTED', undetected);
  const ok = product.problems.length === 0 && random.problems.length === 0 && undetected.length === 0 && product.parsed > 0 && product.declined > 0 &&
    random.parsed > 0 && random.declined > 0;
  const faults = DIFFERENTIAL_RUBY_FAULTS.length + DIFFERENTIAL_TS_FAULTS.length;
  process.stdout.write(`${ok ? 'GENERIC_DIFFERENTIAL_PASS' : 'GENERIC_DIFFERENTIAL_FAIL'} ruby=${expectedRuby} seeds=${seeds.length + goldens.genericCases.length} lines=${lines.size} cases=${cases.length} parsed_identically=${product.parsed} declined_by_both=${product.declined} differences=${product.problems.length} random_streams=${DIFFERENTIAL_RANDOM_STREAMS.length} random_cases=${randomCases.length} random_parsed_identically=${random.parsed} random_declined_by_both=${random.declined} random_differences=${random.problems.length} faults_detected=${faults - undetected.length}/${faults}\n`);
  const formats = await runFormatDifferential(expectedRuby);
  return ok && formats ? 0 : 1;
}

// ---------------------------------------------------------------- the other formats: browser versus generated Ruby
// The Generic Structural stage above covers the format whose bodies are written twice by hand. The other formats
// share one generated grammar for the Syslog header and the key=value body, but each still has code of its own on
// both sides (the JSON reader, the CSV tokenizer, the CEF/LEEF reader, the run-time field-loss check) and leans on
// a library of its engine (JSON.parse, CSV.parse_line). This stage holds the two sides to each other for every
// format: the browser preview calls an event completely parsed (FULL) exactly when the generated Ruby returns a
// record, and then the two field trees are the same. A PARTIAL or UNKNOWN preview is a record that the generated
// Ruby declines. Found on 2026-11-15 this way: ""a"" taken as a quoted CSV field by Ruby only, a form feed at a
// CSV field edge removed by the browser only, a row of spaces parsed by the browser only, an empty JSON object
// emitted by Ruby only, and a form feed after the last key=value pair rejected by the run-time check.
interface FormatConfig {
  name: string; extraction: Record<string, unknown>; draft: Record<string, unknown>; seeds: string[];
  /** Bookkeeping keys of the Ruby record that are not extracted fields. */ rubyOnlyKeys?: string[];
  /** Receiver settings of the compiled project that differ from the sample (the framing of a multi-line format). */ receiver?: Record<string, unknown>;
  /** One event is a group of lines up to a blank line (LF LF framing); LF is then part of an event. */ multiline?: boolean;
}
type PreviewFn = typeof preview;
type TokenizeFn = typeof tokenizeCSV;
const FORMAT_SPECIAL = ['"', "'", '\\', '=', ':', ',', ';', '[', ']', '{', '}', '|', '<', '>', '(', ')', '/', '-', '.', '0', '9', 'a', 'Z', ' ', '\t', '%', '^', '#', '@', '+', '*', '?', '!', '~', '`', '$', '&', '_',
  '\\"', '\\\\', '""', "''", '==', ': ', ', ', '; ', ' = ', '=""', '="', "='", '[]', '{}', '()', '::', '..', '--', '\u00e9', '\u4e2d', '\ud83d\ude00', 'e\u0301', '0x', '1e5', '-1', '1.5', 'null', 'true',
  'CEF:0|', 'LEEF:2.0|', '{"a":1}', 'a=b', '<13>', 'Oct 1 00:00:00 ', '\u00a0', '\u2028', '\ufeff', '\u0085', '\u000b', '\u000c', '\u001f', '\u007f', '\\n', '\\t', '\\u0041', '\\ud83d', '\\x41', '\\|', '\\=', '\\]',
  '  ', '\t\t', '+0530', 'Z', '.123', '99', '00', '1 ', '2 ', '- ', '-', '[a b="c"] ', 'k=v ', 'k="v w" ', 'k= ', '=v', '/* c */'];
function formatConfigs(): FormatConfig[] {
  const kvBody = (raw: string) => { const match = /^(?:<\d+>)?(?:\d )?.*? (\S+=.*)$/.exec(raw); return match ? match[1]! : raw; };
  const kvSeeds = [...new Set(goldens.cases.filter(item => item.body === 'kv').map(item => kvBody(item.raw)))].slice(0, 40);
  // Numbers at and around what a double holds exactly: the browser, Ruby and JSON text must agree on which
  // integers are kept and which decline the event, in every spelling.
  const jsonNumberSeeds = ['{"id":9007199254740991,"n":-9007199254740991}', '{"id":9007199254740992}', '{"id":9007199254740993}', '{"id":-9007199254740993}',
    '{"id":18446744073709551615}', '{"id":-9223372036854775808}', '{"n":123456789012345678901234567890}', '{"n":1e21}', '{"n":1E400}', '{"n":-1e400}',
    '{"n":0.1234567890123456789}', '{"n":-0}', '{"n":-0.0}', '{"n":1.0}', '{"n":1e2}', '{"n":4.9e-324}', '{"n":1.7976931348623157e308}', '{"n":9007199254740993.0}',
    '{"a":[9007199254740993,1]}', '{"a":{"b":12345678901234567890}}', '{"s":"9007199254740993"}', '{"n":9.007199254740993e15}', '{"n":1e16}', '{"n":10000000000000001}',
    // Decimals at the edge of what a double identifies: printed from a double (read) and one digit beyond (declined).
    '{"n":1731719701.123456}', '{"n":1731719701.1234567}', '{"n":1731719701.12345678}', '{"n":0.30000000000000004}', '{"n":1.0000000000000002}',
    '{"n":0.1000000000000000055511151231257827}', '{"n":123456789012345.6}', '{"n":1.5e-7}', '{"n":5e-324}', '{"n":2.5e-324}'];
  // The JSON source contract: eight nested levels are an event, nine are not. (An unpaired surrogate escape, the
  // other half of that contract, is also declined by the loss accounting, which cannot read it a second time.)
  const nested = (levels: number): string => '{"k":'.repeat(levels) + '1' + '}'.repeat(levels);
  const jsonDepthSeeds = [nested(7), nested(8), nested(9), nested(10), '{"a":[[[[[[[1]]]]]]]}', '{"a":[[[[[[[[1]]]]]]]]}', '{"a":{"b":[{"c":[{"d":[{"e":1}]}]}]}}'];
  const jsonSeeds = [...goldens.jsonCases.map(item => item.raw), ...jsonNumberSeeds, ...jsonDepthSeeds];
  const cefSeeds = goldens.familyCases.filter(item => item.family === 'cef').map(item => item.raw);
  const leefSeeds = goldens.familyCases.filter(item => item.family === 'leef').map(item => item.raw);
  const csvSeeds = [...new Set([...goldens.csvCases.filter(item => item.delimiter === ',').map(item => item.raw),
    'aaa,bbb,ccc', '"aaa","bbb","ccc"', 'aaa,"b,bb",ccc', 'aaa,"b""bb",ccc', ' aaa , bbb ,ccc', 'aaa,,ccc', '"a a", "b" ,c', '1,2026/10/16 15:44:21,TRAFFIC', ',,', ' , , ',
    // Blank for the browser's String#trim when the separator is TAB (third pass: the Unicode part of the blank rule was not exercised).
    '\u00a0,,', '\u3000,\u2028,\ufeff', '\u00a0,x,'])];
  const bodies: Record<string, string[]> = { kv: kvSeeds, json: jsonSeeds, raw: ['plain text message here', 'a=b not kv: really'], cef: cefSeeds, leef: leefSeeds };
  const heads = {
    syslog_rfc3164: ['<134>Nov 14 09:30:00 fw01 ', '<134>Nov 14 09:30:00 fw01 app[12]: '],
    syslog_rfc5424: ['<165>1 2026-11-14T09:30:00.123Z host app 123 ID47 - ', '<165>1 2026-11-14T09:30:00+09:00 host app - ID47 [meta@32473 a="b" c="d\\"e"] '],
  };
  const configs: FormatConfig[] = [
    { name: 'kv', extraction: { format: 'kv' }, draft: { format: 'kv' }, seeds: kvSeeds },
    { name: 'json', extraction: { format: 'json' }, draft: { format: 'json' }, seeds: jsonSeeds },
    { name: 'cef', extraction: { format: 'cef' }, draft: { format: 'cef' }, seeds: cefSeeds },
    { name: 'leef', extraction: { format: 'leef' }, draft: { format: 'leef' }, seeds: leefSeeds },
  ];
  for (const [label, delimiter] of [['comma', ','], ['semicolon', ';'], ['tab', '\t']] as const)
    configs.push({ name: 'csv-' + label, extraction: { format: 'csv', csvDelimiter: delimiter, csvColumns: ['c1', 'c2', 'c3'] },
      draft: { format: 'csv', csvDelimiter: delimiter, csvColumns: 'c1,c2,c3' }, seeds: csvSeeds.map(raw => raw.split(',').join(delimiter)) });
  for (const body of Object.keys(bodies)) for (const grammar of ['syslog_rfc3164', 'syslog_rfc5424'] as const)
    configs.push({ name: `${grammar}+${body}`, extraction: { format: grammar, syslogBodyFormat: body }, draft: { format: grammar, syslogBodyFormat: body },
      seeds: [...bodies[body]!.flatMap(raw => heads[grammar].map(head => head + raw)), ...(body === 'kv' ? goldens.cases.filter(item => item.grammar === grammar).map(item => item.raw) : [])] });
  // Second independent re-audit (2026-11-15): the mixed router, the Regex format and the forwarder-family template
  // were not compared. Mixed: every family alone and inside each Syslog envelope, with and without PRI and TAG,
  // and with white space in front of the message (no family: the router tests exact prefixes).
  const bsd = '<134>Nov 14 09:30:00 fw01 ', bsdTagged = '<134>Nov 14 09:30:00 fw01 app[12]: ', ietf = '<165>1 2026-11-14T09:30:00.123Z host app 123 ID47 - ';
  const ietfSd = '<165>1 2026-11-14T09:30:00+09:00 host app - ID47 [meta@32473 a="b" c="d\\"e"] ';
  const mixedSeeds = [...kvSeeds.slice(0, 12), ...jsonSeeds.slice(0, 6), ...cefSeeds.slice(0, 4), ...leefSeeds.slice(0, 3),
    ...kvSeeds.slice(0, 8).flatMap(raw => [bsd + raw, bsdTagged + raw, ietf + raw, ietfSd + raw, 'Nov 14 09:30:00 fw01 ' + raw, 'Nov 14 09:30:00 fw01 app: ' + raw,
      ietf + ' ' + raw, ietf + '\t' + raw, bsdTagged + ' ' + raw, bsdTagged + '\t' + raw]),
    ...jsonSeeds.slice(0, 4).flatMap(raw => [ietf + raw, ietf + ' ' + raw, bsd + raw]),
    ...cefSeeds.slice(0, 3).flatMap(raw => [bsd + raw, ietf + raw, ietf + ' ' + raw, bsdTagged + raw]),
    ...leefSeeds.slice(0, 2).flatMap(raw => [bsd + raw, ietf + raw]), 'aaa,bbb,ccc', '"a,a",b,c', 'a=1,b=2,c=3'];
  const mixed = (name: string, formats: string[], csv = false) => configs.push({ name,
    extraction: { format: 'mixed', mixedFormats: formats, ...(csv ? { csvDelimiter: ',', csvColumns: ['c1', 'c2', 'c3'] } : {}) },
    draft: { format: 'mixed', mixedFormats: formats, ...(csv ? { csvDelimiter: ',', csvColumns: 'c1,c2,c3' } : {}) }, seeds: mixedSeeds });
  mixed('mixed-kv-json-rfc3164kv-rfc5424kv', ['kv', 'json', 'rfc3164_kv', 'rfc5424_kv']);
  mixed('mixed-cef-leef-rfc5424json-rfc3164cef', ['cef', 'leef', 'rfc5424_json', 'rfc3164_cef']);
  mixed('mixed-rfc5424cef-rfc5424leef-rfc3164leef-json', ['rfc5424_cef', 'rfc5424_leef', 'rfc3164_leef', 'json']);
  mixed('mixed-kv-csv', ['kv', 'csv'], true);
  // Regex: two patterns with a static cost proof (the only ones that can be exported for Ruby 2.4.9).
  const regexSeeds = ['abc def ghi', '2026-11-14T09:30:00Z host1 message text here', 'a b', 'abc\u00a0def ghi jkl', 'x  y z', '12 x y', 'a=b c d', 'abc def ', 'fw01 443 allowed out', 'host.example 0 x', 'a:b 12 '];
  for (const [name, pattern] of [['regex-non-space-tokens', '^(?<ts>\\S+) (?<host>\\S+) (?<msg>.*)$'], ['regex-classes-and-digits', '^(?<a>[A-Za-z0-9_.:@%+/-]+) (?<b>[0-9]+) (?<rest>.*)$']] as const) {
    // A pattern without the proof is refused at export (TARGET_RUNTIME_REGEX_UNSUPPORTED) and, compiled anyway,
    // declines every event on Ruby 2.4.9; comparing it would compare nothing.
    if (!analyzeRuby24RegexCost(pattern).ok) throw new Error(`REGEX_CONFIG_WITHOUT_COST_PROOF ${name}`);
    configs.push({ name, extraction: { format: 'regex', pattern }, draft: { format: 'regex', pattern }, seeds: regexSeeds });
  }
  // Work order of 2026-11-15, item 3: what the gate did not reach. A Regex body inside each Syslog envelope.
  const bodyPattern = '^(?<a>[A-Za-z0-9_.:@%+/-]+) (?<b>[0-9]+) (?<rest>.*)$';
  if (!analyzeRuby24RegexCost(bodyPattern).ok) throw new Error('REGEX_CONFIG_WITHOUT_COST_PROOF syslog+regex');
  for (const grammar of ['syslog_rfc3164', 'syslog_rfc5424'] as const)
    configs.push({ name: `${grammar}+regex`, extraction: { format: grammar, syslogBodyFormat: 'regex', pattern: bodyPattern },
      draft: { format: grammar, syslogBodyFormat: 'regex', pattern: bodyPattern }, seeds: regexSeeds.flatMap(raw => heads[grammar].map(head => head + raw)) });
  // The two formats whose event is a group of lines (LF LF framing): a Java stack trace and multi-line JSON.
  const blankLine = { guided: { eventBoundary: 'blank-line', receiver: { messageLimit: 65536 } } };
  const javaSeeds = [
    'java.lang.IllegalStateException: boom\n\tat com.example.App.run(App.java:42)\n\tat com.example.Main.main(Main.java:7)',
    'java.io.IOException: disk full\n\tat a.B.c(B.java:1)\nCaused by: java.lang.RuntimeException: inner\n\tat a.B.d(B.java:2)\n\t... 3 more',
    'java.lang.NullPointerException\n\tat x.Y.z(Y.java:10)',
    'org.example.DataException: bad row \u00e9\ud83d\ude00 = x\n\tat org.example.Loader.load(Loader.java:120)\n\tat org.example.Loader.main(Loader.java:12)\nCaused by: java.sql.SQLException: timeout\n\tat org.example.Db.query(Db.java:55)',
    'java.lang.IllegalStateException: boom', 'java.lang.IllegalStateException: boom\n\tat', 'not a trace\nat all',
  ];
  configs.push({ name: 'java_stacktrace', multiline: true, receiver: { protocols: ['tcp'], tcpFraming: 'blank_line_java' },
    extraction: { format: 'java_stacktrace' }, draft: { format: 'java_stacktrace', ...blankLine }, seeds: javaSeeds });
  const prettyJson = (raw: string): string[] => { try { return [JSON.stringify(JSON.parse(raw), null, 2), JSON.stringify(JSON.parse(raw), null, '\t')]; } catch { return []; } };
  configs.push({ name: 'json-blank-line', multiline: true, receiver: { protocols: ['tcp'], tcpFraming: 'blank_line_json' },
    extraction: { format: 'json' }, draft: { format: 'json', ...blankLine }, seeds: jsonSeeds.flatMap(raw => [raw, ...prettyJson(raw)]) });
  // Declared forwarder (the forwarder-family template): direct events, one and two relay hops, an undeclared relay, too many hops.
  const relay = '<13>Nov 14 09:30:00 relay1 fwd: ', relayIetf = '<13>1 2026-11-14T09:30:00Z relay1 fwd - - - ';
  configs.push({ name: 'forwarder-kv', rubyOnlyKeys: ['__parserstudio_forwarder_hops'],
    extraction: { format: 'kv', forwarder: { relayHosts: ['relay1', '10.9.9.9'], maxHops: 2 } }, draft: { format: 'kv', forwarder: { relayHosts: ['relay1', '10.9.9.9'], maxHops: 2 } },
    seeds: kvSeeds.slice(0, 10).flatMap(raw => [raw, relay + raw, relayIetf + raw, relay + relayIetf + raw, '<13>Nov 14 09:30:00 other fwd: ' + raw, relay + relay + relay + raw]) });
  configs.push({ name: 'forwarder-syslog_rfc5424+kv', rubyOnlyKeys: ['__parserstudio_forwarder_hops'],
    extraction: { format: 'syslog_rfc5424', syslogBodyFormat: 'kv', forwarder: { relayHosts: ['relay1'], maxHops: 1 } }, draft: { format: 'syslog_rfc5424', syslogBodyFormat: 'kv', forwarder: { relayHosts: ['relay1'], maxHops: 1 } },
    seeds: kvSeeds.slice(0, 10).flatMap(raw => [ietf + raw, relay + ietf + raw, relay + relay + ietf + raw, ietfSd + raw]) });
  return configs;
}
/** A text that LF LF framing delivers as one event and the browser's blank-line boundary reads as one event. */
const oneFramedEvent = (raw: string): boolean => !raw.includes('\r') && !raw.split('\n').some(line => line.trim().length === 0);
function formatLines(seeds: string[], seed: number, count: number, multiline = false): string[] {
  const usable = (raw: string): boolean => raw.length > 0 && !loneSurrogate(raw) && (multiline ? oneFramedEvent(raw) : !/[\n\r]/.test(raw));
  let state = seed >>> 0;
  const random = () => { state ^= state << 13; state >>>= 0; state ^= state >>> 17; state ^= state << 5; state >>>= 0; return state / 4294967296; };
  const pick = <T,>(list: T[]): T => list[Math.floor(random() * list.length)]!;
  const lines = new Set<string>(seeds.filter(usable));
  const target = lines.size + count;
  for (let attempt = 0; lines.size < target && attempt < count * 20; attempt += 1) {
    let raw = pick(seeds);
    const operations = 1 + Math.floor(random() * 3);
    for (let operation = 0; operation < operations; operation += 1) {
      const points = [...raw];
      const at = Math.floor(random() * (points.length + 1));
      const kind = random();
      if (kind < 0.4) points.splice(at, 0, pick(FORMAT_SPECIAL));
      else if (kind < 0.6) points.splice(at, 1);
      else if (kind < 0.8) points.splice(at, 1, pick(FORMAT_SPECIAL));
      else if (kind < 0.9) points.splice(at, 0, ...points.slice(at, at + 1 + Math.floor(random() * 10)));
      else points.length = at;
      raw = points.join('');
    }
    // One event is one line, or one blank-line framed group of lines; what line endings do is the subject of the
    // line-ending stage (lineEndingProblems).
    if (usable(raw)) lines.add(raw);
  }
  return [...lines];
}
/** CSV rows for the tokenizer comparison: every string of up to six symbols over a, the quotation mark, the separator and SP, and a pseudo-random stream over a wider alphabet. */
function csvRows(separator: string, seed: number, count: number): string[] {
  const rows = new Set<string>();
  const small = ['a', '"', separator, ' '];
  const extend = (prefix: string, depth: number) => { if (prefix) rows.add(prefix); if (depth > 0) for (const symbol of small) extend(prefix + symbol, depth - 1); };
  extend('', 6);
  const alphabet = ['a', 'b', '"', '"', separator, separator, ' ', '\t', '""', 'x y', '\u00a0', '\u00e9', '\u2028', '\\', "'", '\u000b', '\u000c', '\ud83d\ude00'];
  let state = seed >>> 0;
  const random = () => { state ^= state << 13; state >>>= 0; state ^= state >>> 17; state ^= state << 5; state >>>= 0; return state / 4294967296; };
  const target = rows.size + count;
  while (rows.size < target) { let row = ''; const length = 1 + Math.floor(random() * 12); for (let at = 0; at < length; at += 1) row += alphabet[Math.floor(random() * alphabet.length)]!; rows.add(row); }
  return [...rows];
}
const FORMAT_TS_FAULTS: Mutant[] = [
  // The browser strips form feed and vertical tab at the edge of an unquoted CSV field again; the generated parser keeps them.
  { id: 'ts-format-csv-form-feed-stripped', file: 'src/grammar/extractEvent.ts', find: "while (end > start && (token[end - 1] === ' ' || token[end - 1] === '\\t')) end -= 1;", replace: "while (end > start && (token[end - 1] === ' ' || token[end - 1] === '\\t' || token[end - 1] === '\\f')) end -= 1;" },
  // The browser returns one empty field for a row of spaces again.
  { id: 'ts-format-csv-empty-row-parsed', file: 'src/grammar/extractEvent.ts', find: "  if (out.length === 1 && out[0] === null) return null;\n", replace: "" },
  // The JSON format drops its source contract (8 levels, paired surrogates) in the browser.
  { id: 'ts-format-json-source-contract-removed', file: 'src/grammar/extractEvent.ts', find: "if (!jsonSourceValueValid(parsed)) return failure(", replace: "if (false) return failure(" },
  // The browser's field-loss check splits tokens at SP and TAB only again: a form feed after the last pair makes a complete event PARTIAL.
  // The browser's mixed router asks for PRI in front of a BSD timestamp again; the generated Ruby does not.
  { id: 'ts-format-mixed-bsd-envelope-needs-pri', file: 'src/grammar/extractEvent.ts', find: "const BSD_ENVELOPE = new RegExp('^(?:<\\\\d{1,3}>)?' + SYSLOG_HEADER_TOKENS.BSD_MONTH", replace: "const BSD_ENVELOPE = new RegExp('^<\\\\d{1,3}>' + SYSLOG_HEADER_TOKENS.BSD_MONTH" },
  // The browser's mixed router takes a key=value message that starts with white space again (it tried every body parser).
  { id: 'ts-format-mixed-message-prefix-not-exact', file: 'src/grammar/extractEvent.ts', find: "      KEY_VALUE_START.test(message) ? 'kv' as const : null;", replace: "      /^[ \\t]*[A-Za-z_][A-Za-z0-9_.-]*=/u.test(message) ? 'kv' as const : null;" },
  { id: 'ts-format-guard-form-feed-in-value', file: 'src/grammar/parseStatus.ts', find: "const GAP_RUN = /[ \\t\\n\\x0b\\f\\r]*/uy;\nconst TOKEN_RUN = /[^ \\t\\n\\x0b\\f\\r]*/uy;", replace: "const GAP_RUN = /[ \\t]*/uy;\nconst TOKEN_RUN = /[^ \\t]*/uy;" },
];
// The translation and runtime faults that change what an artifact of these formats returns for a generated line.
// regex-line-anchors, runtime-undefined-exported-as-null, runtime-large-number-not-an-integer and
// runtime-split-drops-trailing-fields leave every result of this stage unchanged; the translation conformance
// probes detect them (scripts/verification/translation-conformance.ts). translation-split-ruby belonged here until
// the loss accounting existed: Ruby's split drops the empty LEEF attribute after a trailing delimiter, the faulty
// reader accepts the line, and src/grammar/lossGuard.ts now declines it (the delimiter is in no attribute), as the
// browser does. The Generic Structural stage above still detects that fault.
const FORMAT_RUBY_FAULTS: Mutant[] = [
  'translation-regex-sticky-unanchored', 'translation-truthiness-ruby', 'translation-null-is-nil', 'translation-length-in-characters',
  'translation-number-to-i', 'runtime-json-null-is-absent', 'runtime-empty-string-is-true',
  'runtime-zero-is-true', 'runtime-length-in-characters',
].map(fault => translationFault(fault, 'format'));
const FORMAT_STREAM = 401;
const FORMAT_LINES_PER_CONFIG = 1500;
const CSV_ROWS_PER_SEPARATOR = 3000;

interface FormatCase { id: string; config: string; raw: string }
function formatProblems(run: PreviewFn, draft: typeof createDraft, configs: Map<string, FormatConfig>, cases: FormatCase[], results: Record<string, RubyExtract>, prefix: string): { problems: string[]; parsed: number; declined: number } {
  const problems: string[] = [];
  let parsed = 0, declined = 0;
  for (const item of cases) {
    const ruby = results[prefix + item.id];
    if (!ruby || ruby.raised) { problems.push(`${item.id}: the generated Ruby ${ruby ? 'raised ' + ruby.raised : 'returned nothing'}: ${JSON.stringify(item.raw).slice(0, 140)}`); continue; }
    let events: ReturnType<PreviewFn>['events'];
    try { events = run(item.raw, { ...draft(), ...configs.get(item.config)!.draft } as ReturnType<typeof createDraft>).events; } catch (error) { problems.push(`${item.id}: the browser preview raised ${String(error).slice(0, 80)}`); continue; }
    const full = events.length === 1 && events[0]!.parseStatus === 'FULL';
    const rubyParsed = ruby.value !== undefined && ruby.value !== null;
    if (full !== rubyParsed) problems.push(`${item.id}: ${full ? 'FULL in the browser, declined by the generated Ruby' : `parsed by the generated Ruby, ${events.length === 1 ? String(events[0]!.parseStatus) : events.length + ' events'} in the browser`}: ${JSON.stringify(item.raw).slice(0, 140)}`);
    else if (full && canonicalTree(events[0]!.fields) !== canonicalTree(withoutKeys(ruby.value, configs.get(item.config)!.rubyOnlyKeys))) problems.push(`${item.id}: different field tree: ${JSON.stringify(item.raw).slice(0, 140)}`);
    else if (full) parsed += 1; else declined += 1;
  }
  return { problems, parsed, declined };
}
const withoutKeys = (value: unknown, keys: string[] | undefined): unknown =>
  keys && value !== null && typeof value === 'object' && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([key]) => !keys.includes(key))) : value;
// ------------------------------------------------------------------------------------------------ line endings
// What reaches the generated parser is a frame: the receiver cuts the byte stream at LF (or at LF LF for the two
// multi-line formats). The browser preview reads the same stream as lines (CRLF or LF) or as groups of lines. This
// stage holds the two to each other on streams instead of single lines: every frame the receiver would deliver is
// given to the generated Ruby, and the events of the preview of the whole stream must be the same events, in order.
interface StreamCase { id: string; config: string; stream: string; frames: string[] }
function lineEndingStreams(config: FormatConfig, valid: string[]): StreamCase[] {
  const out: StreamCase[] = [];
  const add = (stream: string) => {
    // The receiver's framing: LF LF for a multi-line format, LF otherwise; a terminator at the end of the stream
    // leaves no frame behind it.
    const pieces = stream.split(config.multiline ? '\n\n' : '\n');
    if (pieces[pieces.length - 1] === '') pieces.pop();
    out.push({ id: `${config.name}/stream${out.length}`, config: config.name, stream, frames: pieces });
  };
  valid.slice(0, 12).forEach((first, index) => {
    const second = valid[(index + 1) % valid.length]!;
    const middle = Math.floor(first.length / 2);
    if (config.multiline) {
      add(first + '\n\n' + second);
      add(first.split('\n').join('\r\n') + '\n\n' + second);
      add(first.slice(0, middle) + '\r' + first.slice(middle) + '\n\n' + second);
      add(first + '\n\n' + second + '\n\n');
      return;
    }
    add(first + '\r\n');
    add(first + '\r\n' + second + '\r\n');
    add(first + '\n' + second);
    add(first + '\n\n' + second + '\n');
    add(first + '\r\r\n');
    add('\r' + first + '\n');
    add(first.slice(0, middle) + '\r' + first.slice(middle) + '\n');
    add(' \r\n' + first + '\r\n');
    add(first + '\r\n\r\n' + second + '\r\n');
    add(first + ' \r\n' + second + '\t\r\n');
  });
  return out;
}
function lineEndingProblems(run: PreviewFn, draft: typeof createDraft, configs: Map<string, FormatConfig>, streams: StreamCase[], results: Record<string, RubyExtract>): { problems: string[]; events: number; declined: number } {
  const problems: string[] = [];
  let parsed = 0, declined = 0;
  for (const item of streams) {
    const config = configs.get(item.config)!;
    let events: ReturnType<PreviewFn>['events'];
    try { events = run(item.stream, { ...draft(), ...config.draft } as ReturnType<typeof createDraft>).events; } catch (error) { problems.push(`${item.id}: the browser preview raised ${String(error).slice(0, 80)}`); continue; }
    let next = 0;
    item.frames.forEach((frame, index) => {
      const ruby = results[`${item.id}#${index}`];
      const where = `${item.id} frame ${index} of ${JSON.stringify(item.stream).slice(0, 120)}`;
      if (!ruby || ruby.raised) { problems.push(`${where}: the generated Ruby ${ruby ? 'raised ' + ruby.raised : 'returned nothing'}`); return; }
      const rubyParsed = ruby.value !== undefined && ruby.value !== null;
      // The line as the preview sees it: the CR of a CRLF terminator is not part of it. A blank line is no event.
      const line = !config.multiline && frame.endsWith('\r') ? frame.slice(0, -1) : frame;
      if (line.split('\n').every(part => part.trim().length === 0)) {
        if (rubyParsed) problems.push(`${where}: a blank line was parsed by the generated Ruby`); else declined += 1;
        return;
      }
      const event = events[next];
      next += 1;
      if (!event) { problems.push(`${where}: the browser preview has no event for this frame`); return; }
      const full = event.parseStatus === 'FULL';
      if (full !== rubyParsed) problems.push(`${where}: ${full ? 'FULL in the browser, declined by the generated Ruby' : 'parsed by the generated Ruby, ' + String(event.parseStatus) + ' in the browser'}`);
      else if (full && canonicalTree(event.fields) !== canonicalTree(withoutKeys(ruby.value, config.rubyOnlyKeys))) problems.push(`${where}: different field tree`);
      else if (full) parsed += 1; else declined += 1;
    });
    if (next !== events.length) problems.push(`${item.id}: the browser preview has ${events.length} events, the receiver delivers ${next} frames that are not blank: ${JSON.stringify(item.stream).slice(0, 120)}`);
  }
  return { problems, events: parsed, declined };
}

interface CsvRowCase { id: string; separator: string; raw: string }
function csvRowProblems(tokenize: TokenizeFn, cases: CsvRowCase[], results: Record<string, RubyExtract>, prefix: string): { problems: string[]; parsed: number; declined: number } {
  const problems: string[] = [];
  let parsed = 0, declined = 0;
  for (const item of cases) {
    const ruby = results[prefix + item.id];
    if (!ruby || ruby.raised) { problems.push(`${item.id}: the generated Ruby ${ruby ? 'raised ' + ruby.raised : 'returned nothing'}: ${JSON.stringify(item.raw)}`); continue; }
    const browser = tokenize(item.raw, item.separator);
    const rubyRow = ruby.value === undefined || ruby.value === null ? null : ruby.value;
    if (JSON.stringify(browser) !== JSON.stringify(rubyRow)) problems.push(`${item.id}: browser ${JSON.stringify(browser)} generated Ruby ${JSON.stringify(rubyRow)} for ${JSON.stringify(item.raw)}`);
    else if (browser) parsed += 1; else declined += 1;
  }
  return { problems, parsed, declined };
}

async function runFormatDifferential(expectedRuby: string): Promise<boolean> {
  const configs = new Map(formatConfigs().map(config => [config.name, config]));
  const fragments: Record<string, string> = {};
  const cases: FormatCase[] = [];
  const perConfig: FormatCase[][] = [];
  for (const config of configs.values()) {
    const project = sampleProject() as unknown as Record<string, any>;
    project.extraction = config.extraction;
    project.normalization.topFields = {};
    project.normalization.nsFields = {};
    project.normalization.vendorFields = { differential_probe: { normalized_name: 'differential_probe', data_type: 'string' } };
    project.classification = { defaultIndex: 'syslog', rules: [] };
    if (config.receiver) Object.assign(project.receiver, config.receiver);
    fragments[`format:${config.name}`] = compilePair(project).files.find(file => !file.name.endsWith('.conf'))!.content;
    perConfig.push(formatLines(config.seeds, FORMAT_STREAM, FORMAT_LINES_PER_CONFIG, config.multiline === true).map((raw, index) => ({ id: `${config.name}#${index}`, config: config.name, raw })));
  }
  // The cases are interleaved, one configuration after the other, so that every batch holds lines of every
  // configuration and an injected fault is met in the first batches whatever format it lives in.
  for (let index = 0; perConfig.some(list => index < list.length); index += 1)
    for (const list of perConfig) if (index < list.length) cases.push(list[index]!);
  const csvCasesList: CsvRowCase[] = [];
  for (const [label, separator] of [['comma', ','], ['semicolon', ';'], ['tab', '\t']] as const)
    csvRows(separator, FORMAT_STREAM, CSV_ROWS_PER_SEPARATOR).forEach((raw, index) => csvCasesList.push({ id: `csvrow-${label}#${index}`, separator, raw }));
  const csvFragment = (separator: string) => `format:csv-${separator === ',' ? 'comma' : separator === ';' ? 'semicolon' : 'tab'}`;
  const formatPayload = (item: FormatCase, fragment: string, prefix = '') => ({ id: prefix + item.id, fragment, raw: item.raw, call: 'format_extract' });
  const csvPayload = (item: CsvRowCase, fragment: string, prefix = '') => ({ id: prefix + item.id, fragment, raw: item.raw, call: 'csv_tokens', separator: item.separator });
  const results = rubyExtractBatches('FORMAT_DIFFERENTIAL', fragments, [
    ...cases.map(item => formatPayload(item, `format:${item.config}`)),
    ...csvCasesList.map(item => csvPayload(item, csvFragment(item.separator))),
  ], expectedRuby);
  if (!results) return false;
  const product = formatProblems(preview, createDraft, configs, cases, results, '');
  report('FORMAT_DIFFERENTIAL', product.problems.slice(0, 40));
  // Every configuration must have been exercised on both sides of the decision: at least one event that both
  // engines parse completely and one that both decline. A configuration that only declines compares nothing.
  const vacuous: string[] = [];
  for (const name of configs.keys()) {
    const own = formatProblems(preview, createDraft, configs, cases.filter(item => item.config === name), results, '');
    process.stdout.write(`FORMAT_DIFFERENTIAL_CONFIG ${name} full_and_identical=${own.parsed} declined_by_both=${own.declined} differences=${own.problems.length}\n`);
    if (own.parsed === 0 || own.declined === 0) vacuous.push(name);
  }
  if (vacuous.length) report('FORMAT_DIFFERENTIAL_VACUOUS_CONFIG', vacuous);
  const rows = csvRowProblems(tokenizeCSV, csvCasesList, results, '');
  report('CSV_ROW_DIFFERENTIAL', rows.problems.slice(0, 40));
  // Line endings: streams built from events both engines parse completely, cut into frames as the receiver does.
  const streams: StreamCase[] = [];
  for (const config of configs.values()) {
    const valid = cases.filter(item => item.config === config.name).map(item => item.raw).filter(raw => {
      const events = preview(raw, { ...createDraft(), ...config.draft } as ReturnType<typeof createDraft>).events;
      return events.length === 1 && events[0]!.parseStatus === 'FULL';
    });
    streams.push(...lineEndingStreams(config, valid));
  }
  const frameResults = rubyExtractBatches('LINE_ENDING_DIFFERENTIAL', fragments,
    streams.flatMap(item => item.frames.map((frame, index) => ({ id: `${item.id}#${index}`, fragment: `format:${item.config}`, raw: frame, call: 'format_extract' }))), expectedRuby);
  if (!frameResults) return false;
  const lineEndings = lineEndingProblems(preview, createDraft, configs, streams, frameResults);
  report('LINE_ENDING_DIFFERENTIAL', lineEndings.problems.slice(0, 40));
  process.stdout.write(`LINE_ENDING_DIFFERENTIAL streams=${streams.length} frames=${streams.reduce((sum, item) => sum + item.frames.length, 0)} events_identical=${lineEndings.events} declined_by_both=${lineEndings.declined} differences=${lineEndings.problems.length}\n`);
  const undetected: string[] = [];
  // A fault is compiled into every Fragment that holds its target text and run on the cases of those formats,
  // batch by batch, until a batch reports more differences than the product does on the same cases.
  for (const fault of FORMAT_RUBY_FAULTS) {
    // A translation fault is injected into the generated grammar of every Fragment whose grammar it changes.
    const faulty: Record<string, string> = {};
    const hit: string[] = [];
    for (const name of configs.keys()) {
      const fragment = fragments[`format:${name}`]!;
      if (fault.file === 'translation') {
        try { faulty[`${fault.id}@${name}`] = applyMutant(fragment, fault); } catch (error) {
          if (!String(error).includes('TRANSLATION_FAULT_NOT_APPLICABLE')) throw error;
          continue;
        }
      } else if (fragment.split(fault.find).length === 2) faulty[`${fault.id}@${name}`] = applyMutant(fragment, fault);
      else continue;
      hit.push(name);
    }
    if (hit.length === 0) throw new Error(`MUTANT_NOT_APPLICABLE ${fault.id}: target text is in no compiled Fragment`);
    const scopedCases = cases.filter(item => hit.includes(item.config));
    // The row tokenizer is run again only for a fault that lives in the CSV Fragments alone.
    const scopedRows = hit.every(name => name.startsWith('csv-')) ? csvCasesList.filter(item => hit.includes(csvFragment(item.separator).slice('format:'.length))) : [];
    let found = 0, ran = 0;
    for (let start = 0; start < scopedRows.length && found === 0; start += FAULT_BATCH) {
      const batch = scopedRows.slice(start, start + FAULT_BATCH);
      const faultResults = rubyExtractBatches('FORMAT_DIFFERENTIAL', faulty, batch.map(item => csvPayload(item, `${fault.id}@${csvFragment(item.separator).slice('format:'.length)}`, `${fault.id}::`)), expectedRuby);
      if (!faultResults) return false;
      ran += batch.length;
      found = csvRowProblems(tokenizeCSV, batch, faultResults, `${fault.id}::`).problems.length - csvRowProblems(tokenizeCSV, batch, results, '').problems.length;
    }
    for (let start = 0; start < scopedCases.length && found === 0; start += FAULT_BATCH) {
      const batch = scopedCases.slice(start, start + FAULT_BATCH);
      const faultResults = rubyExtractBatches('FORMAT_DIFFERENTIAL', faulty, batch.map(item => formatPayload(item, `${fault.id}@${item.config}`, `${fault.id}::`)), expectedRuby);
      if (!faultResults) return false;
      ran += batch.length;
      found = formatProblems(preview, createDraft, configs, batch, faultResults, `${fault.id}::`).problems.length - formatProblems(preview, createDraft, configs, batch, results, '').problems.length;
    }
    process.stdout.write(`FORMAT_DIFFERENTIAL_FAULT ${fault.id} ${found > 0 ? 'DETECTED' : 'UNDETECTED'} new_differences=${found} cases_run=${ran} fragments=${hit.length}\n`);
    if (found <= 0) undetected.push(fault.id);
  }
  for (const fault of FORMAT_TS_FAULTS) {
    const loaded = await pipelineFromCopy(fault);
    const found = formatProblems(loaded.preview, loaded.createDraft, configs, cases, results, '').problems.length - product.problems.length +
      csvRowProblems(loaded.tokenizeCSV, csvCasesList, results, '').problems.length - rows.problems.length;
    loaded.dispose();
    process.stdout.write(`FORMAT_DIFFERENTIAL_FAULT ${fault.id} ${found > 0 ? 'DETECTED' : 'UNDETECTED'} new_differences=${found} cases_run=${cases.length + csvCasesList.length}\n`);
    if (found <= 0) undetected.push(fault.id);
  }
  if (undetected.length) report('FORMAT_DIFFERENTIAL_FAULT_UNDETECTED', undetected);
  const faults = FORMAT_RUBY_FAULTS.length + FORMAT_TS_FAULTS.length;
  const ok = product.problems.length === 0 && rows.problems.length === 0 && undetected.length === 0 && vacuous.length === 0 && rows.parsed > 0 && rows.declined > 0 &&
    lineEndings.problems.length === 0 && lineEndings.events > 0 && lineEndings.declined > 0;
  process.stdout.write(`${ok ? 'FORMAT_DIFFERENTIAL_PASS' : 'FORMAT_DIFFERENTIAL_FAIL'} ruby=${expectedRuby} formats=${configs.size} cases=${cases.length} full_and_identical=${product.parsed} declined_by_both=${product.declined} differences=${product.problems.length} csv_rows=${csvCasesList.length} csv_rows_identical=${rows.parsed} csv_rows_declined_by_both=${rows.declined} csv_row_differences=${rows.problems.length} faults_detected=${faults - undetected.length}/${faults}\n`);
  return ok;
}


const mode = process.argv[2];
if (mode === 'ts') process.exit(await runTs());
else if (mode === 'native') process.exit(runNative());
else if (mode === 'python') process.exit(runPython());
else if (mode === 'differential') process.exit(await runDifferential());
else if (mode === 'mutants') {
  // Applicability of every source mutant: its target text must occur exactly once in its file.
  const lists: Record<string, Mutant[]> = { TS_MUTANTS, TS_GENERIC_MUTANTS, TS_FAMILY_MUTANTS, TS_CSV_MUTANTS, TS_JSON_MUTANTS, PYTHON_MUTANTS, DIFFERENTIAL_TS_FAULTS, FORMAT_TS_FAULTS };
  let stale = 0;
  for (const [name, list] of Object.entries(lists)) for (const mutant of list) {
    if (['contract', 'translation', 'fragment'].includes(mutant.file)) continue;
    const path = [join(REPO, mutant.file), join(REPO, 'runtime/multipass', mutant.file)].find(candidate => { try { return statSync(candidate).isFile(); } catch { return false; } });
    const count = path ? readFileSync(path, 'utf8').split(mutant.find).length - 1 : -1;
    if (count !== 1) { stale += 1; process.stdout.write(`MUTANT_STALE ${name} ${mutant.id} file=${mutant.file} occurrences=${count} find=${JSON.stringify(mutant.find).slice(0, 150)}\n`); }
  }
  process.stdout.write(`MUTANT_APPLICABILITY stale=${stale}\n`);
  process.exit(stale ? 1 : 0);
}
else { process.stderr.write('usage: semantic-oracle.ts ts|native|python|differential|mutants\n'); process.exit(2); }
