#!/usr/bin/env node
// Grammar contract code generator.
//
// contracts/syslog-header-grammar.v1.json is the only place where the Syslog
// header grammar is defined. This script validates the contract, compiles each
// rule to an anchored regular expression per runtime dialect and writes the
// generated consumers. `--verify` (CI) fails when a generated file differs from
// what the contract produces, so a hand edit of generated code cannot ship.
//
//   node scripts/grammar/generate-grammar.mjs --write
//   node scripts/grammar/generate-grammar.mjs --verify
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CONTRACT_PATH = 'contracts/syslog-header-grammar.v1.json';
export const GENERATED_TS_PATH = 'src/grammar/syslogHeaderGrammar.generated.ts';
export const DIALECTS = Object.freeze(['js', 'ruby', 'python']);

const ALLOWED_ESCAPES = new Set(['\\', '{', '}', '[', ']', '(', ')', '|', '.', '+', '*', '?', '^', '$', 'r', 'n', 't', '-']);

/** Rejects every construct whose meaning differs between ECMAScript, Ruby 2.4 and Python. */
export function validateTokenPattern(name, pattern) {
  const fail = why => { throw new Error(`GRAMMAR_TOKEN_NOT_PORTABLE ${name}: ${why}`); };
  if (typeof pattern !== 'string' || pattern.length === 0) fail('empty pattern');
  let i = 0, inClass = false, depth = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    const code = c.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) fail('non-ASCII or control character');
    if (c === '#' || c === '/') fail(`'${c}' is not allowed (interpolation or delimiter in a consumer dialect)`);
    if (c === '\\') {
      if (!ALLOWED_ESCAPES.has(pattern[i + 1])) fail(`escape \\${pattern[i + 1]} is not in the portable subset`);
      i += 2; continue;
    }
    if (inClass) {
      if (c === '[') fail('nested bracket class');
      if (c === ']') inClass = false;
      i += 1; continue;
    }
    if (c === '[') {
      inClass = true; i += 1;
      if (pattern[i] === '^') i += 1;
      if (pattern[i] === ']') fail('empty or leading-] bracket class');
      continue;
    }
    if (c === '(') {
      if (!pattern.startsWith('(?:', i) && !pattern.startsWith('(?!', i)) fail('only (?: ) and (?! ) groups are allowed; captures belong to rules');
      depth += 1; i += 3; continue;
    }
    if (c === ')') { depth -= 1; if (depth < 0) fail('unbalanced )'); i += 1; continue; }
    if (c === '.' || c === '^' || c === '$') fail(`'${c}' has runtime-dependent meaning`);
    if (c === '{') {
      const m = /^\{[0-9]+(?:,[0-9]*)?\}/.exec(pattern.slice(i));
      if (!m) fail('malformed bounded quantifier');
      i += m[0].length;
      if (pattern[i] === '?' || pattern[i] === '+') fail('lazy or possessive quantifier');
      continue;
    }
    if (c === '+' || c === '*' || c === '?') {
      if (pattern[i + 1] === '?' || pattern[i + 1] === '+') fail('lazy or possessive quantifier');
      i += 1; continue;
    }
    if (c === '}' || c === ']') fail(`unbalanced ${c}`);
    i += 1;
  }
  if (inClass || depth !== 0) fail('unterminated class or group');
}

const escapeLiteral = text => text.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&').replace(/ /g, '[ ]');

function emitSequence(sequence, contract, dialect, captures, ruleName) {
  if (!Array.isArray(sequence) || sequence.length === 0) throw new Error(`GRAMMAR_RULE_INVALID ${ruleName}: empty sequence`);
  return sequence.map(item => {
    const keys = Object.keys(item);
    if (keys.length === 1 && typeof item.lit === 'string' && item.lit.length > 0 && /^[\x20-\x7e]+$/.test(item.lit) && !/[#/]/.test(item.lit))
      return escapeLiteral(item.lit);
    if (keys.length === 1 && item.sp === '+') return '[ ]+';
    if (keys.length === 1 && item.sp === '1') return '[ ]';
    if (keys.length === 1 && Array.isArray(item.optional))
      return '(?:' + emitSequence(item.optional, contract, dialect, captures, ruleName) + ')?';
    if (typeof item.token === 'string' && keys.every(key => key === 'token' || key === 'cap')) {
      const token = contract.tokens[item.token];
      if (!token) throw new Error(`GRAMMAR_RULE_INVALID ${ruleName}: unknown token ${item.token}`);
      if (item.cap === undefined) return '(?:' + token.pattern + ')';
      if (!/^[a-z][a-z0-9_]{0,31}$/.test(item.cap) || captures.includes(item.cap))
        throw new Error(`GRAMMAR_RULE_INVALID ${ruleName}: bad or duplicate capture ${item.cap}`);
      captures.push(item.cap);
      return (dialect === 'python' ? '(?P<' : '(?<') + item.cap + '>' + token.pattern + ')';
    }
    throw new Error(`GRAMMAR_RULE_INVALID ${ruleName}: unsupported sequence item ${JSON.stringify(item)}`);
  }).join('');
}

/** Compiles one rule to an anchored whole-line pattern for a runtime dialect. */
export function compileRule(contract, ruleName, dialect) {
  if (!DIALECTS.includes(dialect)) throw new Error(`GRAMMAR_DIALECT_UNKNOWN ${dialect}`);
  const rule = contract.rules[ruleName];
  if (!rule) throw new Error(`GRAMMAR_RULE_UNKNOWN ${ruleName}`);
  const captures = [];
  const body = emitSequence(rule.sequence, contract, dialect, captures, ruleName);
  const [open, close] = dialect === 'js' ? ['^', '$'] : dialect === 'ruby' ? ['\\A', '\\z'] : ['\\A', '\\Z'];
  return { source: open + body + close, captures };
}

export function validateContract(contract) {
  if (contract.schema !== 'parserstudio.grammar-contract.v1' || !Number.isInteger(contract.revision))
    throw new Error('GRAMMAR_CONTRACT_SCHEMA');
  for (const [name, token] of Object.entries(contract.tokens)) {
    if (!/^[A-Z][A-Z0-9_]{0,31}$/.test(name)) throw new Error(`GRAMMAR_TOKEN_NAME ${name}`);
    validateTokenPattern(name, token.pattern);
  }
  const used = new Set();
  const walk = sequence => sequence.forEach(item => {
    if (item.token) used.add(item.token);
    if (item.optional) walk(item.optional);
  });
  for (const [name, rule] of Object.entries(contract.rules)) {
    if (!/^[a-z][a-z0-9_]{0,47}$/.test(name)) throw new Error(`GRAMMAR_RULE_NAME ${name}`);
    walk(rule.sequence);
    const reference = compileRule(contract, name, 'js');
    for (const dialect of DIALECTS) {
      const compiled = compileRule(contract, name, dialect);
      if (compiled.captures.join() !== reference.captures.join()) throw new Error(`GRAMMAR_CAPTURE_DRIFT ${name}`);
    }
    new RegExp(reference.source); // must at least be a valid ECMAScript expression
  }
  for (const name of Object.keys(contract.tokens))
    if (!used.has(name)) throw new Error(`GRAMMAR_TOKEN_UNUSED ${name}`);
  for (const [name, list] of Object.entries(contract.alternatives ?? {}))
    for (const rule of list) if (!contract.rules[rule]) throw new Error(`GRAMMAR_ALTERNATIVE_UNKNOWN ${name}/${rule}`);
  const semantics = contract.semantics;
  if (!Number.isInteger(semantics.priMax) || !Array.isArray(semantics.rfc5424SupportedVersions) ||
      Object.keys(semantics.bsdMonthDays).length !== 12) throw new Error('GRAMMAR_SEMANTICS_INVALID');
}

export function contractSha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Generated TypeScript consumer (browser and Node). */
export function generateTypeScript(contractText) {
  const contract = JSON.parse(contractText);
  validateContract(contract);
  const rules = Object.fromEntries(Object.keys(contract.rules).map(name => [name, compileRule(contract, name, 'js')]));
  return [
    '// GENERATED FILE - DO NOT EDIT.',
    `// Source: ${CONTRACT_PATH} (revision ${contract.revision}); regenerate with`,
    '//   node scripts/grammar/generate-grammar.mjs --write',
    '// CI runs the generator with --verify, so a hand edit of this file fails the gate.',
    `export const GRAMMAR_CONTRACT_SHA256 = ${JSON.stringify(contractSha256(contractText))};`,
    `export const GRAMMAR_CONTRACT_REVISION = ${contract.revision};`,
    'export interface CompiledHeaderRule { readonly source: string; readonly captures: readonly string[] }',
    `export const SYSLOG_HEADER_RULES = ${JSON.stringify(rules, null, 2)} as const satisfies Record<string, CompiledHeaderRule>;`,
    `export const SYSLOG_HEADER_ALTERNATIVES = ${JSON.stringify(contract.alternatives, null, 2)} as const;`,
    `export const SYSLOG_HEADER_SEMANTICS = ${JSON.stringify(contract.semantics, null, 2)} as const;`,
    'export type SyslogHeaderRuleName = keyof typeof SYSLOG_HEADER_RULES;',
    '',
  ].join('\n');
}

function main(argv) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const contractText = readFileSync(resolve(root, CONTRACT_PATH), 'utf8');
  const outputs = { [GENERATED_TS_PATH]: generateTypeScript(contractText) };
  if (argv.includes('--write')) {
    for (const [path, content] of Object.entries(outputs)) writeFileSync(resolve(root, path), content);
    process.stdout.write(`GRAMMAR_GENERATED files=${Object.keys(outputs).length} contract=${contractSha256(contractText).slice(0, 16)}\n`);
    return;
  }
  if (argv.includes('--verify')) {
    for (const [path, content] of Object.entries(outputs)) {
      let current = '';
      try { current = readFileSync(resolve(root, path), 'utf8'); } catch { /* reported below */ }
      if (current !== content) {
        process.stderr.write(`GRAMMAR_GENERATED_STALE ${path}: run node scripts/grammar/generate-grammar.mjs --write\n`);
        process.exit(1);
      }
    }
    process.stdout.write(`GRAMMAR_GENERATED_IN_SYNC files=${Object.keys(outputs).length} contract=${contractSha256(contractText).slice(0, 16)}\n`);
    return;
  }
  process.stderr.write('usage: generate-grammar.mjs --write | --verify\n');
  process.exit(2);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
