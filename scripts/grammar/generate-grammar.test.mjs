// node --test scripts/grammar/generate-grammar.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  CONTRACT_PATH, DIALECTS, GENERATED_BACKEND_PATH, GENERATED_PYTHON_PATH, GENERATED_TS_PATH, compileFragment, compileRule,
  generateBackendTypeScript, generatePython, generateTypeScript, validateContract, validateTokenPattern,
} from './generate-grammar.mjs';

const contractText = readFileSync(CONTRACT_PATH, 'utf8');
const contract = JSON.parse(contractText);

test('the committed generated consumer is exactly what the contract produces', () => {
  assert.equal(readFileSync(GENERATED_TS_PATH, 'utf8'), generateTypeScript(contractText));
  assert.equal(readFileSync(GENERATED_BACKEND_PATH, 'utf8'), generateBackendTypeScript(contractText));
  assert.equal(readFileSync(GENERATED_PYTHON_PATH, 'utf8'), generatePython(contractText));
});

test('the contract validates and every dialect shares capture names', () => {
  validateContract(contract);
  for (const rule of Object.keys(contract.rules)) {
    const names = DIALECTS.map(dialect => compileRule(contract, rule, dialect).captures.join());
    assert.equal(new Set(names).size, 1, rule);
  }
});

test('dialects differ only in anchors and the named-group prefix', () => {
  for (const rule of Object.keys(contract.rules)) {
    const js = compileRule(contract, rule, 'js').source;
    const ruby = compileRule(contract, rule, 'ruby').source;
    const python = compileRule(contract, rule, 'python').source;
    assert.equal(ruby, '\\A' + js.slice(1, -1) + '\\z');
    assert.equal(python, '\\A' + js.slice(1, -1).replace(/\(\?</g, '(?P<') + '\\Z');
  }
});

test('runtime-dependent constructs are rejected', () => {
  for (const pattern of ['.+', '\\d{1,3}', '\\S+', '\\w+', 'a\\b', '^a', 'a$', '(a)', '(?<n>a)', '(?=a)b', 'a+?', 'a{1,2}?', 'a++', '[[:alpha:]]', 'a/b', 'a#b', 'é', '[a', '(?:a', 'a{,2}', '[a-z&&aeiou]', '[^ =]{1,4}', '\\x1', '\\x1C', '\\x80', '\\xff', '\\u001c'])
    assert.throws(() => validateTokenPattern('T', pattern), /GRAMMAR_TOKEN_NOT_PORTABLE/, pattern);
  for (const pattern of ['[0-9]{1,3}', '(?!\\{|CEF:)[!-<>-~]{1,255}', '[^\\r\\n]+', '(?:a|b)*c?', '[A-Za-z_][A-Za-z0-9_.-]{0,95}', '[^ \\x1c-\\x1f]+', '\\x7f'])
    assert.doesNotThrow(() => validateTokenPattern('T', pattern), pattern);
});

test('contract mistakes fail generation instead of shipping', () => {
  const mutate = change => { const copy = JSON.parse(contractText); change(copy); return copy; };
  assert.throws(() => validateContract(mutate(c => { c.tokens.PRI.pattern = '\\d{1,3}'; })), /NOT_PORTABLE/);
  assert.throws(() => validateContract(mutate(c => { c.tokens.EXTRA = { pattern: '[a-z]' }; })), /TOKEN_UNUSED/);
  assert.throws(() => validateContract(mutate(c => { c.rules.rfc5424.sequence[1].cap = 'hostname'; })), /duplicate capture/);
  assert.throws(() => validateContract(mutate(c => { c.rules.rfc5424.sequence[1].token = 'MISSING'; })), /unknown token/);
  assert.throws(() => validateContract(mutate(c => { c.alternatives.rfc3164.push('nope'); })), /ALTERNATIVE_UNKNOWN/);
  // Mistakes that used to generate without an error and would only break a consumer at run time.
  assert.throws(() => validateContract(mutate(c => { c.rules.rfc3164_tagless.sequence.find(item => item.cap === 'hostname').cap = 'host'; })), /CAPTURES_REQUIRED/);
  assert.throws(() => validateContract(mutate(c => { delete c.rules.rfc3164_tagged.sequence.find(item => item.cap === 'month').cap; })), /CAPTURES_REQUIRED/);
  assert.throws(() => validateContract(mutate(c => { delete c.rules.rfc5424; })), /RULE_REQUIRED|TOKEN_UNUSED/);
  assert.throws(() => validateContract(mutate(c => { c.alternatives.rfc3164 = []; })), /ALTERNATIVES_INVALID/);
  assert.throws(() => validateContract(mutate(c => { delete c.alternatives.rfc3164; })), /ALTERNATIVES_INVALID/);
  for (const priMax of [-5, 99999, 1.5]) assert.throws(() => validateContract(mutate(c => { c.semantics.priMax = priMax; })), /SEMANTICS_INVALID/);
  assert.throws(() => validateContract(mutate(c => { c.semantics.bsdMonthDays.Feb = 0; })), /SEMANTICS_INVALID/);
  assert.throws(() => validateContract(mutate(c => { c.semantics.rfc5424SupportedVersions = []; })), /SEMANTICS_INVALID/);
});

test('the F-1 guard is part of the contract, not of a consumer', () => {
  const hostname = contract.tokens.BSD_HOSTNAME.pattern;
  const expression = new RegExp('^(?:' + hostname + ')$');
  assert.equal(expression.test('fw01'), true);
  assert.equal(expression.test('fe80::1'), true);
  assert.equal(expression.test('a'.repeat(255)), true);
  for (const body of ['srcip=10.1.1.1', '{"a":1}', 'CEF:0|x', 'LEEF:1.0|x', 'kernel:', 'sshd[123]:', 'a'.repeat(256)]) assert.equal(expression.test(body), false, body);
});

test('the key=value fragment is the same expression in every dialect and matches at a position', () => {
  const js = compileFragment(contract, 'kv_pair', 'js');
  assert.equal(compileFragment(contract, 'kv_pair', 'ruby').source, '\\G' + js.source);
  assert.equal(compileFragment(contract, 'kv_pair', 'python').source, js.source.replace(/\(\?</g, '(?P<'));
  assert.deepEqual(js.captures, ['key', 'dq', 'sq', 'bare']);
  const sticky = new RegExp(js.source, 'y');
  sticky.lastIndex = 4;
  const match = sticky.exec('a=1 msg="x y" c=3');
  assert.equal(match.groups.key, 'msg');
  assert.equal(match.groups.dq, 'x y');
  const mutate = change => { const copy = JSON.parse(contractText); change(copy); return copy; };
  assert.throws(() => validateContract(mutate(c => { delete c.fragments.kv_pair; })), /FRAGMENT_REQUIRED|TOKEN_UNUSED/);
  assert.throws(() => validateContract(mutate(c => { c.semantics.kvMaxPairs = 0; })), /SEMANTICS_INVALID/);
  assert.throws(() => validateContract(mutate(c => { c.semantics.kvForbiddenKeys = []; })), /SEMANTICS_INVALID/);
  assert.throws(() => validateContract(mutate(c => { c.standaloneTokens.push('NOPE'); })), /STANDALONE_TOKEN_UNKNOWN/);
});
