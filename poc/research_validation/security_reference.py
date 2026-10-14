"""Independent source-field oracles; no candidate or engine imports.

JSON values come from stdlib json.loads. A separate token stream, walked in
source-tree order, establishes exact byte positions without output matching.
Leading-quoted FortiGate KV values use POSIX shlex. Bare vendor values
are opaque source tokens, not shell words: interior quotes remain literal.
Only the vendor body is scored for syslog-wrapped KV; envelope fields are
explicitly outside this oracle. NUL-corrupted inputs are separately accounted.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
import re
import shlex
from typing import Any

TOKEN = re.compile(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|[{}\[\]:,]')
KV = re.compile(r'''(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,127})=(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?!["'])(?:\\[ \t]|[^\s])*)(?=$|\s)''')
RFC = re.compile(r'^<\d{1,3}>1 (?:\S+ ){5}- ')
PRI = re.compile(r'^<\d{1,3}>[ \t]*')

@dataclass(frozen=True)
class Reference:
    raw: str
    kind: str
    fields: tuple[tuple[tuple[str | int, ...], Any, int, int], ...]
    tree: Any
    complete: bool
    body_start_byte: int = 0
    issue: str | None = None
    scorable: bool = True


def offsets(raw: str) -> list[int]:
    out = [0]
    for c in raw:
        out.append(out[-1] + len(c.encode('utf8')))
    return out


def _pairs(pairs):
    out = {}
    for k,v in pairs:
        if k in out:
            raise ValueError('REFERENCE_DUPLICATE_JSON_KEY')
        out[k] = v
    return out


def json_reference(raw: str) -> Reference:
    tree = json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
    if not isinstance(tree, (dict, list)):
        raise ValueError('REFERENCE_JSON_ROOT_NOT_COLLECTION')
    tokens = list(TOKEN.finditer(raw)); position = 0; end = 0
    for token in tokens:
        if raw[end:token.start()].strip():
            raise ValueError('REFERENCE_JSON_TOKEN_GAP')
        end = token.end()
    if raw[end:].strip():
        raise ValueError('REFERENCE_JSON_TOKEN_TAIL')
    byte = offsets(raw); fields = []
    def consume(literal):
        nonlocal position
        if position >= len(tokens) or tokens[position].group() != literal:
            raise ValueError('REFERENCE_JSON_STRUCTURE_MISMATCH')
        position += 1
    def walk(node, path):
        nonlocal position
        if isinstance(node, dict):
            consume('{')
            for i,(key,child) in enumerate(node.items()):
                if i: consume(',')
                if json.loads(tokens[position].group()) != key:
                    raise ValueError('REFERENCE_KEY_ORDER_MISMATCH')
                position += 1; consume(':'); walk(child, path+(key,))
            consume('}')
        elif isinstance(node, list):
            consume('[')
            for i,child in enumerate(node):
                if i: consume(',')
                walk(child,path+(i,))
            consume(']')
        else:
            token = tokens[position]; position += 1
            value = json.loads(token.group())
            if type(value) is not type(node) or value != node:
                raise ValueError('REFERENCE_LEAF_MISMATCH')
            fields.append((path,node,byte[token.start()],byte[token.end()]))
    walk(tree, () if isinstance(tree,dict) else ('$array',))
    if position != len(tokens):
        raise ValueError('REFERENCE_EXTRA_JSON_TOKENS')
    stored = tree if isinstance(tree,dict) else {'$array':tree}
    return Reference(raw,'json',tuple(fields),stored,True)


def kv_reference(raw: str) -> Reference:
    if '\x00' in raw:
        return Reference(raw,'kv',(),{},False,issue='NUL_CORRUPTED_INPUT',scorable=False)
    header = RFC.match(raw) or PRI.match(raw)
    start = header.end() if header else 0
    pos = start; byte = offsets(raw); fields = []; tree = {}; issue = None
    while pos < len(raw):
        while pos < len(raw) and raw[pos].isspace(): pos += 1
        if pos == len(raw): break
        match = KV.match(raw,pos)
        if match is None:
            issue = 'MALFORMED_OR_UNSUPPORTED_KV_TAIL'; break
        key = match.group('key'); token = match.group()
        a = match.start()+len(key)+1; b = match.end()
        if raw[a:a+1] in ('"',"'"):
            try:
                decoded = shlex.split(token,comments=False,posix=True)
            except ValueError:
                issue = 'REFERENCE_SHLEX_UNSUPPORTED_TOKEN'; break
            if len(decoded) != 1 or not decoded[0].startswith(key+'='):
                issue = 'REFERENCE_SHLEX_TOKEN_BOUNDARY'; break
            value = decoded[0][len(key)+1:]
            a += 1; b -= 1
        else:
            # Bare vendor values are not shell expressions. Interior quotes
            # and unknown path escapes remain literal source characters.
            value = re.sub(r'\\([ \t])', r'\1', raw[a:b])
        fields.append(((key,),value,byte[a],byte[b]))
        if key in tree:
            prior = tree[key]
            tree[key] = prior+[value] if isinstance(prior,list) else [prior,value]
        else: tree[key] = value
        pos = match.end()
    return Reference(raw,'kv',tuple(fields),tree,issue is None,byte[start],issue)


def reference(raw: str, family: str) -> Reference:
    return kv_reference(raw) if family == 'fortigate' else json_reference(raw)
