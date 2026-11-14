"""Source key=value scanner driven by the shared grammar contract.

The pair expression, the pair separator (SP and TAB), the trailing white space,
the escape set, the forbidden keys and the pair limit all come from the module
generated out of contracts/syslog-header-grammar.v1.json. The browser parser
(src/grammar/kvBody.ts) and the generated Ruby Fragment read the same contract,
so a body is split at the same characters and decoded to the same values by
every executor: NBSP and U+2028 are value data and only the listed escapes are
decoded. One deliberate difference remains: this source preview keeps every
occurrence of a repeated key (release gate H3) where the strict parsers reject
the body.

The issue code attached to a rejected body is diagnostic only; whether a body
is accepted is decided by the contract expressions alone. A rejected tail stays
raw: no nested apparent keys are scavenged from it.
"""
from __future__ import annotations
import re
from structured_source import Fragment
from syslog_header_grammar_generated import FRAGMENTS,SEMANTICS,TOKENS,KV_ASCII_WHITESPACE

PAIR=re.compile(FRAGMENTS['kv_pair']['source'])
TRAILING=re.compile('(?:'+TOKENS['KV_TRAILING']+')')
GAP=re.compile('(?:'+TOKENS['KV_GAP']+')')
KEY=re.compile('(?:'+TOKENS['KV_KEY']+')=')
UNESCAPED=frozenset(SEMANTICS['kvUnescapedAfterBackslash'])
UNSAFE=frozenset(SEMANTICS['kvForbiddenKeys'])
MAX_FIELDS=SEMANTICS['kvMaxPairs']
MAX_BYTES=131072


def unescape_kv_value(text:str)->str:
    """Decode only the escapes the contract lists; any other backslash stays as written."""
    out=[];index=0
    while index<len(text):
        if text[index]=='\\' and index+1<len(text):
            following=text[index+1]
            out.append(following if following in UNESCAPED else text[index:index+2])
            index+=2
        else:
            out.append(text[index]);index+=1
    return ''.join(out)


def _diagnose(raw:str,pos:int)->str:
    """Name why no contract pair starts at `pos`. Never decides acceptance."""
    pos=GAP.match(raw,pos).end()
    key=KEY.match(raw,pos)
    if key is None:return 'KV_TOKEN_UNRECOGNIZED'
    following=raw[key.end():key.end()+1]
    if following in ('"',"'"):return 'KV_QUOTE_UNCLOSED'
    if following=='' or following in KV_ASCII_WHITESPACE:return 'KV_EMPTY_UNQUOTED_VALUE'
    return 'KV_VALUE_MALFORMED'


def decode_source_kv(raw:str,begin:int=0,*,max_fields:int=MAX_FIELDS)->Fragment:
    if not isinstance(raw,str):raise TypeError('KV_SOURCE_NOT_TEXT')
    if not (0<=begin<=len(raw) and 1<=max_fields<=MAX_FIELDS):
        raise ValueError('KV_SOURCE_BOUND_INVALID')
    out=Fragment()
    if len(raw.encode('utf8'))>MAX_BYTES or '\x00' in raw:
        out.issues.append('KV_SOURCE_SIZE_OR_NUL_INVALID');return out
    pos=begin;n=len(raw)
    while pos<n:
        if TRAILING.fullmatch(raw,pos) is not None:
            out.covered.append((pos,n));break
        match=PAIR.match(raw,pos)
        if match is None or match.end()<=pos:
            out.issues.append(_diagnose(raw,pos));break
        key=match['key']
        if key in UNSAFE:
            out.issues.append('KV_UNSAFE_SOURCE_KEY');break
        if out.primitive_fields>=max_fields:
            out.issues.append('KV_SOURCE_FIELD_LIMIT');break
        group=next(name for name in ('dq','sq','bare') if match[name] is not None)
        value=unescape_kv_value(match[group])
        if key in out.fields:
            # Source preview keeps every occurrence of a repeated key, in order
            # (release gate H3). The strict browser and Ruby parsers reject the
            # body instead; the difference is tracked as D-1 in the Semantic Oracle.
            previous=out.fields[key]
            if isinstance(previous,list):previous.append(value)
            else:out.fields[key]=[previous,value]
        else:out.fields[key]=value
        out.spans.append((key,*match.span(group)))
        out.primitive_fields+=1
        if match.start('key')>pos:out.covered.append((pos,match.start('key')))
        out.covered.append((match.start('key'),match.end()))
        pos=match.end()
    return out
