"""Source key=value scanner driven by the shared grammar contract.

The pair expression, the pair separator (SP and TAB), the trailing white space,
the escape set, the forbidden keys and the pair limit all come from the module
generated out of contracts/syslog-header-grammar.v1.json. The browser parser
(src/grammar/kvBody.ts) and the generated Ruby Fragment read the same contract,
so a body is split at the same characters and decoded to the same values by
every executor: NBSP and U+2028 are value data and only the listed escapes are
decoded. A repeated key (owner policy D-1): the strict parsers decline the body;
this source preview keeps every value in order and reports the event as not
completely parsed (DUPLICATE_SOURCE_FIELD), so no engine reports it as FULL.

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
    """Decode a quoted value: only the escapes the contract lists; any other backslash stays as written."""
    out=[];index=0
    while index<len(text):
        if text[index]=='\\' and index+1<len(text):
            following=text[index+1]
            out.append(following if following in UNESCAPED else text[index:index+2])
            index+=2
        else:
            out.append(text[index]);index+=1
    return ''.join(out)


def _delimited_pair_unread(raw:str,start:int,end:int)->bool:
    """True when the unquoted value raw[start:end] holds, or ends in, a list delimiter (, ; |) that the key of
    another pair follows, with no "=" before it: "1,b=2", or "1," before " b=2". Such a value is not one value.
    Same rule as unquotedValueEnd of src/grammar/parseStatus.ts, where the browser grades the event PARTIAL; a
    value with "=" before the delimiter is a list of its own (a distinguished name) and is one value."""
    for at in range(start,end):
        ch=raw[at]
        if ch=='=':return False
        if ch not in ',;|':continue
        if at+1<end:
            key=KEY.match(raw,at+1)
            if key is not None and key.end()<=end:return True
        else:
            following=end
            while following<len(raw) and raw[following] in KV_ASCII_WHITESPACE:following+=1
            if KEY.match(raw,following) is not None:return True
    return False


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
        # An unquoted value has no quoting syntax to escape from: it is the text as written.
        value=match[group] if group=='bare' else unescape_kv_value(match[group])
        # A pair behind a list delimiter was not read as a pair: every field is kept, and the event is never
        # reported as completely parsed (the browser grades it PARTIAL, src/grammar/parseStatus.ts).
        if group=='bare' and 'KV_DELIMITED_PAIR_UNREAD' not in out.issues and _delimited_pair_unread(raw,*match.span('bare')):
            out.issues.append('KV_DELIMITED_PAIR_UNREAD')
        if key in out.fields:
            # Source preview keeps every occurrence of a repeated key, in order (release gate H3).
            previous=out.fields[key]
            if isinstance(previous,list):previous.append(value)
            else:out.fields[key]=[previous,value]
            # Owner policy D-1: every value is kept in order, and the event is never reported as
            # completely parsed while a field is repeated (same issue code as CEF and JSON use).
            if 'DUPLICATE_SOURCE_FIELD' not in out.issues:out.issues.append('DUPLICATE_SOURCE_FIELD')
        else:out.fields[key]=value
        out.spans.append((key,*match.span(group)))
        out.primitive_fields+=1
        if match.start('key')>pos:out.covered.append((pos,match.start('key')))
        out.covered.append((match.start('key'),match.end()))
        pos=match.end()
    return out
