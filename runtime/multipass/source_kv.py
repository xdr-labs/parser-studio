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
from source_field_names import source_field_name

PAIR=re.compile(FRAGMENTS['kv_pair']['source'])
LIST_PAIR=re.compile(FRAGMENTS['kv_list_pair']['source'])
LIST_SEPARATOR=re.compile(FRAGMENTS['kv_list_separator']['source'])
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


KEY_BEHIND_DELIMITER=re.compile(r'[^ \t\n\x0b\f\r,;|="\']+=')


def _delimited_pair_unread(raw:str,start:int,end:int)->tuple[bool,bool]:
    """What the list delimiters (, ; |) of the unquoted value raw[start:end] say, as (inside, last).
    inside: a delimiter inside the value is followed by a key ("1,b=2"). Whether that is a second pair is
    decided by the line: see decode_source_kv. last: the value ends in a delimiter and the next token is a pair
    ("1," before " b=2"); the delimiter is not part of the value.
    Same rule as unquotedValueEnd of src/grammar/parseStatus.ts, where the browser grades the event PARTIAL."""
    inside=False;query=False
    for at in range(start,end):
        # "&" separates pairs inside one token too ("a=1&b=2", audit G-11), except after a "?" that opened a
        # URL query ("url=/a?x=1&y=2"). Same rule as unquotedValueEnd of src/grammar/parseStatus.ts.
        if raw[at]=='?':query=True;continue
        if raw[at]=='&':
            if not query and at+1<end and KEY_BEHIND_DELIMITER.match(raw,at+1) is not None:inside=True
            continue
        if raw[at] not in ',;|':continue
        if at+1<end:
            if KEY_BEHIND_DELIMITER.match(raw,at+1) is not None:inside=True
        else:
            following=end
            while following<len(raw) and raw[following] in KV_ASCII_WHITESPACE:following+=1
            if KEY.match(raw,following) is not None:return inside,True
    return inside,False


def _diagnose(raw:str,pos:int)->str:
    """Name why no contract pair starts at `pos`. Never decides acceptance."""
    pos=GAP.match(raw,pos).end()
    key=KEY.match(raw,pos)
    if key is None:return 'KV_TOKEN_UNRECOGNIZED'
    following=raw[key.end():key.end()+1]
    if following in ('"',"'"):return 'KV_QUOTE_UNCLOSED'
    if following=='' or following in KV_ASCII_WHITESPACE:return 'KV_EMPTY_UNQUOTED_VALUE'
    return 'KV_VALUE_MALFORMED'


def _is_delimited_pair_list(raw:str,begin:int)->bool:
    """True when the body is a delimited list (contract fragments.kv_list_pair): two or more list pairs,
    each separated from the next by the same list delimiter, and only white space after the last one.
    Same control flow as isDelimitedPairList of src/grammar/kvBody.ts."""
    delimiter='';count=0;pos=begin
    while pos<=len(raw):
        match=LIST_PAIR.match(raw,pos)
        if match is None or match.end()<=pos:return False
        count+=1
        if count>MAX_FIELDS:return True
        pos=match.end()
        if TRAILING.fullmatch(raw,pos) is not None:return count>=2
        separator=LIST_SEPARATOR.match(raw,pos)
        if separator is None:return False
        found=separator['delimiter']
        if delimiter!='' and found!=delimiter:return False
        delimiter=found;pos=separator.end()
    return False


def decode_source_kv(raw:str,begin:int=0,*,max_fields:int=MAX_FIELDS)->Fragment:
    if not isinstance(raw,str):raise TypeError('KV_SOURCE_NOT_TEXT')
    if not (0<=begin<=len(raw) and 1<=max_fields<=MAX_FIELDS):
        raise ValueError('KV_SOURCE_BOUND_INVALID')
    out=Fragment()
    if len(raw.encode('utf8'))>MAX_BYTES or '\x00' in raw:
        out.issues.append('KV_SOURCE_SIZE_OR_NUL_INVALID');return out
    pos=begin;n=len(raw)
    listed=_is_delimited_pair_list(raw,begin)
    # A pair behind a list delimiter that was not read as a pair: inside a value, or a delimiter kept at the end
    # of a value. A pair that follows another pair after white space alone (bare_gap) says that the line
    # separates its pairs with white space: a delimiter inside one of its values is then value data.
    inside=False;last=False;bare_gap=False
    while pos<n:
        if TRAILING.fullmatch(raw,pos) is not None:
            out.covered.append((pos,n));break
        if listed and out.primitive_fields>0:
            separator=LIST_SEPARATOR.match(raw,pos)
            if separator is None:
                out.issues.append(_diagnose(raw,pos));break
            out.covered.append(separator.span());pos=separator.end()
        match=(LIST_PAIR if listed else PAIR).match(raw,pos)
        if match is None or match.end()<=pos:
            out.issues.append(_diagnose(raw,pos));break
        # A name the JavaScript object model reserves is kept under its reversible field name (G-5).
        key=source_field_name(match['key'])
        if out.primitive_fields>=max_fields:
            out.issues.append('KV_SOURCE_FIELD_LIMIT');break
        group=next(name for name in ('dq','sq','bare') if match[name] is not None)
        # An unquoted value has no quoting syntax to escape from: it is the text as written.
        value=match[group] if group=='bare' else unescape_kv_value(match[group])
        # In a delimited list a quoted value is the text between its quotes (contract KV_LIST_DQ).
        if listed:value=match[group]
        # A pair behind a list delimiter was not read as a pair: every field is kept, and the event is never
        # reported as completely parsed (the browser grades it PARTIAL, src/grammar/parseStatus.ts).
        if out.primitive_fields>0 and raw[pos-1] not in ',;|':bare_gap=True
        if group=='bare':
            found=_delimited_pair_unread(raw,*match.span('bare'))
            inside=inside or found[0];last=last or found[1]
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
    # Every field is kept, and the event is never reported as completely parsed (the browser grades it PARTIAL,
    # src/grammar/parseStatus.ts).
    if last or (inside and not bare_gap):out.issues.append('KV_DELIMITED_PAIR_UNREAD')
    return out
