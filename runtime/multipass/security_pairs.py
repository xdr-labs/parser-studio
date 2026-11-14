"""Bounded colon/quoted-value maps used by security Log Exporter sources.

This is a syntax decoder, not a Check Point semantic mapping. Repeated keys,
unknown names and quoted delimiter characters remain source data. Malformed
suffixes remain residual and never supply guessed nested fields.
"""
from __future__ import annotations
from datetime import datetime
import re
from engine import MAX_RAW_BYTES
from structured_source import Fragment,RFC5424_HEAD
from syslog_header_grammar_generated import PRI_MAX,RFC5424_SUPPORTED_VERSIONS
from source_parse import SourceEvent,ValueSpan,_span,_close

KEY=re.compile(r'[A-Za-z_][A-Za-z0-9_.:-]{0,127}:')
PREFIX=re.compile(r'\[[ \t]*[A-Za-z_][A-Za-z0-9_.:-]{0,127}:')
UNSAFE={'__proto__','prototype','constructor'}


def extract_pair_envelope(raw:str)->tuple[Fragment,int]|None:
    """Lexical IETF-like header plus an explicit bracket-colon source body.

    Invalid time syntax is preserved and flagged; it is never rewritten or
    represented as a normalized timestamp. Strict RFC decoding is unchanged.
    """
    match=RFC5424_HEAD.match(raw)
    if match is None or not PREFIX.match(raw,match.end()):return None
    if int(match['pri'])>PRI_MAX or match['version'] not in RFC5424_SUPPORTED_VERSIONS:return None
    limits={'timestamp':64,'hostname':255,'appname':48,'procid':128,'msgid':32}
    if any(len(match[k])>limit or not re.fullmatch(r'[!-~]+',match[k]) for k,limit in limits.items()):return None
    fields=match.groupdict()
    result=Fragment(fields={'syslog':fields},spans=[('syslog.'+k,*match.span(k)) for k in fields],covered=[(0,match.end())],primitive_fields=len(fields))
    if fields['timestamp']!='-':
        try:
            ts=datetime.fromisoformat(fields['timestamp'].replace('Z','+00:00'))
            if ts.tzinfo is None or 'T' not in fields['timestamp']:raise ValueError()
        except ValueError:result.issues.append('SOURCE_TIMESTAMP_INVALID')
    return result,match.end()


def parse_bracket_pairs(raw:str)->SourceEvent:
    out=SourceEvent(raw,syntax='BRACKET_COLON_KV')
    if len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw or not PREFIX.match(raw):
        out.issues.append('BRACKET_SOURCE_PREFIX_OR_BOUND_INVALID');return _close(out)
    pos=1;n=len(raw);out.covered.append((0,1))
    while pos<n:
        start=pos
        while pos<n and raw[pos] in ' \t':pos+=1
        if raw[pos:pos+1]==']':
            pos+=1;out.covered.append((start,pos))
            if raw[pos:].strip(' \t'):
                out.issues.append('BRACKET_TRAILING_SOURCE')
            else:out.covered.append((pos,n))
            return _close(out)
        if out.primitive_fields>=1024:
            out.issues.append('BRACKET_FIELD_LIMIT');break
        match=KEY.match(raw,pos)
        if match is None or match.group()[:-1] in UNSAFE:
            out.issues.append('BRACKET_INVALID_SOURCE_KEY');break
        key=match.group()[:-1];pos=match.end()
        if raw[pos:pos+1]!='"':
            out.issues.append('BRACKET_QUOTED_VALUE_REQUIRED');break
        pos+=1;first=pos;decoded=[]
        while pos<n:
            char=raw[pos]
            if char=='\\':
                if pos+1==n:break
                nxt=raw[pos+1]
                decoded.append(nxt if nxt in ('"','\\') else raw[pos:pos+2]);pos+=2
            elif char=='"':break
            else:decoded.append(char);pos+=1
        if pos==n or raw[pos:pos+1]!='"':
            out.issues.append('BRACKET_QUOTE_UNCLOSED');break
        last=pos;pos+=1
        while pos<n and raw[pos] in ' \t':pos+=1
        if pos==n or raw[pos] not in ';]':
            out.issues.append('BRACKET_VALUE_BOUNDARY_INVALID');break
        value=''.join(decoded)
        if key in out.vendor_fields:
            previous=out.vendor_fields[key]
            out.vendor_fields[key]=previous+[value] if isinstance(previous,list) else [previous,value]
        else:out.vendor_fields[key]=value
        span=_span(raw,key,first,last)
        out.value_spans.append(ValueSpan(span.path,span.start_byte,span.end_byte,(key,)))
        out.primitive_fields+=1
        if raw[pos]==';':pos+=1
        out.covered.append((start,pos))
    out.issues.append('BRACKET_SOURCE_INCOMPLETE')
    return _close(out)
