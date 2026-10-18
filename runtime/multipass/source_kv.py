"""Occurrence-preserving source KV scanner, independent of semantic adapters.

Repeated native keys retain ordered values and one exact span per occurrence.
Single/double quoted strings and escaped bare spaces are bounded lexically;
malformed tails stay raw, without scavenging nested apparent keys. This is a
source-only extension: historical role-learning controls remain unchanged.
"""
from __future__ import annotations
import re
from structured_source import Fragment

KEY=re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}=')
UNSAFE={'__proto__','prototype','constructor'}
MAX_FIELDS=1024
MAX_BYTES=131072


def decode_source_kv(raw:str,begin:int=0,*,max_fields:int=MAX_FIELDS)->Fragment:
    if not isinstance(raw,str):raise TypeError('KV_SOURCE_NOT_TEXT')
    if not (0<=begin<=len(raw) and 1<=max_fields<=MAX_FIELDS):
        raise ValueError('KV_SOURCE_BOUND_INVALID')
    out=Fragment()
    if len(raw.encode('utf8'))>MAX_BYTES or '\x00' in raw:
        out.issues.append('KV_SOURCE_SIZE_OR_NUL_INVALID');return out
    pos=begin;n=len(raw)
    while pos<n:
        whitespace=pos
        while pos<n and raw[pos].isspace():pos+=1
        if whitespace<pos:out.covered.append((whitespace,pos))
        if pos==n:break
        if out.primitive_fields>=max_fields:
            out.issues.append('KV_SOURCE_FIELD_LIMIT');break
        start=pos;match=KEY.match(raw,pos)
        if match is None:
            out.issues.append('KV_TOKEN_UNRECOGNIZED');break
        key=match.group()[:-1]
        if key in UNSAFE:
            out.issues.append('KV_UNSAFE_SOURCE_KEY');break
        pos=match.end();value_start=pos;decoded=[]
        quote=raw[pos:pos+1]
        if quote in ('"',"'"):
            pos+=1;value_start=pos
            while pos<n:
                char=raw[pos]
                if char=='\\':
                    if pos+1==n:
                        out.issues.append('KV_ESCAPE_TRUNCATED');return out
                    following=raw[pos+1]
                    decoded.append(following if following in (quote,'\\') else raw[pos:pos+2])
                    pos+=2
                elif char==quote:break
                else:decoded.append(char);pos+=1
            if pos==n:
                out.issues.append('KV_QUOTE_UNCLOSED');return out
            value_end=pos;pos+=1
            if pos<n and not raw[pos].isspace():
                out.issues.append('KV_AFTER_QUOTE_INVALID');return out
        else:
            while pos<n and not raw[pos].isspace():
                # Unknown bare escapes (including paths) are literal source.
                # Only an explicitly escaped separator joins a bare value.
                if raw[pos]=='\\' and pos+1<n and raw[pos+1] in ' \t':
                    decoded.append(raw[pos+1]);pos+=2
                else:decoded.append(raw[pos]);pos+=1
            value_end=pos
            if value_start==value_end:out.issues.append('KV_EMPTY_UNQUOTED_VALUE')
        value=''.join(decoded)
        if key in out.fields:
            previous=out.fields[key]
            if isinstance(previous,list):previous.append(value)
            else:out.fields[key]=[previous,value]
        else:out.fields[key]=value
        out.spans.append((key,value_start,value_end))
        out.primitive_fields+=1
        out.covered.append((start,pos))
    return out
