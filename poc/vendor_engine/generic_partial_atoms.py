"""Conservative lexical source atoms for incomplete security events.

This layer never assigns source/destination/user semantics and never turns an
incomplete event into SOURCE_PARSED. It only adds exact residual source atoms
whose lexical form can be independently validated.
"""
from __future__ import annotations

from copy import deepcopy
import ipaddress
import re

from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

IPV4_ENDPOINT=re.compile(
    r'(?<![0-9A-Fa-f:.])'
    r'(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})'
    r'(?:(?P<sep>[:/])(?P<port>[0-9]{1,5}))?'
    r'(?![0-9A-Fa-f:.])'
)
MAC=re.compile(
    r'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
    r'(?![0-9A-Fa-f])'
)
URL=re.compile(r'https?://[^\s"\'<>]+')
SHA256=re.compile(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])')


def _b(raw:str,pos:int)->int:
    return len(raw[:pos].encode('utf8'))


def _overlaps(a:int,b:int,spans:list[ValueSpan])->bool:
    return any(max(a,s.start_byte)<min(b,s.end_byte) for s in spans)


def _valid_ip_endpoint(match:re.Match[str])->bool:
    try:
        ipaddress.ip_address(match.group('ip'))
    except ValueError:
        return False
    port=match.group('port')
    return port is None or 0<=int(port)<=65535


def _candidates(raw:str):
    for match in IPV4_ENDPOINT.finditer(raw):
        if _valid_ip_endpoint(match):
            yield 'network',match.start(),match.end(),match.group(0)
    for match in MAC.finditer(raw):
        yield 'mac',match.start(),match.end(),match.group(0)
    for match in URL.finditer(raw):
        yield 'url',match.start(),match.end(),match.group(0)
    for match in SHA256.finditer(raw):
        yield 'sha256',match.start(),match.end(),match.group(0)


def augment_incomplete_atoms(event:SourceEvent)->SourceEvent:
    """Add non-overlapping validated lexical values; never certify completeness."""
    assert_source_accounting(event)
    if event.status=='SOURCE_PARSED':
        return event
    out=deepcopy(event)
    generic=out.vendor_fields.get('generic_atoms')
    if generic is not None and not isinstance(generic,dict):
        return event
    buckets={} if generic is None else deepcopy(generic)
    additions=[]
    for kind,char_a,char_b,value in _candidates(event.raw):
        byte_a=_b(event.raw,char_a);byte_b=_b(event.raw,char_b)
        if _overlaps(byte_a,byte_b,out.value_spans):
            continue
        bucket=buckets.setdefault(kind,[])
        index=len(bucket);bucket.append(value)
        additions.append(ValueSpan(
            f'generic_atoms.{kind}.{index}',byte_a,byte_b,
            ('generic_atoms',kind,index),
        ))
        out.covered.append((char_a,char_b))
    if not additions:
        return event
    out.vendor_fields['generic_atoms']=buckets
    out.value_spans.extend(additions)
    out.value_spans.sort(key=lambda s:(s.start_byte,s.end_byte,s.path))
    out.primitive_fields=len(out.value_spans)
    out.syntax=out.syntax+'+GENERIC_ATOMS'
    out.unparsed=[]
    out=_close(out)
    # Keep an explicit incompleteness marker even if atoms happened to cover
    # all raw bytes; atoms are values, not a grammar proof.
    if not out.issues:
        out.issues.append('GENERIC_ATOMS_CANDIDATE_ONLY')
    assert_source_accounting(out)
    return out
