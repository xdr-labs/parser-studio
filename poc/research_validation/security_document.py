"""Compose explicit source schemas without leaking state into other formats.

Known security records use the caller's current parser. Explicit table schema
state applies only to otherwise unframed rows. Values, metadata and unknown
records retain a complete occurrence ledger. No semantic type coercion occurs.
"""
from __future__ import annotations
import re
from typing import Callable
from candidate import Document, parse_document
from source_parse import SourceEvent

DECLARATION=re.compile(r'#separator \\x(?:09|2[cC]|3[bB]|7[cC])\Z')
METADATA=('set_separator','empty_field','unset_field','path','open','close','fields','types')
STRONG_FORMATS=('JSON','CEF','LEEF','CEE_JSON','SYSLOG_','BSD_SYSLOG')


def parse_security_document(records: list[str], *, base_parser: Callable[[str], SourceEvent]) -> Document:
    if len(records)>100000:
        raise ValueError('DOCUMENT_RECORD_LIMIT')
    if any(not isinstance(raw,str) for raw in records):
        raise TypeError('DOCUMENT_RECORD_NOT_TEXT')
    result=Document(list(records),[],[])
    separator=None;field_header=None;type_header=None;delimiter=None
    for i,raw in enumerate(records):
        if DECLARATION.fullmatch(raw):
            separator=raw;delimiter=chr(int(raw[-2:],16))
            field_header=None;type_header=None
            result.metadata_indices.append(i)
            continue
        if raw.startswith('#separator '):
            # An invalid replacement declaration must not reuse earlier state.
            separator=None;delimiter=None;field_header=None;type_header=None
            result.events.append((i,base_parser(raw)))
            continue
        label=next((name for name in METADATA
                    if delimiter is not None and raw.startswith('#'+name+delimiter)),None)
        if label:
            result.metadata_indices.append(i)
            if label=='fields':field_header=raw;type_header=None
            elif label=='types':type_header=raw
            elif label=='close':
                separator=None;delimiter=None;field_header=None;type_header=None
            continue
        if separator is None or raw.startswith('#'):
            result.events.append((i,base_parser(raw)))
            continue
        # Avoid sending ordinary declared rows through a second parser.
        # Probe only explicit format leaders or an undelimited native KV row.
        leader=raw.lstrip(' \t')
        framed=(leader.startswith(('{','[','@cee:','CEF:','LEEF:','<'))
                or re.match(r'[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:',leader))
        kv=(delimiter not in raw and re.match(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}=',leader))
        if framed or kv:
            ordinary=base_parser(raw)
            if ordinary.syntax.startswith(STRONG_FORMATS) or (kv and ordinary.syntax=='KV'):
                result.events.append((i,ordinary))
                continue
        # Reuse the bounded, tested scalar decoder with at most three headers.
        # Resetting #fields explicitly invalidates the old #types declaration.
        context=[x for x in (separator,field_header,type_header) if x is not None]
        decoded=parse_document(context+[raw],metadata=True,kv=False)
        rows=dict(decoded.events)
        if len(context) not in rows:
            raise AssertionError('DECLARED_ROW_MISSING')
        result.events.append((i,rows[len(context)]))
    indices=[i for i,_ in result.events]+result.metadata_indices
    if sorted(indices)!=list(range(len(records))):
        raise AssertionError('DOCUMENT_LEDGER_LOSS_OR_DUPLICATION')
    return result
