"""Declared document/schema state isolated from ordinary security records.

Only explicit #separator/#fields/#types declarations can create a table row
parser. Strong security formats always go through the caller's current source
parser, and #close/rotation destroys stale schema state. Every physical input
record remains either a metadata record or an emitted SourceEvent.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

from source_parse import SourceEvent,ValueSpan,_close

MAX_RECORDS=100000
MAX_COLUMNS=1024
DECLARATION=re.compile(r'#separator \\x(?P<hex>09|2[cC]|3[bB]|7[cC])\Z')
SAFE_FIELD=re.compile(r'[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z')
METADATA=('set_separator','empty_field','unset_field','path','open','close','fields','types')
STRONG_PREFIXES=('JSON','CEF','LEEF','CEE_JSON','SYSLOG_','BSD_SYSLOG','SECURITY_')


@dataclass
class SecurityDocument:
    records:list[str]
    events:list[tuple[int,SourceEvent]]
    metadata_indices:list[int]


def _split_spans(raw:str,delimiter:str)->list[tuple[str,int,int]]:
    if '\r' in raw or '\n' in raw:raise ValueError('DECLARED_ROW_MULTILINE')
    cells=[];start=0
    while True:
        end=raw.find(delimiter,start)
        if end<0:end=len(raw)
        cells.append((raw[start:end],start,end))
        if len(cells)>MAX_COLUMNS:raise ValueError('DECLARED_ROW_COLUMN_LIMIT')
        if end==len(raw):return cells
        start=end+1


def _declared_row(raw:str,delimiter:str,fields:list[str]|None,types:list[str]|None)->SourceEvent:
    event=SourceEvent(raw,syntax='DECLARED_SCHEMA_ROW')
    try:cells=_split_spans(raw,delimiter)
    except ValueError as exc:
        event.issues.append(str(exc));return _close(event)
    if fields is None or types is None:
        event.issues.append('DECLARED_SCHEMA_INCOMPLETE');return _close(event)
    if len(fields)!=len(types) or len(cells)!=len(fields):
        event.issues.append('DECLARED_SCHEMA_WIDTH_MISMATCH');return _close(event)
    if len(set(fields))!=len(fields) or any(SAFE_FIELD.fullmatch(name) is None for name in fields):
        event.issues.append('DECLARED_SCHEMA_FIELD_INVALID_OR_DUPLICATE');return _close(event)
    for name,(value,a,b) in zip(fields,cells):
        event.vendor_fields[name]=value
        start=len(raw[:a].encode('utf8'));end=len(raw[:b].encode('utf8'))
        event.value_spans.append(ValueSpan(name,start,end,(name,)))
    event.primitive_fields=len(cells);event.covered=[(0,len(raw))]
    return _close(event)


def _strong_security(raw:str,base_parser:Callable[[str],SourceEvent],delimiter:str)->SourceEvent|None:
    leader=raw.lstrip(' \t')
    framed=(leader.startswith(('{','[','@cee:','CEF:','LEEF:','<'))
            or re.match(r'[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:',leader))
    native_kv=(delimiter not in raw and re.match(r'[A-Za-z_][A-Za-z0-9_.:-]{0,127}=',leader))
    if not (framed or native_kv):return None
    event=base_parser(raw)
    if event.syntax.startswith(STRONG_PREFIXES) or (native_kv and (event.syntax=='KV' or event.syntax.endswith('+KV'))):
        return event
    return None


def parse_security_document(records:list[str],*,base_parser:Callable[[str],SourceEvent])->SecurityDocument:
    if len(records)>MAX_RECORDS:raise ValueError('DOCUMENT_RECORD_LIMIT')
    if any(not isinstance(raw,str) for raw in records):raise TypeError('DOCUMENT_RECORD_NOT_TEXT')
    result=SecurityDocument(list(records),[],[])
    delimiter=None;fields=None;types=None
    for index,raw in enumerate(records):
        declaration=DECLARATION.fullmatch(raw)
        if declaration:
            delimiter=chr(int(declaration['hex'],16));fields=None;types=None
            result.metadata_indices.append(index);continue
        if raw.startswith('#separator '):
            # A malformed replacement declaration invalidates old state and
            # remains visible as an ordinary source record.
            delimiter=None;fields=None;types=None
            result.events.append((index,base_parser(raw)));continue
        label=None
        if delimiter is not None:
            label=next((name for name in METADATA if raw.startswith('#'+name+delimiter)),None)
        if label is not None:
            result.metadata_indices.append(index)
            payload=raw.split(delimiter)[1:]
            if label=='fields':
                fields=payload if 0<len(payload)<=MAX_COLUMNS else None
                types=None
            elif label=='types':
                types=payload if fields is not None and len(payload)==len(fields) else None
            elif label=='close':
                delimiter=None;fields=None;types=None
            continue
        if delimiter is None or raw.startswith('#'):
            result.events.append((index,base_parser(raw)));continue
        ordinary=_strong_security(raw,base_parser,delimiter)
        if ordinary is not None:
            result.events.append((index,ordinary));continue
        result.events.append((index,_declared_row(raw,delimiter,fields,types)))
    ledger=result.metadata_indices+[i for i,_ in result.events]
    if sorted(ledger)!=list(range(len(records))) or len(ledger)!=len(set(ledger)):
        raise AssertionError('DOCUMENT_LEDGER_LOSS_OR_DUPLICATION')
    return result
