"""Compose declared source metadata with the caller's current security engine.

Only explicit Zeek-style separator/schema declarations select the metadata
reader. Every ordinary event still uses the current caller parser, never H1
or a frozen engine replacement. Original data and metadata stay in one ledger.
"""
from __future__ import annotations
import re
from typing import Callable
from candidate import Document, parse_document
from source_parse import SourceEvent

DECLARATION=re.compile(r'#separator \\x(?:09|2[cC]|3[bB]|7[cC])\Z')


def parse_security_document(records: list[str], *, base_parser: Callable[[str], SourceEvent]) -> Document:
    if len(records)>100000:
        raise ValueError('DOCUMENT_RECORD_LIMIT')
    if any(not isinstance(raw,str) for raw in records):
        raise TypeError('DOCUMENT_RECORD_NOT_TEXT')
    if not any(DECLARATION.fullmatch(raw) for raw in records):
        return Document(list(records),[(i,base_parser(raw)) for i,raw in enumerate(records)],[])
    declared=parse_document(records,metadata=True,kv=False)
    # Preserve metadata results, including explicit malformed-schema failures.
    # Everything outside declared rows falls back to the current security API.
    events=[(i,event if event.syntax=='DECLARED_DELIMITED' else base_parser(records[i]))
            for i,event in declared.events]
    result=Document(list(records),events,list(declared.metadata_indices))
    indices=[i for i,_ in result.events]+result.metadata_indices
    if sorted(indices)!=list(range(len(records))):
        raise AssertionError('DOCUMENT_LEDGER_LOSS_OR_DUPLICATION')
    return result
