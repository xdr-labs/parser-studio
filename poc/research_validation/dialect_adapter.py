"""Selective H2 adapter: never replace a recognized native format with CSV.

Engine-only experiment. Caller supplies the frozen base parser. This module
neither changes H1/H3 nor fixes the separately blocked metadata exception.
A learned dialect is scoped to a homogeneous source batch, not a universal
router. No field-name/type/Dictionary inference occurs here.
"""
from __future__ import annotations
from typing import Callable
from candidate import Dialect, parse_candidate
from source_parse import SourceEvent


def parse_with_dialect(raw: str, model: Dialect | None, *,
                       base_parser: Callable[[str], SourceEvent]) -> SourceEvent:
    primary = base_parser(raw)
    if model is None:
        return primary
    # Preserve authoritative syntax even if malformed or only partly parsed.
    if primary.syntax not in {'UNKNOWN', 'CSV_UNLABELED_CANDIDATE'}:
        return primary
    if primary.syntax == 'UNKNOWN' and primary.vendor_fields:
        return primary
    if 'SOURCE_SIZE_OR_NUL_INVALID' in primary.issues:
        return primary
    proposal = parse_candidate(raw, kv=False, dialect=model)
    if proposal.status != 'SOURCE_PARSED':
        return primary
    return proposal
