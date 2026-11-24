"""Source field names the JavaScript object model reserves (G-5), the rule of src/grammar/sourceFieldNames.ts.

`__proto__`, `constructor` and `prototype` (contract kvForbiddenKeys) are kept under a reversible name: the prefix
`parserstudio_key_` is put in front of a reserved name and in front of every source name that already starts with it,
so different source names never share a name and original_field_name gives the source name back. The browser, the
generated Ruby and these readers keep such a field instead of refusing the event.
"""
from __future__ import annotations

from syslog_header_grammar_generated import SEMANTICS

SOURCE_NAME_PREFIX = 'parserstudio_key_'
_RESERVED = frozenset(SEMANTICS['kvForbiddenKeys'])


def source_field_name(name: str) -> str:
    return SOURCE_NAME_PREFIX + name if name in _RESERVED or name.startswith(SOURCE_NAME_PREFIX) else name


def original_field_name(name: str) -> str:
    return name[len(SOURCE_NAME_PREFIX):] if name.startswith(SOURCE_NAME_PREFIX) else name


def with_source_field_names(value):
    """A decoded JSON value with every member name kept under its field name."""
    if isinstance(value, list):
        return [with_source_field_names(item) for item in value]
    if isinstance(value, dict):
        return {source_field_name(key): with_source_field_names(item) for key, item in value.items()}
    return value
