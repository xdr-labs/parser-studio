"""Bounded tagless BSD/PRI envelopes for explicit security-source payloads.

The RFC3164 header ends at HOSTNAME; a colon-terminated application TAG is not
required to retain a CEF/LEEF/JSON payload. No substring search or semantic
vendor detection is used. Headerless CSV stays an unlabeled source candidate.
"""
from __future__ import annotations
import re
from structured_source import Fragment,MONTHS

BSD_HEADER=re.compile(
    r'^(?:<(?P<pri>[0-9]{1,3})>)?(?P<month>[A-Z][a-z]{2}) +'
    r'(?P<day>[0-9]{1,2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) +'
    r'(?P<hostname>[!-~]{1,255}) +'
)
PRI_HEADER=re.compile(r'^<(?P<pri>[0-9]{1,3})>[ \t]*')
ARRAY_START=re.compile(r'\[\s*(?:[\[{}\]"0-9-]|true\b|false\b|null\b)')
CSV_START=re.compile(r'[0-9]{1,10},')


def _structured_payload(raw:str,start:int)->bool:
    return (raw.startswith(('CEF:','LEEF:','@cee:','{'),start)
            or ARRAY_START.match(raw,start) is not None
            or CSV_START.match(raw,start) is not None)


def extract_security_envelope(raw:str)->tuple[Fragment,int]|None:
    """Return source header fields only at a validated explicit body boundary."""
    if not isinstance(raw,str):raise TypeError('SECURITY_ENVELOPE_NOT_TEXT')
    match=BSD_HEADER.match(raw)
    if match is not None:
        values=match.groupdict()
        hh,mm,ss=map(int,values['time'].split(':'))
        if (not 1<=int(values['day'])<=MONTHS.get(values['month'],0)
            or hh>23 or mm>59 or ss>59
            or values['pri'] is not None and int(values['pri'])>191):
            return None
    else:
        match=PRI_HEADER.match(raw)
        if match is None or int(match['pri'])>191:return None
        values=match.groupdict()
    if not _structured_payload(raw,match.end()):return None
    fields={key:value for key,value in values.items() if value is not None}
    result=Fragment(fields={'syslog':fields},
        spans=[('syslog.'+key,*match.span(key)) for key in fields],
        covered=[(0,match.end())],primitive_fields=len(fields))
    return result,match.end()
