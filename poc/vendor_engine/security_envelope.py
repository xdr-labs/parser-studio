"""Bounded tagless BSD/PRI envelopes for explicit security-source payloads.

The RFC3164 header ends at HOSTNAME; a colon-terminated application TAG is not
required to retain a CEF/LEEF/JSON payload. No substring search or semantic
vendor detection is used. Headerless CSV stays an unlabeled source candidate.
"""
from __future__ import annotations
import re
from datetime import datetime
from structured_source import Fragment,MONTHS

BSD_HEADER=re.compile(
    r'^(?:<(?P<pri>[0-9]{1,3})>)?(?P<month>[A-Z][a-z]{2}) +'
    r'(?P<day>[0-9]{1,2}) (?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) +'
    r'(?P<hostname>[!-~]{1,255}) +'
)
SHORT_IETF_CSV_HEADER=re.compile(r'^<(?P<pri>[0-9]{1,3})>(?P<version>1) (?P<timestamp>[^ \t\r\n]{1,64}) (?P<hostname>[!-~]{1,255}) +(?=[0-9]{1,10},)')
PRI_HEADER=re.compile(r'^<(?P<pri>[0-9]{1,3})>[ \t]*')
ARRAY_START=re.compile(r'\[\s*(?:[\[{}\]"0-9-]|true\b|false\b|null\b)')
CSV_START=re.compile(r'[0-9]{1,10},')


def _structured_payload(raw:str,start:int)->bool:
    return (raw.startswith(('CEF:','LEEF:','@cee:','{'),start)
            or ARRAY_START.match(raw,start) is not None
            or CSV_START.match(raw,start) is not None
            or re.match(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}=',raw[start:]) is not None)


def extract_security_envelope(raw:str)->tuple[Fragment,int]|None:
    """Return source header fields only at a validated explicit body boundary."""
    if not isinstance(raw,str):raise TypeError('SECURITY_ENVELOPE_NOT_TEXT')
    short=SHORT_IETF_CSV_HEADER.match(raw)
    if short is not None and int(short['pri'])<=191:
        try:
            stamp=datetime.fromisoformat(short['timestamp'].replace('Z','+00:00'))
            if stamp.tzinfo is None or 'T' not in short['timestamp']:raise ValueError()
        except ValueError:return None
        fields=short.groupdict()
        return Fragment(fields={'syslog':fields},spans=[('syslog.'+k,*short.span(k)) for k in fields],covered=[(0,short.end())],primitive_fields=len(fields)),short.end()
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
    start=match.end()
    nil_tag=raw.startswith('- ',start) and CSV_START.match(raw,start+2) is not None
    if nil_tag:start+=2
    # Some security appliances emit RFC3164-style TAG:CEF without an
    # optional space after the tag colon. Accept that boundary only when the
    # following byte begins a known structured payload.
    tag_match=None
    if not nil_tag and not _structured_payload(raw,start):
        tag_match=re.match(
            r'(?P<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95}(?:\[\d{1,8}\])?):',
            raw[start:],
        )
        if tag_match is not None:
            candidate=start+tag_match.end()
            if _structured_payload(raw,candidate):
                start=candidate
            else:
                tag_match=None
    if not _structured_payload(raw,start):return None
    fields={key:value for key,value in values.items() if value is not None}
    result=Fragment(fields={'syslog':fields},
        spans=[('syslog.'+key,*match.span(key)) for key in fields],
        covered=[(0,match.end())],primitive_fields=len(fields))
    if nil_tag:
        fields['tag']='-';result.spans.append(('syslog.tag',match.end(),match.end()+1))
        result.primitive_fields+=1;result.covered=[(0,start)]
    elif tag_match is not None:
        tag_start=match.end()+tag_match.start('tag')
        tag_end=match.end()+tag_match.end('tag')
        fields['tag']=tag_match['tag']
        result.spans.append(('syslog.tag',tag_start,tag_end))
        result.primitive_fields+=1;result.covered=[(0,start)]
    return result,start
