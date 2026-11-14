"""Bounded tagless BSD/PRI envelopes for explicit security-source payloads.

The RFC3164 header ends at HOSTNAME; a colon-terminated application TAG is not
required to retain a CEF/LEEF/JSON payload. No substring search or semantic
vendor detection is used. Headerless CSV stays an unlabeled source candidate.

The header tokens come from the shared grammar contract
(contracts/syslog-header-grammar.v1.json through the generated module), like
the browser and the Ruby export: HOSTNAME is optional and can never be a
key=value token, a structured-body opener or a colon-terminated TAG.
"""
from __future__ import annotations
import re
from datetime import datetime
from structured_source import Fragment,MONTHS
from syslog_header_grammar_generated import TOKENS,PRI_MAX,RFC5424_SUPPORTED_VERSIONS

_BSD_PREFIX=(r'^(?:<(?P<pri>'+TOKENS['PRI']+r')>)?(?P<month>'+TOKENS['BSD_MONTH']+r') +'
             r'(?P<day>'+TOKENS['BSD_DAY']+r')')
_BSD_CLOCK=r'(?P<time>'+TOKENS['CLOCK2']+':'+TOKENS['CLOCK2']+':'+TOKENS['CLOCK2']+r') +'
_BSD_HOST=r'(?:(?P<hostname>'+TOKENS['BSD_HOSTNAME']+r') +)?'

BSD_HEADER=re.compile(_BSD_PREFIX+' +'+_BSD_CLOCK+_BSD_HOST)
BSD_YEAR_HEADER=re.compile(_BSD_PREFIX+r' +(?P<year>[0-9]{4}) +'+_BSD_CLOCK+_BSD_HOST)
SHORT_IETF_CSV_HEADER=re.compile(r'^<(?P<pri>'+TOKENS['PRI']+r')>(?P<version>'+TOKENS['RFC5424_VERSION']+r') (?P<timestamp>[^ \t\r\n]{1,64}) (?P<hostname>'+TOKENS['RFC5424_HOSTNAME']+r') +(?=[0-9]{1,10},)')
PRI_HEADER=re.compile(r'^<(?P<pri>'+TOKENS['PRI']+r')>[ \t]*')
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
    if short is not None and int(short['pri'])<=PRI_MAX and short['version'] in RFC5424_SUPPORTED_VERSIONS:
        try:
            stamp=datetime.fromisoformat(short['timestamp'].replace('Z','+00:00'))
            if stamp.tzinfo is None or 'T' not in short['timestamp']:raise ValueError()
        except ValueError:return None
        fields=short.groupdict()
        return Fragment(fields={'syslog':fields},spans=[('syslog.'+k,*short.span(k)) for k in fields],covered=[(0,short.end())],primitive_fields=len(fields)),short.end()
    match=BSD_YEAR_HEADER.match(raw) or BSD_HEADER.match(raw)
    if match is not None:
        values=match.groupdict()
        hh,mm,ss=map(int,values['time'].split(':'))
        if (not 1<=int(values['day'])<=MONTHS.get(values['month'],0)
            or hh>23 or mm>59 or ss>59
            or values.get('year') is not None and not 1<=int(values['year'])<=9999
            or values['pri'] is not None and int(values['pri'])>PRI_MAX):
            return None
    else:
        match=PRI_HEADER.match(raw)
        if match is None or int(match['pri'])>PRI_MAX:return None
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
