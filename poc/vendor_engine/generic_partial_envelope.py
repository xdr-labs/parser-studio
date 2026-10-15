"""Conservative header recovery for incomplete appliance/syslog events.

This layer is candidate-only. It extracts exact header/event-code values from
strong bounded envelopes and never certifies the remaining free-text body.
"""
from __future__ import annotations

from copy import deepcopy
import re

from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

MONTH_DAYS={
    'Jan':31,'Feb':29,'Mar':31,'Apr':30,'May':31,'Jun':30,
    'Jul':31,'Aug':31,'Sep':30,'Oct':31,'Nov':30,'Dec':31,
}
TAG_ONLY=re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?'
    r'(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) +'
    r'(?P<time>\d{2}:\d{2}:\d{2}) +'
    r'(?P<label>[A-Za-z_][A-Za-z0-9_.-]{0,95}(?:\[\d{1,8}\])?): +'
)
NESTED_SEQUENCE=re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?'
    r'(?P<seq_0>\d{1,12}): +(?P<hostname>[^:\s]{1,255}): +'
    r'(?P<seq_1>\d{1,12}): +'
    r'(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) +'
    r'(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +'
    r'(?P<label>[A-Za-z0-9_.-]{1,95}): +'
)
IOS_UPTIME_SEQUENCE=re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?'
    r'(?P<seq_0>\d{1,12}): +(?P<hostname>[^:\s]{1,255}): +'
    r'(?P<seq_1>\d{1,12}): +(?P<uptime>[A-Za-z0-9_.-]{1,64}): +'
)
NEXUS_YEAR_HEADER=re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?:? *'
    r'(?P<year>\d{4}) +(?P<month>[A-Z][a-z]{2}) +'
    r'(?P<day>\d{1,2}) +(?P<time>\d{2}:\d{2}:\d{2}) +'
    r'(?P<timezone>[A-Z]{2,8}) *: +'
)
EVENT_CODE=re.compile(
    r'(?<![A-Za-z0-9_])%([A-Z][A-Z0-9_-]{1,31})-(\d{1,2})-'
    r'([A-Z0-9_]{3,64}):'
)


def _b(raw:str,pos:int)->int:
    return len(raw[:pos].encode('utf8'))


def _valid_pri(match:re.Match[str])->bool:
    pri=match.groupdict().get('pri')
    return pri is None or int(pri)<=191


def _valid(match:re.Match[str])->bool:
    if not _valid_pri(match):
        return False
    month=match.group('month');day=int(match.group('day'))
    if day<1 or day>MONTH_DAYS.get(month,0):
        return False
    hh,mm,ss=(
        int(value)
        for value in match.group('time').split('.',1)[0].split(':')
    )
    return hh<=23 and mm<=59 and ss<=59


def _valid_year_header(match:re.Match[str])->bool:
    if not _valid_pri(match):
        return False
    year=int(match.group('year'))
    if year<1970 or year>2200:
        return False
    month=match.group('month');day=int(match.group('day'))
    if day<1 or day>MONTH_DAYS.get(month,0):
        return False
    hh,mm,ss=(int(value) for value in match.group('time').split(':'))
    return hh<=23 and mm<=59 and ss<=59


def _overlaps(a:int,b:int,spans:list[ValueSpan])->bool:
    return any(max(a,s.start_byte)<min(b,s.end_byte) for s in spans)


def _add_match(
    event:SourceEvent,match:re.Match[str],keys:tuple[str,...],
    syntax_suffix:str,validator=_valid,
)->SourceEvent:
    if not validator(match):
        return event
    specs=[]
    values={}
    for key in keys:
        value=match.groupdict().get(key)
        if value is None:
            continue
        a,b=match.span(key)
        byte_a=_b(event.raw,a);byte_b=_b(event.raw,b)
        if _overlaps(byte_a,byte_b,event.value_spans):
            return event
        values[key]=value
        specs.append((key,byte_a,byte_b))
    if not specs:
        return event
    out=deepcopy(event)
    out.vendor_fields['generic_envelope']=values
    for key,a,b in specs:
        out.value_spans.append(ValueSpan(
            f'generic_envelope.{key}',a,b,
            ('generic_envelope',key),
        ))
    out.covered.append((match.start(),match.end()))
    out.value_spans.sort(key=lambda s:(s.start_byte,s.end_byte,s.path))
    out.primitive_fields=len(out.value_spans)
    out.syntax=out.syntax+syntax_suffix
    out.unparsed=[]
    out=_close(out)
    if out.status=='SOURCE_PARSED':
        out.issues.append('GENERIC_ENVELOPE_CANDIDATE_ONLY')
        out=_close(out)
    assert_source_accounting(out)
    return out


def _add_event_code(event:SourceEvent,start:int)->SourceEvent:
    matches=[
        match for match in EVENT_CODE.finditer(event.raw,start)
        if not _overlaps(
            _b(event.raw,match.start()),_b(event.raw,match.end()),
            event.value_spans,
        )
    ]
    if len(matches)!=1:
        return event
    match=matches[0]
    out=deepcopy(event)
    values={}
    for index in (1,2,3):
        key=f'part_{index-1}';value=match.group(index)
        a,b=match.span(index);byte_a=_b(event.raw,a);byte_b=_b(event.raw,b)
        values[key]=value
        out.value_spans.append(ValueSpan(
            f'generic_event_code.{key}',byte_a,byte_b,
            ('generic_event_code',key),
        ))
    out.vendor_fields['generic_event_code']=values
    out.covered.append((match.start(),match.end()))
    out.value_spans.sort(key=lambda s:(s.start_byte,s.end_byte,s.path))
    out.primitive_fields=len(out.value_spans)
    out.syntax=out.syntax+'+GENERIC_EVENT_CODE_CANDIDATE'
    out.unparsed=[]
    out=_close(out)
    if out.status=='SOURCE_PARSED':
        out.issues.append('GENERIC_EVENT_CODE_CANDIDATE_ONLY')
        out=_close(out)
    assert_source_accounting(out)
    return out


def augment_incomplete_envelope(event:SourceEvent)->SourceEvent:
    assert_source_accounting(event)
    if event.status=='SOURCE_PARSED':
        return event
    if 'generic_envelope' in event.vendor_fields:
        return event
    match=NESTED_SEQUENCE.match(event.raw)
    keys=('pri','seq_0','hostname','seq_1','month','day','time','label')
    suffix='+GENERIC_NESTED_SEQUENCE_HEADER'
    validator=_valid
    if match is None:
        match=IOS_UPTIME_SEQUENCE.match(event.raw)
        keys=('pri','seq_0','hostname','seq_1','uptime')
        suffix='+GENERIC_IOS_UPTIME_HEADER'
        validator=_valid_pri
    if match is None:
        match=NEXUS_YEAR_HEADER.match(event.raw)
        keys=('pri','year','month','day','time','timezone')
        suffix='+GENERIC_NEXUS_YEAR_HEADER'
        validator=_valid_year_header
    if match is None:
        # Tag-only BSD-like rows already expose the same visible tokens
        # through the qualified RFC3164 parser. Reinterpreting them would
        # change field ownership without adding source values.
        return event
    out=_add_match(event,match,keys,suffix,validator)
    if out is event:
        return event
    return _add_event_code(out,match.end())
