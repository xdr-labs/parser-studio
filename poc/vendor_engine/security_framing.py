"""Bounded, lossless framing for structured security-log sample streams.

JSON/NDJSON and multiline JSON may coexist with line-delimited Syslog, CEF,
LEEF, KV and CSV. No vendor-field normalization, line concatenation, record
mutation, array explosion, event-time rewriting or external IO occurs here.
Ambiguous or truncated suffixes remain opaque, rather than invented records.
"""
from __future__ import annotations
from dataclasses import dataclass,field
from collections import Counter
from array import array
import re
from source_parse import SourceEvent,assert_source_accounting
from security_source import parse_security_source
from engine import MAX_RAW_BYTES
from structured_source import extract_rfc3164,extract_rfc5424,extract_plain_bsd

DEFAULT_BATCH_BYTES=1048576
MAX_BATCH_BYTES=16777216
MAX_EVENTS=10000
ARRAY_START=re.compile(r'\[\s*(?:[\[{}\]"0-9-]|true\b|false\b|null\b)')
WHITESPACE=' \t\r\n'


@dataclass(frozen=True)
class SecurityFrame:
    raw:str
    start_byte:int
    end_byte:int
    event:SourceEvent


@dataclass(frozen=True)
class Separator:
    start_byte:int
    end_byte:int
    kind:str='WHITESPACE'


@dataclass
class SecurityBatch:
    raw:str
    frames:list[SecurityFrame]=field(default_factory=list)
    separators:list[Separator]=field(default_factory=list)

    def report(self)->dict:
        """Public aggregate-only evidence; original values stay local."""
        counts=Counter(frame.event.status for frame in self.frames)
        return {
            'contract':'parser-studio.poc.security-framing.v1',
            'input_bytes':len(self.raw.encode('utf8')),
            'record_count':len(self.frames),
            'record_bytes':sum(f.end_byte-f.start_byte for f in self.frames),
            'separator_bytes':sum(s.end_byte-s.start_byte for s in self.separators),
            'source_fields':sum(f.event.primitive_fields for f in self.frames),
            'source_value_spans':sum(len(f.event.value_spans) for f in self.frames),
            'status_counts':dict(sorted(counts.items())),
            'dictionary_attempted':False,'native_verified':False,
            'target_verified':False,'masking_optimization':False,
        }


def _line_end(raw:str,start:int)->int:
    end=raw.find('\n',start)
    if end<0:return len(raw)
    return end-1 if end>start and raw[end-1]=='\r' else end


def _collection_at(raw:str,start:int)->bool:
    return raw.startswith('{',start) or ARRAY_START.match(raw,start) is not None


def _direct_json_start(raw:str,start:int)->int|None:
    if _collection_at(raw,start):return start
    if raw.startswith('@cee: ',start):
        pos=start+6
        while pos<len(raw) and raw[pos] in ' \t':pos+=1
        if raw.startswith('{',pos):return pos
    return None


def _json_body_start(raw:str,start:int)->int|None:
    direct=_direct_json_start(raw,start)
    if direct is not None:return direct
    # An envelope is recognized independently of its JSON body's contents.
    # Only the first physical header line is inspected; no prose inference.
    line=raw[start:_line_end(raw,start)]
    for extractor in (extract_rfc5424,extract_rfc3164,extract_plain_bsd):
        outer=extractor(line)
        if outer is not None:
            fragment,offset=outer
            if not fragment.issues and offset is not None:
                pos=start+offset
                while pos<len(raw) and raw[pos] in ' \t':pos+=1
                return _direct_json_start(raw,pos)
            return None
    # Devices can emit PRI followed immediately by a JSON collection.
    matched=re.match(r'<([0-9]{1,3})>[ \t]*',line)
    if matched and int(matched[1])<=191:
        pos=start+matched.end()
        if _collection_at(raw,pos):return pos
    return None


def _json_end(raw:str,start:int)->tuple[int,str|None]:
    stack=[];quoted=False;escape=False
    for pos in range(start,len(raw)):
        char=raw[pos]
        if quoted:
            if escape:escape=False
            elif char=='\\':escape=True
            elif char=='"':quoted=False
            continue
        if char=='"':quoted=True
        elif char in '{[':
            stack.append(char)
            if len(stack)>64:return len(raw),'FRAMING_NESTING_LIMIT'
        elif char in '}]':
            if not stack or {'{':'}','[':']'}[stack.pop()]!=char:
                return _line_end(raw,pos),'FRAMING_MISMATCHED_JSON_DELIMITER'
            if not stack:return pos+1,None
    return len(raw),'FRAMING_TRUNCATED_JSON'


def _opaque(raw:str,issue:str)->SourceEvent:
    return SourceEvent(raw=raw,issues=[issue],unparsed=[(0,len(raw))])


def parse_security_batch(raw:str,*,max_events:int=1000,
                         max_bytes:int=DEFAULT_BATCH_BYTES)->SecurityBatch:
    """Frame once, then run the existing source parser on unchanged slices.

    Byte offsets cover the original stream exactly once, including whitespace
    and a leading UTF-8 BOM. JSON arrays remain one original record. Truncated
    JSON is not split speculatively at lines that might be nested values.
    """
    if not isinstance(raw,str):raise TypeError('SECURITY_BATCH_NOT_TEXT')
    if (type(max_events) is not int or not 1<=max_events<=MAX_EVENTS or
        type(max_bytes) is not int or not 1<=max_bytes<=MAX_BATCH_BYTES):
        raise ValueError('SECURITY_BATCH_BOUND_INVALID')
    try:data=raw.encode('utf8','strict')
    except UnicodeEncodeError as exc:raise ValueError('SECURITY_BATCH_UTF8_INVALID') from exc
    if len(data)>max_bytes:raise ValueError('SECURITY_BATCH_SIZE_LIMIT')
    # One character-to-byte ledger avoids repeated prefix encoding per field.
    offsets=array('I',[0])
    for char in raw:offsets.append(offsets[-1]+len(char.encode('utf8')))
    result=SecurityBatch(raw)
    pos=0
    if raw.startswith('\ufeff'):
        result.separators.append(Separator(0,offsets[1],'UTF8_BOM'));pos=1
    while pos<len(raw):
        begin=pos
        while pos<len(raw) and raw[pos] in WHITESPACE:pos+=1
        if pos>begin:result.separators.append(Separator(offsets[begin],offsets[pos]))
        if pos==len(raw):break
        start=pos;issue=None
        json_start=_json_body_start(raw,start)
        if json_start is not None:
            end,issue=_json_end(raw,json_start)
            if issue is None:
                next_pos=end
                while next_pos<len(raw) and raw[next_pos] in ' \t':next_pos+=1
                if (next_pos<len(raw) and raw[next_pos] not in '\r\n'
                    and not _collection_at(raw,next_pos)):
                    end=_line_end(raw,next_pos);issue='FRAMING_JSON_TRAILING_CONTENT'
        else:end=_line_end(raw,start)
        if end<=start:raise AssertionError('SECURITY_FRAMING_NO_PROGRESS')
        if len(result.frames)==max_events-1 and raw[end:].strip(WHITESPACE):
            end=len(raw);issue='FRAMING_EVENT_LIMIT'
        piece=raw[start:end]
        if offsets[end]-offsets[start]>MAX_RAW_BYTES:issue='FRAMING_RECORD_SIZE_LIMIT'
        event=_opaque(piece,issue) if issue else parse_security_source(piece)
        result.frames.append(SecurityFrame(piece,offsets[start],offsets[end],event))
        pos=end
    assert_batch_accounting(result)
    return result


def assert_batch_accounting(batch:SecurityBatch)->None:
    """Every input byte is one original record or an explicit separator."""
    data=batch.raw.encode('utf8')
    partitions=[(f.start_byte,f.end_byte) for f in batch.frames]
    for frame in batch.frames:
        if data[frame.start_byte:frame.end_byte].decode('utf8')!=frame.raw:
            raise AssertionError('SECURITY_FRAME_SOURCE_CHANGED')
        if frame.event.raw!=frame.raw:raise AssertionError('SECURITY_PARSED_SOURCE_CHANGED')
        assert_source_accounting(frame.event)
    for separator in batch.separators:
        text=data[separator.start_byte:separator.end_byte].decode('utf8')
        if separator.kind=='UTF8_BOM':
            if separator.start_byte!=0 or text!='\ufeff':raise AssertionError('INVALID_SOURCE_BOM')
        elif not text or any(c not in WHITESPACE for c in text):
            raise AssertionError('NON_WHITESPACE_SOURCE_SEPARATOR')
        partitions.append((separator.start_byte,separator.end_byte))
    position=0
    for start,end in sorted(partitions):
        if start!=position or end<=start or end>len(data):
            raise AssertionError('SECURITY_SOURCE_GAP_OR_OVERLAP')
        position=end
    if position!=len(data):raise AssertionError('SECURITY_UNACCOUNTED_SOURCE_TAIL')
