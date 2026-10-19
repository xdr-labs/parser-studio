"""Common source transport/container framing (no vendor pattern matching).

Preserve original wire boundaries, bytes, and lexical field spans. These
results are source structure only, NOT evidence that downloadable DRAFT
compilers accept the original container. Ambiguous framing abstains.
"""
from __future__ import annotations
import json
import re
from source_parse import SourceEvent,ValueSpan

MAX_FRAME_BYTES=65536
HEADER_KEY=re.compile(r'^[A-Z][A-Z0-9_]{0,127}$')
OCTET_HEAD=re.compile(r'([1-9][0-9]{0,5}) ')


def _framed_event(text:str,parser,kind:str)->SourceEvent:
    e=parser(text)
    e.issues.append('FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER')
    return e


def _invalid_stream(raw:str,reason:str):
    event=SourceEvent(raw,syntax='UNSUPPORTED_SOURCE_CONTAINER',
                      issues=[reason],unparsed=[(0,len(raw))])
    return [('EVENT',0,len(raw),event)]


def _octet(raw:str,max_events:int,parser):
    pos=0
    parts=[]
    count=0
    while pos<len(raw):
        m=OCTET_HEAD.match(raw,pos)
        if not m:return None
        n=int(m.group(1))
        if not 1<=n<=MAX_FRAME_BYTES:return _invalid_stream(raw,'FRAMING_OCTET_LENGTH_INVALID')
        begin=m.end()
        try:
            body=raw[begin:].encode('utf8')[:n].decode('utf8','strict')
        except UnicodeDecodeError:
            return _invalid_stream(raw,'FRAMING_OCTET_BOUNDARY_SPLITS_UTF8')
        end=begin+len(body)
        if len(body.encode('utf8'))!=n or end>len(raw):
            return _invalid_stream(raw,'FRAMING_OCTET_TRUNCATED')
        if not body.startswith(('<','{','[')):
            return None
        parts.append(('SOURCE_FRAMING',pos,begin,None))
        parts.append(('EVENT',begin,end,_framed_event(body,parser,'RFC6587')))
        count+=1
        if count>max_events:return _invalid_stream(raw,'FRAMING_EVENT_LIMIT')
        pos=end
    return parts if count else None


def _nul(raw:str,max_events:int,parser):
    if '\x00' not in raw:return None
    if not raw.endswith('\x00'):
        return _invalid_stream(raw,'FRAMING_UNTERMINATED_NUL_CONTAINER')
    pos=0
    count=0
    parts=[]
    while pos<len(raw):
        end=raw.find('\x00',pos)
        if end<=pos:return _invalid_stream(raw,'FRAMING_EMPTY_NUL_RECORD')
        body=raw[pos:end]
        if len(body.encode('utf8'))>MAX_FRAME_BYTES:
            return _invalid_stream(raw,'FRAMING_RECORD_SIZE_LIMIT')
        if body.startswith('{'):
            try:obj=json.loads(body)
            except (ValueError,TypeError):return _invalid_stream(raw,'FRAMING_INVALID_GELF_JSON')
            if not (isinstance(obj,dict) and obj.get('version')=='1.1'
                    and isinstance(obj.get('host'),str)
                    and isinstance(obj.get('short_message'),str)):
                return _invalid_stream(raw,'FRAMING_GELF_REQUIRED_FIELDS')
        elif not body.startswith('<'):
            return _invalid_stream(raw,'FRAMING_UNKNOWN_NUL_PAYLOAD')
        parts.append(('EVENT',pos,end,_framed_event(body,parser,'RFC6587_OR_GELF_TCP')))
        parts.append(('SOURCE_FRAMING',end,end+1,None))
        pos=end+1
        count+=1
        if count>max_events:return _invalid_stream(raw,'FRAMING_EVENT_LIMIT')
    return parts


def _json_seq(raw:str,max_events:int,parser):
    if not raw.startswith('\x1e'):return None
    parts=[]
    pos=0
    count=0
    while pos<len(raw):
        if raw[pos]!='\x1e':return _invalid_stream(raw,'FRAMING_JSON_SEQ_MISSING_RS')
        parts.append(('SOURCE_FRAMING',pos,pos+1,None))
        begin=pos+1
        next_rs=raw.find('\x1e',begin)
        end=len(raw) if next_rs<0 else next_rs
        chunk=raw[begin:end]
        trim=len(chunk)-len(chunk.rstrip('\n'))
        if trim>1:return _invalid_stream(raw,'FRAMING_JSON_SEQ_EXTRA_LINE_ENDS')
        json_end=end-trim
        source=raw[begin:json_end]
        if not source or len(source.encode('utf8'))>MAX_FRAME_BYTES:
            return _invalid_stream(raw,'FRAMING_JSON_SEQ_RECORD_LIMIT')
        try:obj=json.loads(source)
        except (TypeError,ValueError):return _invalid_stream(raw,'FRAMING_JSON_SEQ_RECORD_INVALID')
        if not isinstance(obj,(list,dict)):
            return _invalid_stream(raw,'FRAMING_JSON_SEQ_PRIMITIVE_UNSUPPORTED')
        parts.append(('EVENT',begin,json_end,_framed_event(source,parser,'RFC7464')))
        if trim:parts.append(('WHITESPACE',json_end,end,None))
        pos=end
        count+=1
        if count>max_events:return _invalid_stream(raw,'FRAMING_EVENT_LIMIT')
    return parts if count else None


def _journal(raw:str,max_events:int):
    if not (raw.startswith(('MESSAGE=','__CURSOR=','_BOOT_ID=')) and
            '\n\n' in raw and '\x00' not in raw):
        return None
    # Whole records are paragraphs separated by an empty line. The lexical
    # field value is the original substring to the end of its physical line.
    sep='\r\n\r\n' if '\r\n' in raw else '\n\n'
    if sep=='\r\n\r\n' and raw.replace('\r\n','').find('\n')>=0:
        return _invalid_stream(raw,'FRAMING_JOURNAL_MIXED_LINE_ENDINGS')
    parts=[]
    count=0
    pos=0
    while pos<len(raw):
        split=raw.find(sep,pos)
        end=len(raw) if split<0 else split
        source=raw[pos:end]
        # A single trailing line break is part of the event's source.
        if not source:return _invalid_stream(raw,'FRAMING_JOURNAL_EMPTY_ENTRY')
        if len(source.encode('utf8'))>MAX_FRAME_BYTES:
            return _invalid_stream(raw,'FRAMING_JOURNAL_ENTRY_LIMIT')
        parsed=SourceEvent(source,syntax='JOURNAL_EXPORT_GROUP')
        values={}
        spans=[]
        line_pos=0
        linebreak='\r\n' if sep.startswith('\r\n') else '\n'
        for line in source.splitlines(keepends=True):
            lexical=line.removesuffix(linebreak)
            key,equals,meaning=lexical.partition('=')
            if not equals or not HEADER_KEY.fullmatch(key) or key in values:
                parsed.issues.append('FRAMING_JOURNAL_FIELD_INVALID_OR_DUPLICATE')
                break
            values[key]=meaning
            begin=line_pos+len(key)+1
            finish=begin+len(meaning)
            spans.append(ValueSpan(key,len(source[:begin].encode('utf8')),
                                   len(source[:finish].encode('utf8'))))
            line_pos+=len(line)
        if not parsed.issues and values.get('MESSAGE') is None:
            parsed.issues.append('FRAMING_JOURNAL_MESSAGE_MISSING')
        if parsed.issues:
            parsed.unparsed=[(0,len(source))]
        else:
            parsed.vendor_fields=values
            parsed.primitive_fields=len(values)
            parsed.value_spans=spans
            parsed.covered=[(0,len(source))]
            parsed.issues.append('FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER')
        parts.append(('EVENT',pos,end,parsed))
        count+=1
        if count>max_events:return _invalid_stream(raw,'FRAMING_EVENT_LIMIT')
        if split<0:break
        parts.append(('SOURCE_FRAMING',end,end+len(sep),None))
        pos=end+len(sep)
    return parts if count else None


def parse_transport_container(raw:str,max_events:int,parser):
    """Return exact, nonoverlapping partitions or None for ordinary streams."""
    if not raw or len(raw.encode('utf8'))>1048576:return None
    if raw.startswith('\x1e'):return _json_seq(raw,max_events,parser)
    if '\x00' in raw:return _nul(raw,max_events,parser)
    if OCTET_HEAD.match(raw):
        return _octet(raw,max_events,parser)
    return _journal(raw,max_events)
