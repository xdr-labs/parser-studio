"""Common source transport/container framing (no vendor pattern matching).

Preserve original wire boundaries, bytes, and lexical field spans. These
results are source structure only, NOT evidence that downloadable DRAFT
compilers accept the original container. Ambiguous framing abstains.
"""
from __future__ import annotations
import json
import re
from datetime import datetime
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
            try:obj=json.loads(body,object_pairs_hook=_no_duplicate_keys)
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
        try:obj=json.loads(source,object_pairs_hook=_no_duplicate_keys)
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



# Linux audit, Kubernetes CRI and Docker JSON-file are independent transport
# grammars. They may explain source records but do not make a Stellar/Ruby
# parser for the original transport available. Recognize only firm signatures.
AUDIT_HEAD=re.compile(
    r'^(?:node=(?P<node>[A-Za-z0-9][A-Za-z0-9_.:-]{0,250}) )?'
    r'type=(?P<type>[A-Z][A-Z0-9_]{1,63}) msg=audit\('
    r'(?P<timestamp>[0-9]{9,12}(?:\.[0-9]{1,9})?):'
    r'(?P<serial>[1-9][0-9]{0,19})\):(?: (?P<body>.*))?$')
AUDIT_SIGNATURE=re.compile(r'^(?:node=\S+ +)?type=[A-Z][A-Z0-9_]* +msg=audit\(')
CRI_SIGNATURE=re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T\S+ +(?:stdout|stderr) +[PF] +')
CRI_LINE=re.compile(
    r'(?P<time>\S+) (?P<stream>stdout|stderr) (?P<tag>[PF]) (?P<content>.*)\Z')
NANO_TIME=re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    r'(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$')
MAX_CONTAINER_FRAGMENTS=256


def _physical_lines(raw:str):
    """(start, value_end, full_end, text) with original untouched line bytes."""
    lines=[]
    pos=0
    while pos<len(raw):
        lf=raw.find('\n',pos)
        full_end=len(raw) if lf<0 else lf+1
        content_end=len(raw) if lf<0 else lf
        if lf>=0 and content_end>pos and raw[content_end-1]=='\r':
            content_end-=1
        text=raw[pos:content_end]
        if not text or '\r' in text:return None
        lines.append((pos,content_end,full_end,text))
        pos=full_end
    return lines


def _byte_span(raw:str,path:str,start:int,end:int,
               segments:tuple[str|int,...]|None=None)->ValueSpan:
    return ValueSpan(path,len(raw[:start].encode('utf8')),
                     len(raw[:end].encode('utf8')),segments)


def _quote_balanced(text:str)->bool:
    active=None
    escaped=False
    for char in text:
        if escaped:
            escaped=False
            continue
        if char=='\\' and active is not None:
            escaped=True
            continue
        if char in ('"',"'"):
            if active is None:active=char
            elif char==active:active=None
    return active is None and not escaped


def _audit(raw:str,max_events:int):
    if not AUDIT_SIGNATURE.match(raw):return None
    lines=_physical_lines(raw)
    if not lines:return _invalid_stream(raw,'FRAMING_AUDIT_PHYSICAL_LINES_INVALID')
    headers=[]
    for _,_,_,line in lines:
        if len(line.encode('utf8'))>MAX_FRAME_BYTES:
            return _invalid_stream(raw,'FRAMING_AUDIT_RECORD_LIMIT')
        match=AUDIT_HEAD.fullmatch(line)
        if match is None or not _quote_balanced(match.group('body') or ''):
            return _invalid_stream(raw,'FRAMING_AUDIT_RECORD_INVALID')
        headers.append(match)
    parts=[]
    i=0
    count=0
    while i<len(lines):
        first=headers[i]
        key=(first.group('node'),first.group('timestamp'),first.group('serial'))
        j=i+1
        # Events must be contiguous. Interleaved serials are never reordered,
        # or assigned a fictitious contiguous byte span around another event.
        while j<len(lines) and (headers[j].group('node'),
              headers[j].group('timestamp'),headers[j].group('serial'))==key:
            j+=1
        start=lines[i][0]
        end=lines[j-1][1]
        source=raw[start:end]
        if len(source.encode('utf8'))>MAX_FRAME_BYTES:
            return _invalid_stream(raw,'FRAMING_AUDIT_EVENT_LIMIT')
        parsed=SourceEvent(source,syntax='LINUX_AUDIT_SERIAL_GROUP')
        records=[]
        spans=[]
        first_serial=headers[i].span('serial')
        spans.append(_byte_span(source,'audit.serial',
                lines[i][0]+first_serial[0]-start,
                lines[i][0]+first_serial[1]-start,('audit','serial')))
        for offset,index in enumerate(range(i,j)):
            head=headers[index]
            record={'type':head.group('type')}
            if head.group('node') is not None:record['node']=head.group('node')
            if head.group('body') is not None:record['body']=head.group('body')
            records.append(record)
            for part in ('type','node','body'):
                if head.group(part) is None:continue
                a,b=head.span(part)
                spans.append(_byte_span(
                    source,f'audit.records[{offset}].{part}',
                    lines[index][0]+a-start,lines[index][0]+b-start,
                    ('audit','records',offset,part)))
        parsed.vendor_fields={'audit':{
            'serial':first.group('serial'),
            'timestamp':first.group('timestamp'),
            'records':records}}
        parsed.value_spans=spans
        parsed.primitive_fields=len(spans)
        parsed.covered=[(0,len(source))]
        parsed.issues=['FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER']
        parts.append(('EVENT',start,end,parsed))
        terminal_end=lines[j-1][2]
        if end<terminal_end:
            parts.append(('WHITESPACE',end,terminal_end,None))
        count+=1
        if count>max_events:return _invalid_stream(raw,'FRAMING_EVENT_LIMIT')
        i=j
    return parts


def _valid_nano_datetime(value:str)->bool:
    if not NANO_TIME.fullmatch(value):return False
    try:
        datetime.fromisoformat(value.replace('Z','+00:00'))
        return True
    except ValueError:
        return False


def _cri(raw:str,max_events:int):
    if not CRI_SIGNATURE.match(raw):return None
    if not raw.endswith('\n') or '\r' in raw:
        return _invalid_stream(raw,'FRAMING_CRI_INCOMPLETE_OR_NON_LF_STREAM')
    lines=_physical_lines(raw)
    if not lines:return _invalid_stream(raw,'FRAMING_CRI_PHYSICAL_LINES_INVALID')
    headers=[]
    for _,_,_,line in lines:
        match=CRI_LINE.fullmatch(line)
        if not match or not _valid_nano_datetime(match.group('time')):
            return _invalid_stream(raw,'FRAMING_CRI_RECORD_INVALID')
        headers.append(match)
    parts=[]
    count=0
    i=0
    while i<len(lines):
        first=headers[i]
        stream=first.group('stream')
        j=i+1
        if first.group('tag')=='P':
            # CRI P/F groups on the same stream are logical messages, but
            # cannot cross another stream without byte-overlap. Abstain.
            while j<len(lines) and headers[j].group('tag')=='P':
                if headers[j].group('stream')!=stream:
                    return _invalid_stream(raw,'FRAMING_CRI_INTERLEAVED_STREAM')
                j+=1
            if j>=len(lines):
                return _invalid_stream(raw,'FRAMING_CRI_UNTERMINATED_PARTIAL')
            if headers[j].group('stream')!=stream:
                return _invalid_stream(raw,'FRAMING_CRI_INTERLEAVED_STREAM')
            j+=1
        if j-i>MAX_CONTAINER_FRAGMENTS:
            return _invalid_stream(raw,'FRAMING_CRI_FRAGMENT_LIMIT')
        start=lines[i][0]
        end=lines[j-1][1]
        source=raw[start:end]
        if len(source.encode('utf8'))>MAX_FRAME_BYTES:
            return _invalid_stream(raw,'FRAMING_CRI_EVENT_LIMIT')
        parsed=SourceEvent(source,syntax='CRI_PARTIAL_FINAL_GROUP')
        fragments=[]
        spans=[]
        for offset,index in enumerate(range(i,j)):
            head=headers[index]
            value={name:head.group(name) for name in ('time','stream','tag','content')}
            fragments.append(value)
            for name in ('time','stream','tag','content'):
                a,b=head.span(name)
                spans.append(_byte_span(
                    source,f'cri.fragments[{offset}].{name}',
                    lines[index][0]+a-start,lines[index][0]+b-start,
                    ('cri','fragments',offset,name)))
        parsed.vendor_fields={'cri':{'stream':stream,'fragments':fragments}}
        parsed.value_spans=spans
        parsed.primitive_fields=len(spans)
        parsed.covered=[(0,len(source))]
        parsed.issues=['FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER']
        parts.append(('EVENT',start,end,parsed))
        if end<lines[j-1][2]:
            parts.append(('WHITESPACE',end,lines[j-1][2],None))
        count+=1
        if count>max_events:return _invalid_stream(raw,'FRAMING_EVENT_LIMIT')
        i=j
    return parts


def _no_duplicate_keys(pairs:list[tuple[str,object]]):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('FRAMING_JSON_DUPLICATE_KEY')
        result[key]=value
    return result


def _looks_docker(raw:str)->bool:
    first=raw.split('\n',1)[0]
    if not first.startswith('{'):return False
    try:
        payload=json.loads(first,object_pairs_hook=_no_duplicate_keys)
        # Two strongly suggestive Docker json-file keys claim the grammar;
        # a missing third required key must fail closed, not pass as JSON.
        return (isinstance(payload,dict) and
                sum(field in payload for field in ('log','stream','time'))>=2 and
                ('log' in payload or 'stream' in payload))
    except (ValueError,TypeError):
        found=sum(bool(re.search(r'"'+re.escape('"'+key+'"')+r'\s*:',first))
                  for key in ('log','stream','time'))
        return found>=2


def _docker(raw:str,max_events:int,parser):
    if not _looks_docker(raw):return None
    if '\r' in raw or not raw.endswith('\n'):
        return _invalid_stream(raw,'FRAMING_DOCKER_INCOMPLETE_OR_NON_LF_STREAM')
    lines=_physical_lines(raw)
    if not lines:return _invalid_stream(raw,'FRAMING_DOCKER_PHYSICAL_LINES_INVALID')
    if len(lines)>max_events:return _invalid_stream(raw,'FRAMING_EVENT_LIMIT')
    parts=[]
    for start,end,full_end,source in lines:
        if len(source.encode('utf8'))>MAX_FRAME_BYTES:
            return _invalid_stream(raw,'FRAMING_DOCKER_RECORD_LIMIT')
        try:
            obj=json.loads(source,object_pairs_hook=_no_duplicate_keys)
        except (TypeError,ValueError):
            return _invalid_stream(raw,'FRAMING_DOCKER_JSON_INVALID')
        if not isinstance(obj,dict) or not all(field in obj for field in ('log','stream','time')):
            return _invalid_stream(raw,'FRAMING_DOCKER_REQUIRED_FIELDS')
        if (not isinstance(obj['log'],str) or
            obj['stream'] not in ('stdout','stderr') or
            not isinstance(obj['time'],str) or
            not _valid_nano_datetime(obj['time'])):
            return _invalid_stream(raw,'FRAMING_DOCKER_FIELDS_INVALID')
        parsed=parser(source)
        if parsed.status!='SOURCE_PARSED':
            return _invalid_stream(raw,'FRAMING_DOCKER_SOURCE_PARSER_UNVERIFIED')
        parsed.syntax='DOCKER_JSON_FILE'
        parsed.issues.append('FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER')
        parts.append(('EVENT',start,end,parsed))
        if end<full_end:
            parts.append(('WHITESPACE',end,full_end,None))
    return parts


def parse_transport_container(raw:str,max_events:int,parser):
    """Return exact, nonoverlapping partitions or None for ordinary streams."""
    if not raw or len(raw.encode('utf8'))>1048576:return None
    if raw.startswith('\x1e'):return _json_seq(raw,max_events,parser)
    if '\x00' in raw:return _nul(raw,max_events,parser)
    if OCTET_HEAD.match(raw):
        return _octet(raw,max_events,parser)
    # Stop at the first authoritative signature. Do not re-interpret a
    # malformed recognized container through an unrelated fallback grammar.
    cri=_cri(raw,max_events)
    if cri is not None:return cri
    audit=_audit(raw,max_events)
    if audit is not None:return audit
    docker=_docker(raw,max_events,parser)
    if docker is not None:return docker
    return _journal(raw,max_events)
