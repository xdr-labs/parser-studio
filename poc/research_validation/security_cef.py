"""Independent CEF-standard boundary candidate; never a global KV replacement.

The current header/framing decoders are reused. Extension scanning is bounded
and honors CEF literal quotes, single-space boundaries and encoding. The
independent reference oracle is never imported. No raw rewriting or mapping.
This is a research dialect candidate, not an approved product default.
"""
from __future__ import annotations
import re
from typing import Callable
from engine import MAX_RAW_BYTES
from source_parse import SourceEvent,ValueSpan,_span,_close
from structured_source import _pipe_parts,extract_rfc3164,extract_rfc5424,extract_plain_bsd

NAMES=('version','vendor','product','device_version','signature_id','name','severity')
KEY=re.compile(r'([A-Za-z_][A-Za-z0-9_.-]{0,127})=')
BAD_KEYS={'__proto__','constructor','prototype'}
ESCAPES={'\\':'\\','=':'=','n':'\n','r':'\r'}


def _direct(raw:str)->SourceEvent|None:
    if not raw.startswith(('CEF:0|','CEF:1|')):return None
    try:parts,start=_pipe_parts(raw,4,7)
    except ValueError:return None
    result=SourceEvent(raw,syntax='CEF')
    result.vendor_fields={'cef_header':{name:v for name,(v,_,_) in zip(NAMES,parts)},'cef_extension':{}}
    result.value_spans=[_span(raw,'cef_header.'+name,a,b) for name,(_,a,b) in zip(NAMES,parts)]
    result.primitive_fields=7;result.covered=[(0,start)]
    if '\r' in raw or '\n' in raw:
        result.issues.append('CEF_LITERAL_RECORD_BREAK_UNSUPPORTED');return _close(result)
    pos=start;n=len(raw);target=result.vendor_fields['cef_extension'];count=0
    while pos<n:
        before=pos
        while pos<n and raw[pos] in ' \t':pos+=1
        if pos==n:
            result.covered.append((before,pos));break
        if count>=1024:
            result.issues.append('CEF_EXTENSION_LIMIT');break
        key=KEY.match(raw,pos)
        if key is None or key[1] in BAD_KEYS:
            result.issues.append('CEF_INVALID_EXTENSION_KEY_OR_BOUNDARY');break
        name=key[1];a=key.end();cursor=a;decoded=[];boundary=False;invalid=False
        while cursor<n:
            char=raw[cursor]
            if char=='\\':
                if cursor+1==n:
                    result.issues.append('CEF_ESCAPE_TRUNCATED');invalid=True;break
                nxt=raw[cursor+1]
                if nxt in ESCAPES:decoded.append(ESCAPES[nxt])
                else:
                    decoded.append(raw[cursor:cursor+2])
                    result.issues.append('CEF_NONSTANDARD_ESCAPE_RETAINED')
                cursor+=2;continue
            # Only the final separator before a key is structural. Earlier
            # spaces stay in the owning value. Quotes never alter this state.
            if char in ' \t' and KEY.match(raw,cursor+1):
                boundary=True;break
            decoded.append(char);cursor+=1
        if invalid:break
        b=cursor
        if not boundary:
            while b>a and raw[b-1] in ' \t':b-=1
            trailing=cursor-b
            if trailing:decoded=decoded[:-trailing]
        value=''.join(decoded)
        if name in target:
            old=target[name];target[name]=old+[value] if isinstance(old,list) else [old,value]
            result.issues.append('DUPLICATE_SOURCE_FIELD')
        else:target[name]=value
        result.value_spans.append(_span(raw,'cef_extension.'+name,a,b));result.primitive_fields+=1;count+=1
        result.covered.append((before,cursor));pos=cursor
    return _close(result)


def parse_security_cef(raw:str,*,base_parser:Callable[[str],SourceEvent])->SourceEvent:
    original=base_parser(raw)
    if not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw:return original
    direct=_direct(raw)
    if direct is not None:return direct
    for family,extractor in (('SYSLOG_RFC5424',extract_rfc5424),('SYSLOG_RFC3164',extract_rfc3164),('BSD_SYSLOG',extract_plain_bsd)):
        frame=extractor(raw)
        if frame is None:continue
        outer,start=frame
        if outer.issues or start is None:return original
        body=_direct(raw[start:])
        if body is None:return original
        event=SourceEvent(raw,syntax=family+'+CEF')
        event.vendor_fields={**outer.fields,'body':body.vendor_fields}
        event.primitive_fields=outer.primitive_fields+body.primitive_fields
        event.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
        offset=len(raw[:start].encode('utf8'))
        event.value_spans.extend(ValueSpan('body.'+s.path,offset+s.start_byte,offset+s.end_byte) for s in body.value_spans)
        event.covered=list(outer.covered)+[(start+a,start+b) for a,b in body.covered]
        event.issues=list(outer.issues)+body.issues
        return _close(event)
    return original
