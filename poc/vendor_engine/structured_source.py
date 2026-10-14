"""Deterministic CEF/LEEF decoding and RFC3164 framing for source extraction.

Research-only implementation influenced by reviewed Vector VRL and the
existing Parser Studio structuredFamilies.ts grammar, without copying either.
All value spans refer to original raw input character offsets. Source paths
are namespaced, no dictionary or normalized ECS semantics are assigned.
"""
from __future__ import annotations

from dataclasses import dataclass,field
import re
from typing import Any

SAFE_KEY=re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
KEY_START=re.compile(r"([A-Za-z_][A-Za-z0-9_.-]{0,127})=")
ESCAPE_MAP={"n":"\n","r":"\r","t":"\t"}
UNSAFE={"__proto__","prototype","constructor"}
MONTHS={"Jan":31,"Feb":29,"Mar":31,"Apr":30,"May":31,
        "Jun":30,"Jul":31,"Aug":31,"Sep":30,"Oct":31,"Nov":30,"Dec":31}
BSD_FRAMED=re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) +(?P<host>[^\s]+) "
    r"(?P<tag>[A-Za-z_][A-Za-z0-9_.-]{0,95}(?:\[\d{1,8}\])?): +",
)


@dataclass
class Fragment:
    fields:dict[str,Any]=field(default_factory=dict)
    spans:list[tuple[str,int,int]]=field(default_factory=list)
    covered:list[tuple[int,int]]=field(default_factory=list)
    issues:list[str]=field(default_factory=list)
    primitive_fields:int=0


def _unescape(segment:str)->str:
    out=[]
    i=0
    while i<len(segment):
        c=segment[i]
        if c=="\\" and i+1<len(segment):
            c2=segment[i+1]
            if c2 in "\\=|:]\\\"":out.append(c2)
            else:out.append(ESCAPE_MAP.get(c2,"\\"+c2))
            i+=2
        else:
            out.append(c)
            i+=1
    return "".join(out)


def _pipe_parts(raw:str,offset:int,header_count:int) -> tuple[list[tuple[str,int,int]],int]:
    """Return exact seven/six/etc header fields plus extension byte position."""
    parts=[]
    start=offset
    i=offset
    while i<len(raw):
        if raw[i]=="\\":
            i+=2
            continue
        if raw[i]=="|":
            parts.append((_unescape(raw[start:i]),start,i))
            if len(parts)==header_count:
                return parts,i+1
            start=i+1
        i+=1
    raise ValueError("STRUCTURED_HEADER_INCOMPLETE")


def _pair(store:dict[str,Any],key:str,value:str,issues:list[str]) -> None:
    if key in store:
        prev=store[key]
        # No data is dropped when a vendor emits a repeated field name.
        store[key]=prev+[value] if isinstance(prev,list) else [prev,value]
        issues.append("DUPLICATE_SOURCE_FIELD")
    else:store[key]=value


def _cef_extension(raw:str,begin:int)->Fragment:
    ext=Fragment(fields={})
    n=len(raw)
    pos=begin
    while pos<n:
        whitespace=pos
        while pos<n and raw[pos] in " \t":
            pos+=1
        if pos==n:
            ext.covered.append((whitespace,pos))
            break
        match=KEY_START.match(raw,pos)
        if not match or match.group(1) in UNSAFE:
            ext.issues.append("CEF_INVALID_EXTENSION_KEY_OR_BOUNDARY")
            break
        key=match.group(1)
        start=match.end()
        cursor=start
        if cursor<n and raw[cursor] in ('"',"'"):
            quote=raw[cursor]
            cursor+=1
            start=cursor
            while cursor<n:
                if raw[cursor]=="\\" and cursor+1<n:
                    cursor+=2
                    continue
                if raw[cursor]==quote:
                    break
                cursor+=1
            if cursor==n:
                ext.issues.append("CEF_UNCLOSED_QUOTE")
                break
            end=cursor
            cursor+=1
            if cursor<n and not raw[cursor].isspace():
                ext.issues.append("CEF_INVALID_QUOTE_SUFFIX")
                break
        else:
            while cursor<n:
                if raw[cursor]=="\\" and cursor+1<n:
                    cursor+=2
                    continue
                if raw[cursor].isspace():
                    probe=cursor
                    while probe<n and raw[probe].isspace():
                        probe+=1
                    if probe==n or KEY_START.match(raw,probe):
                        break
                cursor+=1
            end=cursor
            while end>start and raw[end-1].isspace():
                end-=1
        value=_unescape(raw[start:end])
        _pair(ext.fields,key,value,ext.issues)
        ext.spans.append(("cef_extension."+key,start,end))
        ext.primitive_fields+=1
        ext.covered.append((whitespace,cursor))
        pos=cursor
        if ext.primitive_fields>=1024:
            # Exactly at the limit is complete when only syntax remains.
            # An additional field stays in the raw residual, never truncated.
            if raw[pos:].strip(" \t"):
                ext.issues.append("CEF_EXTENSION_LIMIT")
            elif pos<n:
                ext.covered.append((pos,n))
            break
    return ext


def _leef_extension(raw:str,begin:int,delimiter:str)->Fragment:
    ext=Fragment()
    i=begin
    n=len(raw)
    while i<=n:
        end=raw.find(delimiter,i)
        if end<0:end=n
        if end>i:
            content=raw[i:end]
            split=content.find("=")
            if split<1 or not SAFE_KEY.fullmatch(content[:split]) or content[:split] in UNSAFE:
                ext.issues.append("LEEF_INVALID_EXTENSION_TOKEN")
                break
            key=content[:split]
            value=content[split+1:]
            _pair(ext.fields,key,value,ext.issues)
            ext.spans.append(("leef_extension."+key,i+split+1,end))
            ext.primitive_fields+=1
        ext.covered.append((i,min(end+1,n)))
        if end==n:break
        i=end+1
        if ext.primitive_fields>=1024:
            if raw[i:].strip(delimiter):
                ext.issues.append("LEEF_EXTENSION_LIMIT")
            elif i<n:
                ext.covered.append((i,n))
            break
    return ext


def decode_cef_or_leef(raw:str,offset:int=0)->Fragment:
    """Parse only on exact CEF:/LEEF: prefix. Never substring-fallback."""
    out=Fragment()
    if raw.startswith("CEF:",offset):
        start=offset+4
        names=("version","vendor","product","device_version","signature_id",
               "name","severity")
        try:
            parts,ext_offset=_pipe_parts(raw,start,len(names))
        except ValueError as exc:
            out.issues.append(str(exc))
            return out
        if parts[0][0] not in ("0","1"):
            out.issues.append("CEF_VERSION_UNSUPPORTED")
            return out
        out.fields["cef_header"]={name:item[0] for name,item in zip(names,parts)}
        out.spans.extend((f"cef_header.{name}",item[1],item[2])
                         for name,item in zip(names,parts))
        out.primitive_fields=len(names)
        out.covered.append((offset,ext_offset))
        extension=_cef_extension(raw,ext_offset)
        out.fields["cef_extension"]=extension.fields
    elif raw.startswith("LEEF:",offset):
        start=offset+5
        is_v2=raw.startswith("LEEF:2.0|",offset)
        is_v1=raw.startswith("LEEF:1.0|",offset)
        if not (is_v1 or is_v2):
            out.issues.append("LEEF_VERSION_UNSUPPORTED")
            return out
        names=("version","vendor","product","product_version","event_id")
        if is_v2:names+=("delimiter",)
        try:
            parts,ext_offset=_pipe_parts(raw,start,len(names))
        except ValueError as exc:
            out.issues.append(str(exc))
            return out
        if parts[0][0] not in ("1.0","2.0"):
            out.issues.append("LEEF_VERSION_INVALID")
            return out
        if is_v2:
            token=parts[-1][0]
            if re.fullmatch(r"0x[0-9a-fA-F]{2}",token):
                delimiter=chr(int(token[2:],16))
            else:delimiter=token
        else:delimiter="\t"
        if len(delimiter)!=1 or delimiter in ("=","\\") or ord(delimiter)<9:
            out.issues.append("LEEF_DELIMITER_UNSUPPORTED")
            return out
        out.fields["leef_header"]={name:item[0] for name,item in zip(names,parts)}
        out.spans.extend((f"leef_header.{name}",item[1],item[2])
                         for name,item in zip(names,parts))
        out.primitive_fields=len(names)
        out.covered.append((offset,ext_offset))
        extension=_leef_extension(raw,ext_offset,delimiter)
        out.fields["leef_extension"]=extension.fields
    else:
        out.issues.append("UNSUPPORTED_STRUCTURED_FAMILY")
        return out
    out.primitive_fields+=extension.primitive_fields
    out.spans.extend(extension.spans)
    out.covered.extend(extension.covered)
    out.issues.extend(extension.issues)
    return out


def extract_rfc3164(raw:str)->tuple[Fragment,int]|None:
    """Bounded PRI/BSD/TAG header frame; body stays in a separate parse pass."""
    matched=BSD_FRAMED.match(raw)
    if not matched:return None
    fields=matched.groupdict()
    pri=int(fields["pri"])
    day=int(fields["day"])
    h,m,s=(int(x) for x in fields["time"].split(":"))
    if (pri>191 or day<1 or day>MONTHS.get(fields["month"],0)
        or h>23 or m>59 or s>59):
        return None
    result=Fragment()
    names=("pri","month","day","time","host","tag")
    result.fields["syslog"]={k:fields[k] for k in names}
    result.spans.extend(("syslog."+k,*matched.span(k)) for k in names)
    result.primitive_fields=len(names)
    result.covered.append((0,matched.end()))
    return result,matched.end()


RFC5424_HEAD=re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) "
    r"(?P<timestamp>\S+) (?P<hostname>\S+) (?P<appname>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) "
)
RFC5424_HEAD_ADJACENT_SD=re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) "
    r"(?P<timestamp>\S+) (?P<hostname>\S+) (?P<appname>\S+) "
    r"(?P<procid>\S+) (?P<msgid>[!-~]{1,32}?)(?=\[)"
)


def extract_rfc5424(raw:str,*,source_preserving:bool=False,
                    allow_adjacent_sd:bool=False)->tuple[Fragment,int|None]|None:
    """RFC5424 v1 bounded header and SD attributes, with optional body.

    The default remains strict. source_preserving retains invalid timestamp,
    duplicate SD values and terminal SD spacing with explicit issues; it does
    not certify RFC conformance. Copies the *constraints*, not implementation, of our qualified local TS
    scanner. All SD fields are vendor source fields, never ECS mappings.
    """
    if allow_adjacent_sd:
        match=RFC5424_HEAD_ADJACENT_SD.match(raw) or RFC5424_HEAD.match(raw)
    else:
        match=RFC5424_HEAD.match(raw)
    if not match:
        return None
    result=Fragment()
    values=match.groupdict()
    if int(values["pri"])>191 or values["version"]!="1":
        result.issues.append("RFC5424_PRIORITY_OR_VERSION_UNSUPPORTED")
        return result,None
    timestamp=values["timestamp"]
    if timestamp!="-":
        try:
            from datetime import datetime
            parsed=datetime.fromisoformat(timestamp.replace("Z","+00:00"))
            if parsed.tzinfo is None or "T" not in timestamp:
                raise ValueError("RFC5424_TIMESTAMP_ZONE_REQUIRED")
        except ValueError:
            result.issues.append("RFC5424_TIMESTAMP_INVALID")
            if not source_preserving:return result,None
    limits={"hostname":255,"appname":48,"procid":128,"msgid":32}
    for path,limit in limits.items():
        value=values[path]
        if (len(value.encode("utf8"))>limit or
            not re.fullmatch(r"[!-~]+",value)):
            result.issues.append("RFC5424_HEADER_TOKEN_INVALID")
            return result,None
    pos=match.end()
    syslog={k:values[k] for k in
            ("pri","version","timestamp","hostname","appname","procid","msgid")}
    result.spans.extend(("syslog."+k,*match.span(k)) for k in syslog)
    result.primitive_fields=len(syslog)
    # If structured-data parsing later fails, strict RFC parsing remains
    # fail-closed. Source-preserving callers may retain the independently
    # validated header, but strict callers must not expose orphan spans.
    header_span_count=len(result.spans)
    header_primitive_fields=result.primitive_fields
    sd_start=pos
    structured={}
    if raw[pos:pos+1]=="-":
        pos+=1
    elif raw[pos:pos+1]=="[":
        while raw[pos:pos+1]=="[":
            pos+=1
            def read_name()->str:
                nonlocal pos
                start=pos
                while pos<len(raw):
                    code=ord(raw[pos])
                    if code<33 or code>126 or raw[pos] in '\"=[]\\':
                        break
                    pos+=1
                if not (1<=pos-start<=32):
                    raise ValueError("RFC5424_INVALID_SD_NAME")
                return raw[start:pos]
            try:
                ident=read_name()
                if ident in structured or ident in UNSAFE:
                    raise ValueError("RFC5424_DUPLICATE_SD_ID")
                fields={}
                while raw[pos:pos+1]==" ":
                    pos+=1
                    if source_preserving and raw[pos:pos+1]==']':
                        result.issues.append('RFC5424_SD_TRAILING_SPACE_NONSTANDARD')
                        break
                    key=read_name()
                    if key in UNSAFE or key in fields and not source_preserving:
                        raise ValueError("RFC5424_DUPLICATE_SD_KEY")
                    if key in fields:result.issues.append('RFC5424_DUPLICATE_SD_KEY')
                    if raw[pos:pos+2]!='=\"':
                        raise ValueError("RFC5424_SD_VALUE_NOT_QUOTED")
                    pos+=2
                    first=pos
                    while pos<len(raw):
                        if raw[pos]=="\\":
                            if pos+1>=len(raw) or raw[pos+1] not in ("]",'"',"\\"):
                                raise ValueError("RFC5424_INVALID_SD_ESCAPE")
                            pos+=2
                            continue
                        if raw[pos]=='"':
                            break
                        if raw[pos]=="]" or ord(raw[pos])<32 or ord(raw[pos])==127:
                            raise ValueError("RFC5424_INVALID_SD_VALUE")
                        pos+=1
                    if pos>=len(raw):
                        raise ValueError("RFC5424_UNTERMINATED_SD_VALUE")
                    value=_unescape(raw[first:pos])
                    if key in fields:
                        previous=fields[key]
                        fields[key]=previous+[value] if isinstance(previous,list) else [previous,value]
                    else:fields[key]=value
                    result.spans.append((f"syslog.structured_data.{ident}.{key}",first,pos))
                    result.primitive_fields+=1
                    pos+=1
                if raw[pos:pos+1]!="]":
                    raise ValueError("RFC5424_SD_UNCLOSED")
                pos+=1
                structured[ident]=fields
                if len(raw[sd_start:pos].encode("utf8"))>1024:
                    raise ValueError("RFC5424_SD_BYTE_LIMIT")
            except ValueError as exc:
                result.issues.append(str(exc))
                if source_preserving:
                    result.spans=result.spans[:header_span_count]
                    result.primitive_fields=header_primitive_fields
                    result.fields["syslog"]=dict(syslog)
                    result.covered=[(0,match.end())]
                else:
                    result.spans=[]
                    result.primitive_fields=0
                    result.fields={}
                    result.covered=[]
                return result,None
    else:
        result.issues.append("RFC5424_STRUCTURED_DATA_MISSING")
        return result,None
    syslog["structured_data_raw"]=raw[sd_start:pos]
    syslog["structured_data"]=structured
    result.spans.append(("syslog.structured_data_raw",sd_start,pos))
    result.primitive_fields+=1
    result.fields["syslog"]=syslog
    if pos==len(raw):
        result.covered.append((0,pos))
        return result,None
    if raw[pos:pos+1]!=" ":
        result.issues.append("RFC5424_BODY_BOUNDARY_INVALID")
        result.covered.append((0,pos))
        return result,None
    pos+=1
    result.covered.append((0,pos))
    return result,pos


PLAIN_BSD_HEAD=re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) +(?P<hostname>\S+) "
    r"(?P<app_tag>[^:\s]{1,128}): +",
)
APACHE_ERROR_HEAD=re.compile(
    r"^\[(?P<timestamp>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} "
    r"\d{2}:\d{2}:\d{2} \d{4})\] +\[(?P<level>[A-Za-z0-9_-]{1,40})\] +",
)


def extract_plain_bsd(raw:str)->tuple[Fragment,int]|None:
    """Traditional BSD syslog without PRI. Preserve body as unresolved."""
    match=PLAIN_BSD_HEAD.match(raw)
    if not match:return None
    values=match.groupdict()
    day=int(values["day"])
    hh,mm,ss=(int(x) for x in values["time"].split(":"))
    if (day<1 or day>MONTHS.get(values["month"],0)
        or hh>23 or mm>59 or ss>59):
        return None
    fields={k:values[k] for k in
            ("month","day","time","hostname","app_tag")}
    fragment=Fragment(
        fields={"syslog":fields},
        spans=[("syslog."+k,*match.span(k)) for k in fields],
        covered=[(0,match.end())],primitive_fields=len(fields),
    )
    return fragment,match.end()


def extract_apache_error(raw:str)->tuple[Fragment,int]|None:
    """Apache error envelope; never parse residual free text as JSON."""
    match=APACHE_ERROR_HEAD.match(raw)
    if not match:return None
    from datetime import datetime
    try:
        datetime.strptime(match.group("timestamp"),"%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    attrs={k:match.group(k) for k in ("timestamp","level")}
    return (
        Fragment(fields={"apache":attrs},
                 spans=[("apache."+k,*match.span(k)) for k in attrs],
                 covered=[(0,match.end())],primitive_fields=len(attrs)),
        match.end(),
    )
