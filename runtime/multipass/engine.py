"""Isolated, deterministic research POC. Not a production parser or Stellar compiler.

Only public-source fixtures are read in the separate benchmark; no network
requests, LLM calls, user credentials, DP or sensor sockets in this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import csv
from datetime import datetime
import hashlib
import ipaddress
import json
import math
import re
from syslog_header_grammar_generated import KV_ASCII_WHITESPACE
from typing import Any

MAX_RAW_BYTES = 131072
MAX_CAPTURED_FIELDS = 4096
MAX_JSON_DEPTH = 40
BSD = re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d\d:\d\d:\d\d +\S+ +")
PRI = re.compile(r"^<(?P<priority>\d{1,3})>")
IPv4_STRICT = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DEC = json.JSONDecoder()


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    source_path: str
    rule_id: str
    role: str


@dataclass
class ParseResult:
    raw: str
    variant: str = "unknown"
    syntax: str = "UNKNOWN"
    fields: dict[str, Any] = field(default_factory=dict)
    spans: list[Span] = field(default_factory=list)
    covered: list[tuple[int, int]] = field(default_factory=list)
    unparsed: list[tuple[int, int]] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    parsed_source_fields: int = 0
    native_verified: bool = False
    target_verified: bool = False

    @property
    def status(self) -> str:
        if self.issues and not self.fields:
            return "RAW_ONLY"
        if self.issues or self.unparsed:
            return "PARTIAL" if self.fields else "RAW_ONLY"
        if not self.fields:
            return "STRUCTURED_UNMAPPED" if self.covered else "RAW_ONLY"
        # Syntax and semantic extraction can both succeed, but this is NEVER
        # a native/target parser qualification.
        return "LOCAL_EXTRACTED"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw.encode("utf-8")).hexdigest()

    def close(self) -> ParseResult:
        # Real source characters, including whitespace and punctuation, must
        # be either consumed as syntax/known fields or retained as unknown.
        intervals = sorted((max(0, a), min(len(self.raw), b))
                           for a, b in self.covered if a < b)
        cursor = 0
        unknown: list[tuple[int, int]] = []
        for a, b in intervals:
            if a > cursor:
                unknown.append((cursor, a))
            cursor = max(cursor, b)
        if cursor < len(self.raw):
            unknown.append((cursor, len(self.raw)))
        self.unparsed = unknown
        return self

    def summary(self) -> dict[str, Any]:
        def byte(i: int) -> int:
            return len(self.raw[:i].encode("utf-8"))
        return {
            "source_sha256": self.sha256,
            "variant": self.variant,
            "syntax": self.syntax,
            "status": self.status,
            "extracted_fields": sorted(self.fields),
            "parsed_source_fields": self.parsed_source_fields,
            "unparsed_bytes": sum(byte(b)-byte(a) for a,b in self.unparsed),
            "unparsed_ranges": [{"start_byte":byte(a),"end_byte":byte(b)}
                                for a,b in self.unparsed],
            "capture_provenance": [
                {"start_byte":byte(x.start),"end_byte":byte(x.end),
                 "rule_id":x.rule_id,"source_path":x.source_path,
                 "semantic_role":x.role}
                for x in self.spans
            ],
            "issues":list(self.issues),
            "native_verified":False,
            "target_verified":False,
        }


class SpanJsonDecoder:
    """Bounded strict JSON visitor with exact original character-index spans.

    Python character offsets are converted to UTF-8 byte offsets in summary.
    Duplicate object keys are rejected. Strings and arrays are not regex-parsed.
    """
    def __init__(self, raw: str):
        self.raw=raw
        self.i=0
        self.nodes:dict[str,tuple[Any,int,int]]={}
        # Lossless source identities coexist with legacy semantic aliases.
        self.source_leaves:list[tuple[tuple[str|int,...],str,Any,int,int]]=[]
        self.count=0

    def whitespace(self) -> None:
        n=len(self.raw)
        while self.i<n and self.raw[self.i] in " \n\t\r":
            self.i+=1

    def read(self, path: str="", depth:int=0, source_segments:tuple[str|int,...]=()) -> Any:
        if depth>MAX_JSON_DEPTH or self.count>MAX_CAPTURED_FIELDS:
            raise ValueError("JSON_DEPTH_OR_FIELD_LIMIT")
        self.whitespace()
        start=self.i
        if self.i >= len(self.raw): raise ValueError("JSON_TRUNCATED")
        char=self.raw[self.i]
        if char=="{":
            self.i+=1;self.whitespace()
            out={}
            if self.raw[self.i:self.i+1]=="}":
                self.i+=1
            else:
                while True:
                    self.whitespace()
                    if self.raw[self.i:self.i+1]!='"':
                        raise ValueError("JSON_KEY_INVALID")
                    key,self.i=DEC.raw_decode(self.raw,self.i)
                    if not isinstance(key,str) or key in out or key in {"__proto__","constructor","prototype"}:
                        raise ValueError("JSON_DUPLICATE_OR_UNSAFE_KEY")
                    self.whitespace()
                    if self.raw[self.i:self.i+1]!=":":
                        raise ValueError("JSON_COLON_MISSING")
                    self.i+=1
                    sub=path+"."+key if path else key
                    out[key]=self.read(sub,depth+1,source_segments+(key,))
                    self.whitespace()
                    nxt=self.raw[self.i:self.i+1]
                    if nxt=="}":
                        self.i+=1;break
                    if nxt!=",":
                        raise ValueError("JSON_OBJECT_DELIMITER")
                    self.i+=1
            self.nodes[path]=(out,start,self.i)
            return out
        if char=="[":
            self.i+=1;self.whitespace();out=[]
            if self.raw[self.i:self.i+1]=="]":
                self.i+=1
            else:
                while True:
                    if len(out)>=MAX_CAPTURED_FIELDS:raise ValueError("JSON_ARRAY_LIMIT")
                    sub=f"{path}[{len(out)}]"
                    out.append(self.read(sub,depth+1,source_segments+(len(out),)))
                    self.whitespace()
                    nxt=self.raw[self.i:self.i+1]
                    if nxt=="]":
                        self.i+=1;break
                    if nxt!=",":
                        raise ValueError("JSON_ARRAY_DELIMITER")
                    self.i+=1
            self.nodes[path]=(out,start,self.i)
            return out
        if self.count>=MAX_CAPTURED_FIELDS:
            raise ValueError("JSON_FIELD_LIMIT")
        value,end=DEC.raw_decode(self.raw,self.i)
        # Python's default decoder accepts NaN/Infinity and overflows large
        # exponents. Neither may become a verified original numeric value.
        if isinstance(value,float) and not math.isfinite(value):
            raise ValueError("JSON_NUMBER_RANGE_OR_CONSTANT_UNSUPPORTED")
        self.i=end
        self.count+=1
        self.nodes[path]=(value,start,end)
        self.source_leaves.append((source_segments,path,value,start,end))
        return value

    def parse(self) -> Any:
        data=self.read()
        self.whitespace()
        if self.i!=len(self.raw):
            raise ValueError("JSON_TRAILING_DATA")
        return data


def safe_ip(value:Any) -> str | None:
    if not isinstance(value,str) or not value:
        return None
    try:
        return str(ipaddress.ip_address(value.removeprefix("/")))
    except ValueError:
        return None


def safe_port(value:Any) -> int | None:
    if isinstance(value,bool):
        return None
    if isinstance(value,(int,str)) and str(value).isdigit():
        parsed=int(value)
        return parsed if 0<=parsed<=65535 else None
    return None


def emit(result:ParseResult, role:str, value:Any, source_path:str,
         start:int,end:int,rule_id:str) -> None:
    if start<0 or end>len(result.raw) or end<=start:
        raise ValueError("CAPTURE_RANGE_INVALID")
    if role.endswith(".ip"):
        vals=value if isinstance(value,list) else [value]
        clean=[ip for v in vals if (ip:=safe_ip(v)) is not None]
        if not clean:
            result.issues.append("INVALID_IP:"+source_path)
            return
        value=clean if len(clean)>1 else clean[0]
    elif role.endswith(".port"):
        clean=safe_port(value)
        if clean is None:
            result.issues.append("INVALID_PORT:"+source_path)
            return
        value=clean
    elif role=="event.action":
        if isinstance(value,list):
            value=[str(v).lower() for v in value if isinstance(v,str)]
        elif isinstance(value,str):
            value=value.lower() if rule_id.startswith("trend:") else value
        else:
            return
    elif role in {"user.name","url.original"} and not isinstance(value,str):
        return
    if role in result.fields and result.fields[role]!=value:
        result.issues.append("SEMANTIC_ROLE_COLLISION:"+role)
        return
    result.fields[role]=value
    result.spans.append(Span(start,end,source_path,rule_id,role))


def parse_quoted_kv(result:ParseResult, begin:int) -> dict[str,tuple[str,int,int]]:
    s=result.raw
    n=len(s)
    i=begin
    out:dict[str,tuple[str,int,int]]={}
    while i<n:
        start=i
        while i<n and s[i] in KV_ASCII_WHITESPACE:
            i+=1
        if i>start:result.covered.append((start,i))
        if i>=n:break
        start=i
        m=re.match(r"[A-Za-z][A-Za-z0-9_.-]{0,127}=",s[i:])
        if not m:
            result.issues.append("KV_TOKEN_UNRECOGNIZED")
            break
        key=m.group()[:-1]
        i+=m.end()
        val_start=i
        if i<n and s[i]=='"':
            i+=1
            decoded=[]
            while i<n:
                if s[i]=="\\":
                    if i+1>=n:
                        result.issues.append("KV_ESCAPE_TRUNCATED");return out
                    # Decode only familiar escaped quotes and backslashes.
                    decoded.append(s[i+1] if s[i+1] in ('"',"\\") else s[i:i+2])
                    i+=2
                elif s[i]=='"':
                    i+=1
                    break
                else:
                    decoded.append(s[i]);i+=1
            else:
                result.issues.append("KV_QUOTE_UNCLOSED")
                return out
            if i<n and not s[i] in KV_ASCII_WHITESPACE:
                result.issues.append("KV_AFTER_QUOTE_INVALID");return out
            value="".join(decoded)
            val_span=(val_start+1,i-1)
        else:
            while i<n and not s[i] in KV_ASCII_WHITESPACE:
                i+=1
            value=s[val_start:i]
            val_span=(val_start,i)
        if key in out:
            result.issues.append("KV_DUPLICATE_KEY:"+key)
            break
        if not value:
            result.issues.append("KV_EMPTY_VALUE:"+key)
        out[key]=(value,*val_span)
        result.covered.append((start,i))
    result.parsed_source_fields=len(out)
    return out


def parse_csv_spans(result:ParseResult,begin:int) -> list[tuple[str,int,int]]:
    # csv.reader provides validation and transformations; spans are scanned
    # independently and must agree in count and actual decoded content.
    s=result.raw[begin:]
    if "\r" in s or "\n" in s:
        raise ValueError("CSV_EVENT_MULTILINE_UNSUPPORTED")
    try:
        values=next(csv.reader([s],strict=True))
    except csv.Error as e:
        raise ValueError("CSV_GRAMMAR_INVALID") from e
    parts=[]
    pos=begin
    for value in values:
        if pos>len(result.raw):raise ValueError("CSV_SPAN_MISMATCH")
        start=pos
        if result.raw[pos:pos+1]=='"':
            pos+=1
            chars=[]
            value_start=pos
            while pos<len(result.raw):
                if result.raw[pos]=='"':
                    if result.raw[pos:pos+2]=='""':
                        chars.append('"');pos+=2
                    else:
                        pos+=1;break
                else:
                    chars.append(result.raw[pos]);pos+=1
            else:raise ValueError("CSV_UNCLOSED_QUOTE")
            if "".join(chars)!=value:raise ValueError("CSV_QUOTE_VALUE_MISMATCH")
            captured_start=value_start;captured_end=pos-1
        else:
            captured_start=pos
            while pos<len(result.raw) and result.raw[pos]!=',':
                pos+=1
            captured_end=pos
            if result.raw[captured_start:captured_end]!=value:
                raise ValueError("CSV_VALUE_MISMATCH")
            # RFC 4180 rule 5: a double quote may not appear inside a field that is not enclosed. csv.reader
            # accepts it even in strict mode; the browser tokenizer and Ruby's CSV.parse_line reject the row.
            if '"' in value:
                raise ValueError("CSV_GRAMMAR_INVALID")
        parts.append((value,captured_start,captured_end))
        if pos<len(result.raw):
            if result.raw[pos]!=',':raise ValueError("CSV_DELIMITER_INVALID")
            pos+=1
        result.covered.append((start,pos))
    if pos!=len(result.raw):
        raise ValueError("CSV_TRAILING_UNACCOUNTED")
    result.parsed_source_fields=len(parts)
    return parts


def from_kv(r:ParseResult,kv:dict[str,tuple[str,int,int]]) -> None:
    direct={"srcip":"source.ip","dstip":"destination.ip",
            "srcport":"source.port","dstport":"destination.port",
            "user":"user.name","action":"event.action"}
    for source,role in direct.items():
        if source in kv:
            value,a,b=kv[source]
            # Vendor placeholders such as "N/A" are not user entities.
            if source=="user" and value.strip().lower() in ("n/a","none","-","unknown"):
                continue
            if b>a:
                emit(r,role,value,source,a,b,"fortinet:typed-kv-v0.1")


def from_csv(r:ParseResult,items:list[tuple[str,int,int]]) -> None:
    # These positions have been characterized against PAN-OS source fixtures,
    # not inferred as a universal CSV schema.
    if len(items)<31:
        r.issues.append("PANOS_COLUMNS_INSUFFICIENT");return
    typ=items[3][0]
    subtype=items[4][0]
    if typ not in ("TRAFFIC","THREAT"):
        r.issues.append("PANOS_VARIANT_UNKNOWN");return
    r.variant="paloalto:"+typ.lower()+":"+subtype
    for source,role in [(7,"source.ip"),(8,"destination.ip"),(24,"source.port"),(25,"destination.port")]:
        value,a,b=items[source]
        if value and b>a:
            emit(r,role,value,f"csv[{source}]",a,b,"panos:typed-positional-v0.1")
    # Reference-profile subtype semantics are distinct from the original
    # raw action: raw "allow" maps to flow_terminated for subtype "end".
    # Only the profiled, observed combinations are supported; unknown -> no
    # event.action instead of guessing a normalized meaning.
    actions={
        ("TRAFFIC","end"):"flow_terminated",
        ("TRAFFIC","start"):"flow_started",
        ("TRAFFIC","drop"):"flow_dropped",
        ("TRAFFIC","deny"):"flow_denied",
        ("THREAT","url"):"url_filtering",
    }
    action=actions.get((typ,subtype))
    if action:
        _name,a,b=items[4]
        emit(r,"event.action",action,"csv[4]",a,b,"panos:action-by-subtype-v0.1")


def json_map(r:ParseResult,root:Any,dec:SpanJsonDecoder) -> None:
    if not isinstance(root,dict):
        r.issues.append("JSON_ROOT_NOT_OBJECT")
        return
    def add(path:str,role:str,rule:str,allow_ip_list:bool=True) -> None:
        node=dec.nodes.get(path)
        if node is None: return
        value,a,b=node
        if role.endswith(".ip") and isinstance(value,list) and not allow_ip_list: return
        emit(r,role,value,path,a,b,rule)
    if "_eventType" in root and "_serverId" in root:
        r.variant="trellix:edr"
        for source,role in [
            ("sourceAddress","source.ip"),("destAddress","destination.ip"),
            ("sourcePort","source.port"),("destPort","destination.port"),
            ("action","event.action"),("userName","user.name"),
            ("httpUrl","url.original")
        ]:
            add(source,role,"trellix:edr-json-v0.1")
    elif root.get("type")=="MVEvents" and isinstance(root.get("attributes"),dict):
        r.variant="trellix:epo"
        for role,paths in [
            ("source.ip",["attributes.sourceipv4","attributes.sourceipv6"]),
            ("destination.ip",["attributes.targetipv4","attributes.targetipv6"])
        ]:
            values=[];ranges=[]
            for path in paths:
                node=dec.nodes.get(path)
                if node and (v:=safe_ip(node[0])):
                    values.append(v);ranges.append((path,node[1],node[2]))
            if values:
                # Multiple independent byte ranges share one semantic role.
                r.fields[role]=values if len(values)>1 else values[0]
                for path,a,b in ranges:
                    r.spans.append(Span(a,b,path,"trellix:epo-json-v0.1",role))
        add("attributes.sourceusername","user.name","trellix:epo-json-v0.1")
        add("attributes.sourceurl","url.original","trellix:epo-json-v0.1")
    elif ("eventTime" in root or "eventTimeDT" in root) and any(
        k in root for k in ("act","src","dst","eventName","productCode")):
        r.variant="trend:vision_one"
        for source,role in [
            ("src","source.ip"),("dst","destination.ip"),
            ("spt","source.port"),("dpt","destination.port"),
            ("act","event.action"),("url","url.original")
        ]:
            add(source,role,"trend:vision-one-json-v0.1")
    elif set(root).issubset({"data","links","meta","items","progressRate"}):
        r.variant="api:non_event_metadata"
    else:
        r.variant="json:unknown"


def parse_event(raw:str) -> ParseResult:
    if not isinstance(raw,str):raise TypeError("RAW_NOT_STRING")
    r=ParseResult(raw)
    if not raw or len(raw.encode("utf8"))>MAX_RAW_BYTES:
        return ParseResult(raw,issues=["SOURCE_SIZE_INVALID"]).close()
    if any(c=="\x00" for c in raw):
        return ParseResult(raw,issues=["SOURCE_NUL_INVALID"]).close()
    pri=PRI.match(raw)
    if pri and 0<=int(pri.group("priority"))<=191 and (
        raw[pri.end():].startswith(("date=","devname=","devid="))
        and ("devid=" in raw[pri.end():pri.end()+512]
             or "date=" in raw[pri.end():pri.end()+512])
    ):
        r.variant="fortinet:unclassified"
        r.syntax="SYSLOG_PRI_QUOTED_KV"
        r.covered.append((0,pri.end()))
        kv=parse_quoted_kv(r,pri.end())
        if "type" in kv:
            r.variant="fortinet:"+kv["type"][0]+":"+kv.get("subtype",("",0,0))[0]
        from_kv(r,kv)
    elif (m:=BSD.match(raw)) is not None and re.match(r"\d+,",raw[m.end():]):
        r.syntax="SYSLOG_BSD_PANOS_CSV"
        r.covered.append((0,m.end()))
        try:
            parts=parse_csv_spans(r,m.end())
            from_csv(r,parts)
        except ValueError as exc:
            r.issues.append(str(exc))
    elif raw.lstrip().startswith("{"):
        try:
            dec=SpanJsonDecoder(raw)
            obj=dec.parse()
            r.syntax="JSON"
            r.covered.append((0,len(raw)))
            r.parsed_source_fields=dec.count
            json_map(r,obj,dec)
        except (ValueError,IndexError,RecursionError,json.JSONDecodeError) as exc:
            r.issues.append(str(exc)[:80])
            r.covered.clear()
    else:
        r.issues.append("NO_VERIFIED_PROFILE")
    return r.close()


def mine_residual_templates(records:list[ParseResult]) -> dict[str,int]:
    """Deterministic cheap-first residual fingerprinting, NOT actual Drain3.

    Only unparsed spans, not already-structured fields, are clustered.
    Similarity/masks are suggestions; no template is compiled or marked true.
    """
    templates:dict[str,int]={}
    for r in records:
        for start,end in r.unparsed:
            text=r.raw[start:end].strip()
            if len(text)<8:
                continue
            text=re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b","<IP>",text)
            text=re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}\b","<UUID>",text)
            text=re.sub(r"\b\d+\b","<NUM>",text)
            text=text[:512]
            templates[text]=templates.get(text,0)+1
    return dict(sorted(templates.items(),key=lambda x:(-x[1],x[0])))
