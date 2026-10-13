"""Syntax-first vendor-field extraction, independent of semantic normalization.

This is a standalone experimental adapter, NOT native Fluentd/Stellar parsing.
Successful source extraction retains every vendor key/value (including unknown
fields), preserving the original event and exact value byte spans. JSON keeps
the original typed nested tree; CSV retains numbered columns, including empty
cells. Semantic source/destination/user roles are deliberately NOT assigned.
"""
from __future__ import annotations

from dataclasses import dataclass,field
import hashlib
import json
import re
from typing import Any

from engine import (
    BSD, PRI, MAX_RAW_BYTES, ParseResult, SpanJsonDecoder,
    parse_quoted_kv, parse_csv_spans,
)
from structured_source import (
    decode_cef_or_leef,extract_rfc3164,extract_rfc5424,
    extract_plain_bsd,extract_apache_error,
)
from residual_kv import recover_kv_islands

KV_AT_START=re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}=")
JSON_ARRAY_START=re.compile(r'^\[\s*(?:[\[{}\]"0-9-]|true\b|false\b|null\b)')
CSV_AT_START=re.compile(r'^(?:[^,\r\n]*,){2}[^\r\n]*$')


@dataclass(frozen=True)
class ValueSpan:
    path:str
    start_byte:int
    end_byte:int


@dataclass
class SourceEvent:
    raw:str
    syntax:str="UNKNOWN"
    vendor_fields:dict[str,Any]=field(default_factory=dict)
    value_spans:list[ValueSpan]=field(default_factory=list)
    covered:list[tuple[int,int]]=field(default_factory=list)
    unparsed:list[tuple[int,int]]=field(default_factory=list)
    issues:list[str]=field(default_factory=list)
    primitive_fields:int=0
    normalization_attempted:bool=False
    native_verified:bool=False
    target_verified:bool=False

    @property
    def status(self)->str:
        if self.issues or self.unparsed:
            return "PARTIAL" if self.vendor_fields else "RAW_ONLY"
        if not self.vendor_fields:
            return "STRUCTURED_EMPTY" if self.covered else "RAW_ONLY"
        return "SOURCE_PARSED"

    @property
    def raw_sha256(self)->str:
        return hashlib.sha256(self.raw.encode("utf8")).hexdigest()

    @property
    def residual_bytes(self)->int:
        return sum(len(self.raw[a:b].encode("utf8")) for a,b in self.unparsed)

    @property
    def source_bytes(self)->int:
        return len(self.raw.encode("utf8"))

    def report(self)->dict[str,Any]:
        """Value-free public metadata only. Never serialize source field values."""
        return {
            "syntax":self.syntax,"status":self.status,
            "source_bytes":self.source_bytes,
            "residual_bytes":self.residual_bytes,
            "source_fields":self.primitive_fields,
            "source_spans":len(self.value_spans),
            "issues":list(self.issues),
            "normalization_attempted":False,
            "native_verified":False,"target_verified":False,
        }


def _span(raw:str,path:str,start:int,end:int)->ValueSpan:
    if start<0 or end<start or end>len(raw):
        raise ValueError("INVALID_VENDOR_VALUE_RANGE")
    return ValueSpan(
        path,len(raw[:start].encode("utf8")),
        len(raw[:end].encode("utf8")),
    )


def parse_source(raw:str)->SourceEvent:
    """Extract source structure only. Unknown/malformed bytes are never lost."""
    if not isinstance(raw,str):
        raise TypeError("RAW_NOT_STRING")
    event=SourceEvent(raw)
    if not raw or len(raw.encode("utf8"))>MAX_RAW_BYTES or "\x00" in raw:
        event.issues.append("SOURCE_SIZE_OR_NUL_INVALID")
        return _close(event)

    # Stage 1: envelope/body decomposition. RFC5424 must be checked BEFORE
    # generic PRI+KV; RFC3164 can carry CEF, LEEF, JSON, or KV payloads.
    framed=extract_rfc5424(raw)
    family="SYSLOG_RFC5424"
    if framed is None:
        framed=extract_rfc3164(raw)
        family="SYSLOG_RFC3164"
    if framed is None:
        # Real devices also emit "<PRI> CEF:..." without an RFC timestamp.
        # Recognize only an exact known structured body after the PRI; do
        # not mistake arbitrary text as a complete parser success.
        pri_simple=PRI.match(raw)
        if pri_simple and int(pri_simple.group("priority"))<=191:
            body_start=pri_simple.end()
            while raw[body_start:body_start+1]==" ":
                body_start+=1
            next_body=raw[body_start:]
            if next_body.startswith(("CEF:","LEEF:","{")):
                from structured_source import Fragment
                framed=(
                    Fragment(
                        fields={"syslog":{"pri":pri_simple.group("priority")}},
                        spans=[("syslog.pri",*pri_simple.span("priority"))],
                        covered=[(0,body_start)],
                        primitive_fields=1,
                    ),
                    body_start,
                )
                family="SYSLOG_PRI"
    if framed is None:
        framed=extract_plain_bsd(raw)
        family="BSD_SYSLOG"
    if framed is None:
        framed=extract_apache_error(raw)
        family="APACHE_ERROR"
    if framed is not None:
        outer,body_start=framed
        event.syntax=family
        event.vendor_fields=dict(outer.fields)
        event.primitive_fields=outer.primitive_fields
        event.value_spans=[
            _span(raw,path,start,end) for path,start,end in outer.spans
        ]
        event.covered=list(outer.covered)
        event.issues=list(outer.issues)
        if body_start is not None:
            body=parse_source(raw[body_start:])
            event.syntax=family+"+"+body.syntax
            event.vendor_fields["body"]=body.vendor_fields
            event.primitive_fields+=body.primitive_fields
            base_bytes=len(raw[:body_start].encode("utf8"))
            event.value_spans.extend(
                ValueSpan("body."+item.path,base_bytes+item.start_byte,
                          base_bytes+item.end_byte)
                for item in body.value_spans
            )
            event.covered.extend(
                (body_start+a,body_start+b) for a,b in body.covered
            )
            event.issues.extend(body.issues)
        return _close(event)

    # Stage 2: decode CEF/LEEF header and extensions separately so no
    # semantic normalization is required, and preserve all vendor keys.
    if raw.startswith(("CEF:","LEEF:")):
        component=decode_cef_or_leef(raw)
        event.syntax="CEF" if raw.startswith("CEF:") else "LEEF"
        event.vendor_fields=component.fields
        event.value_spans=[
            _span(raw,path,start,end)
            for path,start,end in component.spans
        ]
        event.covered=component.covered
        event.issues=component.issues
        event.primitive_fields=component.primitive_fields
        return _close(event)

    parsed=ParseResult(raw)
    offset=0
    mode=""
    pri=PRI.match(raw)
    bsd=BSD.match(raw)
    if pri is not None and int(pri.group("priority"))<=191:
        offset=pri.end()
        parsed.covered.append((0,offset))
        if KV_AT_START.match(raw[offset:]):
            mode="KV"
            event.syntax="SYSLOG_PRI_KV"
        else:
            event.issues.append("UNSUPPORTED_PRI_BODY")
    elif bsd is not None:
        offset=bsd.end()
        parsed.covered.append((0,offset))
        if re.match(r"\d+,",raw[offset:]):
            mode="CSV"
            event.syntax="SYSLOG_BSD_CSV"
        elif KV_AT_START.match(raw[offset:]):
            mode="KV"
            event.syntax="SYSLOG_BSD_KV"
        else:
            event.issues.append("UNSUPPORTED_BSD_BODY")
    elif raw.lstrip().startswith("{") or JSON_ARRAY_START.match(raw.lstrip()):
        mode="JSON"
        event.syntax="JSON"
    elif KV_AT_START.match(raw):
        mode="KV"
        event.syntax="KV"
    elif CSV_AT_START.fullmatch(raw) is not None:
        mode="CSV"
        event.syntax="CSV_UNLABELED_CANDIDATE"
        # A single free-text sentence can contain two commas. Only multi-
        # sample schema consistency can promote headerless CSV to verified.
        event.issues.append("UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION")
    else:
        event.issues.append("NO_SUPPORTED_GRAMMAR")

    try:
        if mode=="KV":
            cells=parse_quoted_kv(parsed,offset)
            # A properly quoted empty value is valid source data, not a
            # syntax failure. Bare key= remains explicitly flagged.
            parsed.issues=[
                issue for issue in parsed.issues
                if not (issue.startswith("KV_EMPTY_VALUE:")
                        and issue.removeprefix("KV_EMPTY_VALUE:") in cells
                        and raw[cells[issue.removeprefix("KV_EMPTY_VALUE:")][1]-2:
                                cells[issue.removeprefix("KV_EMPTY_VALUE:")][2]+1].endswith('=""'))
            ]
            event.vendor_fields={key:value for key,(value,_,_) in cells.items()}
            event.value_spans=[
                _span(raw,key,start,end) for key,(_,start,end) in cells.items()
            ]
            event.primitive_fields=len(cells)
            if not cells:
                event.issues.append("NO_SOURCE_KV_FIELDS")
        elif mode=="CSV":
            cells=parse_csv_spans(parsed,offset)
            # Indexes are syntactic column positions, NOT inferred meanings.
            event.vendor_fields={f"column_{i}":value
                                 for i,(value,_,_) in enumerate(cells)}
            event.value_spans=[
                _span(raw,f"column_{i}",start,end)
                for i,(_,start,end) in enumerate(cells)
            ]
            event.primitive_fields=len(cells)
        elif mode=="JSON":
            decoder=SpanJsonDecoder(raw)
            root=decoder.parse()
            if not isinstance(root,(dict,list)):
                raise ValueError("JSON_ROOT_NOT_COLLECTION")
            if isinstance(root,dict):
                event.vendor_fields=root
            else:
                event.vendor_fields={"$array":root}
            # A parsed JSON object is an exact, typed and nested vendor record.
            # Every null, empty container and array remains in the tree.
            parsed.covered.append((0,len(raw)))
            event.primitive_fields=_leaf_count(root)
            for path,(value,start,end) in decoder.nodes.items():
                if path and not isinstance(value,(dict,list)):
                    event.value_spans.append(_span(raw,path,start,end))
            if event.primitive_fields>len(event.value_spans):
                event.issues.append("JSON_PATH_SPAN_COLLISION_OR_MISSING")
        elif mode:
            raise AssertionError("UNHANDLED_SOURCE_MODE")
    except (ValueError,IndexError,RecursionError,json.JSONDecodeError) as exc:
        event.issues.append("SOURCE_SYNTAX_ERROR:"+str(exc)[:80])
    event.issues.extend(parsed.issues)
    event.covered=list(parsed.covered)
    if not mode:
        # Recover bounded source KEY=VALUE islands from free text without
        # giving the remaining prose a false SOURCE_PARSED certification.
        candidate=recover_kv_islands(raw)
        if candidate.field_count:
            event.vendor_fields["embedded_kv"]=candidate.values
            event.value_spans.extend(
                _span(raw,path,a,b) for path,a,b in candidate.spans
            )
            event.primitive_fields+=candidate.field_count
            event.covered.extend(candidate.covered)
            event.issues.extend(candidate.issues)
    return _close(event)


def _leaf_count(node:Any)->int:
    if isinstance(node,dict):
        return sum(_leaf_count(x) for x in node.values())
    if isinstance(node,list):
        return sum(_leaf_count(x) for x in node)
    return 1


def _close(event:SourceEvent)->SourceEvent:
    n=len(event.raw)
    cursor=0
    intervals=sorted((max(0,a),min(n,b)) for a,b in event.covered if a<b)
    for a,b in intervals:
        if a>cursor:event.unparsed.append((cursor,a))
        cursor=max(cursor,b)
    if cursor<n:event.unparsed.append((cursor,n))
    return event


def assert_source_accounting(event:SourceEvent)->None:
    """Every original byte is either syntax-covered or explicitly residual."""
    raw=event.raw
    coverage=[False]*len(raw)
    for a,b in event.covered+event.unparsed:
        if not (0<=a<=b<=len(raw)):
            raise AssertionError("SOURCE_RANGE_OUT_OF_BOUNDS")
        for i in range(a,b):
            coverage[i]=True
    if not all(coverage):
        raise AssertionError("UNACCOUNTED_OR_DROPPED_SOURCE_BYTE")
    for span in event.value_spans:
        if not (0<=span.start_byte<=span.end_byte<=event.source_bytes):
            raise AssertionError("INVALID_SOURCE_VALUE_BYTE_SPAN")
