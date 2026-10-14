"""Bounded residual recursion for the accuracy-first multi-pass parser.

Only unparsed bytes owned by an already-recognized security envelope body are
eligible. Existing accepted fields/spans are never reparsed or replaced.
Explicit structured sub-records may recover additional native source fields;
unknown wrapper text remains residual, so recovery cannot create false complete
results. Runtime is not ranked, but depth/window/input bounds and cycle checks
are mandatory.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import re
from typing import Callable

from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

MAX_RESIDUAL_DEPTH=4
MAX_RESIDUAL_WINDOWS=64
MAX_WRAPPER_CHARS=96
PRI_START=re.compile(r'<[0-9]{1,3}>')
WRAPPER_CORE=re.compile(r'[A-Za-z0-9_.@/+\-]+(?:[ \t/_@.+\-]+[A-Za-z0-9_.@/+\-]+){0,2}\Z')
STALE_BODY_ISSUES={
    'NO_SUPPORTED_GRAMMAR',
    'UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION',
}


def _wrapper_ok(text:str)->bool:
    stripped=text.strip(' \t\r\n')
    if not stripped:
        return True
    if len(stripped)>MAX_WRAPPER_CHARS or stripped[-1] not in ':=|;':
        return False
    core=stripped[:-1].strip(' \t\r\n')
    return bool(core and WRAPPER_CORE.fullmatch(core))


def _balanced_json_end(text:str,start:int)->int|None:
    stack=[];quoted=False;escape=False
    for pos in range(start,len(text)):
        char=text[pos]
        if quoted:
            if escape:escape=False
            elif char=='\\':escape=True
            elif char=='"':quoted=False
            continue
        if char=='"':quoted=True
        elif char in '{[':
            stack.append(char)
            if len(stack)>64:return None
        elif char in '}]':
            if not stack or {'{':'}','[':']'}[stack.pop()]!=char:return None
            if not stack:return pos+1
    return None


def _candidate_window(text:str,search_from:int=0)->tuple[int,int]|None:
    """Find one explicit structured sub-record after a tiny opaque wrapper."""
    n=len(text)
    for pos in range(search_from,n):
        prefix=text[search_from:pos]
        if not _wrapper_ok(prefix):
            continue
        if text.startswith('@cee: ',pos):
            start=pos+6
            while start<n and text[start] in ' \t':start+=1
            if start<n and text[start]=='{':
                end=_balanced_json_end(text,start)
                if end is not None:return pos,end
        if text.startswith(('CEF:','LEEF:'),pos):
            end=len(text.rstrip(' \t'))
            if end>pos:return pos,end
        if text[pos:pos+1] in ('{','['):
            end=_balanced_json_end(text,pos)
            if end is not None:return pos,end
        if text[pos:pos+1]=='<' and PRI_START.match(text,pos):
            end=len(text.rstrip(' \t'))
            if end>pos:return pos,end
    return None


def _merge_tree(left:dict,right:dict)->dict|None:
    out=deepcopy(left)
    for key,value in right.items():
        if key not in out:
            out[key]=deepcopy(value);continue
        existing=out[key]
        if isinstance(existing,dict) and isinstance(value,dict):
            merged=_merge_tree(existing,value)
            if merged is None:return None
            out[key]=merged
        elif type(existing) is not type(value) or existing!=value:
            return None
    return out


def _shift_span(span:ValueSpan,byte_offset:int,owner:tuple[str,...])->ValueSpan:
    prefix='.'.join(owner)+'.' if owner else ''
    segments=(owner+span.source_segments) if span.source_segments is not None else None
    return ValueSpan(prefix+span.path,byte_offset+span.start_byte,
                     byte_offset+span.end_byte,segments)


def recover_residual_regions(
    event:SourceEvent,
    *,
    parse_once:Callable[[str],SourceEvent],
    max_depth:int=3,
    _depth:int=0,
    _origin_char:int=0,
    _visited:set[tuple[int,int,str]]|None=None,
    _budget:list[int]|None=None,
)->SourceEvent:
    if type(max_depth) is not int or not 0<=max_depth<=MAX_RESIDUAL_DEPTH:
        raise ValueError('MULTIPASS_RESIDUAL_DEPTH_BOUND')
    assert_source_accounting(event)
    if max_depth==0 or _depth>=max_depth or not event.unparsed:
        return deepcopy(event)
    if not isinstance(event.vendor_fields.get('body'),dict):
        return deepcopy(event)

    visited=set() if _visited is None else _visited
    budget=[0] if _budget is None else _budget
    result=deepcopy(event)
    result.unparsed=[]
    body_was_empty=not result.vendor_fields['body']
    recovered=False
    conflict=False
    span_keys={(s.path,s.source_segments,s.start_byte,s.end_byte) for s in result.value_spans}

    for region_start,region_end in event.unparsed:
        segment=event.raw[region_start:region_end]
        cursor=0
        while cursor<len(segment):
            found=_candidate_window(segment,cursor)
            if found is None:break
            local_start,local_end=found
            if local_end<=local_start:break
            window_start=region_start+local_start
            window_end=region_start+local_end
            piece=event.raw[window_start:window_end]
            # A fresh line-start Syslog header is a separate physical event,
            # never a child of the preceding envelope's residual body.
            if (local_start>0 and segment[local_start-1] in '\r\n'
                and piece.startswith('<') and PRI_START.match(piece)):
                cursor=local_end
                continue
            absolute_start=_origin_char+window_start
            absolute_end=_origin_char+window_end
            digest=hashlib.sha256(piece.encode('utf8')).hexdigest()
            cycle=(absolute_start,absolute_end,digest)
            if cycle in visited:
                cursor=local_end;continue
            if budget[0]>=MAX_RESIDUAL_WINDOWS:
                if 'MULTIPASS_RESIDUAL_REGION_LIMIT' not in result.issues:
                    result.issues.append('MULTIPASS_RESIDUAL_REGION_LIMIT')
                break
            visited.add(cycle);budget[0]+=1
            child=parse_once(piece)
            if (_depth+1)<max_depth and child.unparsed:
                child=recover_residual_regions(
                    child,parse_once=parse_once,max_depth=max_depth,
                    _depth=_depth+1,_origin_char=absolute_start,
                    _visited=visited,_budget=budget,
                )
            if child.primitive_fields<=0 or not child.vendor_fields:
                cursor=local_end;continue

            merged=_merge_tree(result.vendor_fields['body'],child.vendor_fields)
            if merged is None:
                conflict=True;cursor=local_end;continue

            byte_offset=len(event.raw[:window_start].encode('utf8'))
            shifted=[]
            overlap=False
            for span in child.value_spans:
                item=_shift_span(span,byte_offset,('body',))
                # Residual passes may never overwrite or reinterpret accepted bytes.
                if any(max(item.start_byte,old.start_byte)<min(item.end_byte,old.end_byte)
                       and (item.path,item.source_segments,item.start_byte,item.end_byte)
                           not in span_keys
                       for old in result.value_spans):
                    overlap=True;break
                shifted.append(item)
            if overlap:
                conflict=True;cursor=local_end;continue

            result.vendor_fields['body']=merged
            for item in shifted:
                key=(item.path,item.source_segments,item.start_byte,item.end_byte)
                if key not in span_keys:
                    span_keys.add(key);result.value_spans.append(item)
            result.primitive_fields=len(result.value_spans)
            result.covered.extend((window_start+a,window_start+b) for a,b in child.covered)
            for issue in child.issues:
                if issue not in result.issues:result.issues.append(issue)
            recovered=True
            cursor=local_end

    if conflict and 'MULTIPASS_RESIDUAL_CONFLICT' not in result.issues:
        result.issues.append('MULTIPASS_RESIDUAL_CONFLICT')
    if recovered:
        result.syntax=event.syntax+'+RESIDUAL'
        if body_was_empty:
            result.issues=[
                issue for issue in result.issues
                if issue not in STALE_BODY_ISSUES and
                   not issue.startswith('SOURCE_SYNTAX_ERROR:CSV_')
            ]
    result.value_spans.sort(key=lambda s:(s.start_byte,s.end_byte,s.path))
    result.unparsed=[]
    result=_close(result)
    assert_source_accounting(result)
    return result
