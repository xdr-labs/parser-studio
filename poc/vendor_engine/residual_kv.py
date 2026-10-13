"""Conservative quoted key/value islands within unresolved free-text messages.

This does not pretend that the surrounding human-readable message is parsed:
recognised key/value tokens retain exact UTF-8 source spans and original names,
while all other characters remain residual. Optional diagnostic-stage only.
"""
from __future__ import annotations

from dataclasses import dataclass,field
import re
from typing import Any

SAFE_ISLAND=re.compile(
    r"(?<![A-Za-z0-9_?/#])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})="
)
DANGEROUS={"__proto__","prototype","constructor"}


@dataclass
class Islands:
    values:dict[str,Any]=field(default_factory=dict)
    spans:list[tuple[str,int,int]]=field(default_factory=list)
    covered:list[tuple[int,int]]=field(default_factory=list)
    issues:list[str]=field(default_factory=list)
    field_count:int=0


def recover_kv_islands(raw:str,minimum_keys:int=2)->Islands:
    if len(raw)>131072 or "\x00" in raw or minimum_keys<2:
        raise ValueError("ISLAND_BOUND_INVALID")
    out=Islands()
    candidates=[]
    cursor=0
    for hit in SAFE_ISLAND.finditer(raw):
        if hit.start()<cursor:continue
        key=hit.group("key")
        if key in DANGEROUS:continue
        pos=hit.end()
        start=pos
        if pos<len(raw) and raw[pos] in ("\"", "'"):
            quote=raw[pos]
            start=pos+1
            pos=start
            chars=[]
            while pos<len(raw):
                if raw[pos]=="\\":
                    if pos+1>=len(raw):
                        break
                    nxt=raw[pos+1]
                    if nxt not in (quote,"\\"):
                        chars.extend(("\\",nxt))
                    else:chars.append(nxt)
                    pos+=2
                elif raw[pos]==quote:
                    break
                else:
                    chars.append(raw[pos])
                    pos+=1
            if pos>=len(raw) or raw[pos]!=quote:
                # Malformed escape/quote: do not extend beyond this token.
                continue
            end=pos
            pos+=1
            if pos<len(raw) and not raw[pos].isspace() and raw[pos] not in ";,)":
                continue
            value="".join(chars)
        else:
            # Terminal punctuation separates tokens, but quoted values can
            # contain it without truncation.
            while pos<len(raw) and not raw[pos].isspace() and raw[pos] not in ";,)":
                pos+=1
            end=pos
            value=raw[start:end]
        # Recognise only syntactically bounded tokens. No search/replace of
        # arbitrary URL parameters, punctuation, or substring matches.
        candidates.append((key,value,hit.start(),pos,start,end))
        cursor=pos
        if len(candidates)>=256:
            out.issues.append("ISLAND_FIELD_LIMIT")
            break
    if len(candidates)<minimum_keys:
        return Islands()
    for key,value,begin,finish,start,end in candidates:
        if key in out.values:
            previous=out.values[key]
            out.values[key]=previous+[value] if isinstance(previous,list) else [previous,value]
            out.issues.append("ISLAND_DUPLICATE_VENDOR_FIELD")
        else:
            out.values[key]=value
        out.spans.append(("embedded_kv."+key,start,end))
        out.covered.append((begin,finish))
        out.field_count+=1
    return out
