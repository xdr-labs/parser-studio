"""Bounded lexical tokenization for explicit security-product profiles.

This helper never auto-detects arbitrary prose. Callers must first prove a
specific product grammar. It preserves source values and UTF-8 spans without
assigning semantic meanings to positional tokens.
"""
from __future__ import annotations
from dataclasses import dataclass
import re
from typing import Any

KEY=re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}=')


@dataclass(frozen=True)
class ProfileToken:
    path:str
    value:str
    start:int
    end:int


def scan_profile_tokens(raw:str,begin:int,namespace:str)->tuple[dict[str,Any],list[ProfileToken]]|None:
    if not (0<=begin<=len(raw)) or len(raw.encode('utf8'))>131072 or '\x00' in raw:
        return None
    tokens=[];kv={};groups=[];spans=[];pos=begin;n=len(raw)
    while pos<n:
        while pos<n and raw[pos].isspace():pos+=1
        if pos==n:break
        if raw[pos]=='(':
            end=raw.find(')',pos+1)
            if end<0:return None
            if end+1<n and not raw[end+1].isspace():return None
            value=raw[pos+1:end];index=len(groups);groups.append(value)
            spans.append(ProfileToken(f'{namespace}.groups.{index}',value,pos+1,end))
            pos=end+1;continue
        match=KEY.match(raw,pos)
        if match is not None:
            key=match.group()[:-1];cursor=match.end();quote=raw[cursor:cursor+1]
            if quote in ('"',"'"):
                start=cursor+1;cursor=start
                while cursor<n:
                    if raw[cursor]=='\\' and cursor+1<n:cursor+=2;continue
                    if raw[cursor]==quote:break
                    cursor+=1
                if cursor>=n:return None
                end=cursor;cursor+=1
                if cursor<n and not raw[cursor].isspace():return None
            else:
                start=cursor
                while cursor<n and not raw[cursor].isspace():cursor+=1
                end=cursor
            value=raw[start:end]
            previous=kv.get(key)
            kv[key]=value if previous is None else (
                previous+[value] if isinstance(previous,list) else [previous,value]
            )
            spans.append(ProfileToken(f'{namespace}.kv.{key}',value,start,end))
            pos=cursor;continue
        start=pos
        while pos<n and not raw[pos].isspace():pos+=1
        value=raw[start:pos];index=len(tokens);tokens.append(value)
        spans.append(ProfileToken(f'{namespace}.tokens.{index}',value,start,pos))
    return {'tokens':tokens,'kv':kv,'groups':groups},spans
