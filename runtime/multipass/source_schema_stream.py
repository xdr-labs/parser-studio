"""Source-only, bounded declared-field stream grammar shared by W3C and Zeek.

Original physical bytes are never normalized or discarded. Header/directive
lines become explicit metadata partitions; each data row remains a source
event with original lexical UTF-8 byte spans. Compilation is NOT implied.
"""
from __future__ import annotations
import re
from source_parse import SourceEvent, ValueSpan

W3C_FIELD=re.compile(r'^[A-Za-z][A-Za-z0-9_.()/-]{0,127}$')
ZEEK_FIELD=re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,127}$')
ZEEK_TYPE=re.compile(r'^[A-Za-z][A-Za-z0-9_\[\],.-]{0,127}$')
DANGEROUS={'__proto__','constructor','prototype'}
MAX_SCHEMA_LINE=8192
MAX_COLUMNS=128
MAX_ROWS=2000


def _columns(raw:str,delimiter:str):
    """Return decoded value and exact lexical character offsets, or None."""
    cells=[]
    pos=0
    while pos<len(raw):
        if len(cells)>=MAX_COLUMNS:return None
        if delimiter==' ':
            while pos<len(raw) and raw[pos]==' ':pos+=1
        if pos==len(raw):break
        start=pos
        value=[]
        if raw[pos]=='"':
            pos+=1
            found=False
            while pos<len(raw):
                char=raw[pos];pos+=1
                if char=='"':
                    if pos<len(raw) and raw[pos]=='"':
                        value.append('"');pos+=1;continue
                    found=True;break
                if ord(char)<32 or ord(char)==127:return None
                value.append(char)
            if not found or (pos<len(raw) and raw[pos]!=delimiter):return None
        else:
            while pos<len(raw) and raw[pos]!=delimiter:
                char=raw[pos]
                if char=='"' or ord(char)<32 or ord(char)==127:return None
                value.append(char);pos+=1
        cells.append((''.join(value),start,pos))
        if pos==len(raw):break
        if delimiter=='\t':
            pos+=1
            if pos==len(raw):cells.append(('',pos,pos))
        else:
            while pos<len(raw) and raw[pos]==' ':pos+=1
    return cells or None


def _valid_names(names:list[str],family:str)->bool:
    match=W3C_FIELD if family=='W3C' else ZEEK_FIELD
    return bool(1<=len(names)<=MAX_COLUMNS and len(names)==len(set(names))
      and all(match.fullmatch(n) and n not in DANGEROUS for n in names))


def _row_event(line:str,family:str,names:list[str],delimiter:str,types_valid:bool):
    event=SourceEvent(line,syntax='W3C_EFL_DECLARED' if family=='W3C' else 'ZEEK_TSV_DECLARED')
    if not names or not types_valid or len(line.encode('utf8'))>MAX_SCHEMA_LINE:
        event.issues.append('SCHEMA_ROW_WITHOUT_VALID_HEADER')
        event.unparsed=[(0,len(line))]
        return event
    if family=='W3C':
        cells=_columns(line,delimiter)
    else:
        values=line.split('\t')
        cells=[]
        pos=0
        for value in values:
            cells.append((value,pos,pos+len(value)))
            pos+=len(value)+1
    if not cells or len(cells)!=len(names) or any(len(v.encode('utf8'))>2048 for v,_,_ in cells):
        event.issues.append('SCHEMA_ROW_INVALID')
        event.unparsed=[(0,len(line))]
        return event
    event.vendor_fields=dict(zip(names,(value for value,_,_ in cells)))
    event.primitive_fields=len(cells)
    event.covered=[(0,len(line))]
    event.value_spans=[ValueSpan(
        name,len(line[:start].encode('utf8')),len(line[:end].encode('utf8')))
        for name,(_,start,end) in zip(names,cells)]
    # Source extraction is usable; original header-dependent DRAFT compiler is not.
    event.issues.append('SCHEMA_CONTEXT_NOT_IN_DRAFT_COMPILER')
    return event


def parse_declared_schema_stream(raw:str,max_events:int):
    """Return (kind,start_char,end_char,event) partitions or None.

    This grammar is claimed ONLY when a coherent header has been seen. A
    malformed or unsupported stream falls through to the ordinary fail-closed
    parser rather than inferring field names or hiding input.
    """
    if not raw or len(raw.encode('utf8'))>1048576 or '\x00' in raw:
        return None
    rest=raw[1:] if raw.startswith('\ufeff') else raw
    if not rest.startswith('#'):return None
    lines=rest.splitlines(keepends=True)
    if not lines or len(lines)>max_events+512:return None
    marker_w3c=any(line.startswith('#Fields: ') for line in lines[:32])
    marker_zeek=any(line.startswith('#fields\t') for line in lines[:32])
    if marker_w3c==marker_zeek:return None
    family='W3C' if marker_w3c else 'ZEEK'
    parts=[]
    pos=1 if raw.startswith('\ufeff') else 0
    if pos:parts.append(('UTF8_BOM',0,1,None))
    names=[]
    types_valid=False
    delimiter=None
    count=0
    eol=None
    for index,physical in enumerate(lines):
        if physical.endswith('\r\n'):
            line=physical[:-2];trailing='\r\n'
        elif physical.endswith('\n'):
            line=physical[:-1];trailing='\n'
        else:
            line=physical;trailing=''
        if '\r' in line or not line or (trailing and eol not in (None,trailing)):
            return None
        if trailing:eol=trailing
        start=pos
        end=start+len(line)
        if line.startswith('#'):
            if len(line.encode('utf8'))>MAX_SCHEMA_LINE:return None
            if family=='W3C':
                if line.startswith('#Fields: '):
                    found=line[9:].strip().split(' ')
                    if not _valid_names(found,family):return None
                    names=found
                    delimiter=None
                    types_valid=True
                elif not re.fullmatch(r'#[A-Za-z][A-Za-z0-9_-]{0,63}:(?: .*|)',line):
                    return None
            else:
                if line.startswith('#fields\t'):
                    found=line.split('\t')[1:]
                    if len(found)<2 or not _valid_names(found,family):return None
                    names=found
                    types_valid=False
                elif line.startswith('#types\t'):
                    found=line.split('\t')[1:]
                    if len(found)<2 or not all(ZEEK_TYPE.fullmatch(t) for t in found):
                        return None
                    types_valid=bool(names and len(found)==len(names))
                elif not re.fullmatch(r'#[A-Za-z_][A-Za-z0-9_]*(?:[ \t].*|)',line):
                    return None
            parts.append(('SOURCE_METADATA',start,end+len(trailing),None))
        else:
            # Retain every invalid data line as one RAW_ONLY event.
            if family=='W3C' and names and delimiter is None:
                delimiter='\t' if '\t' in line else ' '
            event=_row_event(line,family,names,delimiter or ' ',types_valid)
            parts.append(('EVENT',start,end,event))
            count+=1
            if count>max_events:return None
            if trailing:parts.append(('WHITESPACE',end,end+len(trailing),None))
        pos=end+len(trailing)
    if pos!=len(raw) or count==0:return None
    return parts
