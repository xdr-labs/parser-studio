"""Independent source-only oracles for pinned commercial security fixtures.

Uses stdlib CSV/shlex and full token regexes, not production source decoders.
Original character ranges come from lexical tokens. Field names and source
containers are preserved; no normalized security role or template labels.
"""
from __future__ import annotations
from dataclasses import dataclass,field
from collections import Counter
import csv,io,re,shlex
from typing import Any

@dataclass
class Reference:
    tree:dict=field(default_factory=dict)
    cells:list=field(default_factory=list)
    composite:list=field(default_factory=list)


def reference_record(raw:str,family:str)->Reference:
    r=Reference()
    def cell(path,value,a,b):r.cells.append((tuple(path),value,len(raw[:a].encode()),len(raw[:b].encode())))
    def store(node,key,value):
        if key in node:
            old=node[key];node[key]=old+[value] if isinstance(old,list) else [old,value]
        else:node[key]=value
    def ietf_header():
        tokens=list(re.finditer(r'\S+',raw))[:6]
        if len(tokens)!=6:raise ValueError('REFERENCE_HEADER_TRUNCATED')
        pri=re.fullmatch(r'<([0-9]{1,3})>([0-9]{1,2})',tokens[0][0])
        if not pri:raise ValueError('REFERENCE_IETF_HEADER')
        hdr={'pri':pri[1],'version':pri[2]}
        for k,i in (('pri',1),('version',2)):cell(('syslog',k),pri[i],*pri.span(i))
        for name,t in zip(('timestamp','hostname','appname','procid','msgid'),tokens[1:]):
            hdr[name]=t[0];cell(('syslog',name),t[0],t.start(),t.end())
        r.tree['syslog']=hdr
        pos=tokens[-1].end()
        while pos<len(raw) and raw[pos]==' ':pos+=1
        return pos
    def structured_data(pos):
        start=pos;data={}
        if raw[pos:pos+1]=='-':pos+=1
        else:
            while raw[pos:pos+1]=='[':
                ident=re.match(r'\[([^\s\[\]="\\]{1,32})',raw[pos:])
                if not ident:raise ValueError('REFERENCE_SD_ID')
                name=ident[1];pos+=ident.end();node={}
                while raw[pos:pos+1]==' ':
                    if raw[pos:].startswith(' ]'):pos+=1;break
                    token=re.match(r' ([^\s\[\]="\\]{1,32})="((?:\\.|[^"\\])*)"',raw[pos:])
                    if not token:raise ValueError('REFERENCE_SD_TOKEN')
                    key=token[1];value=re.sub(r'\\(["\\\]])',lambda m:m[1],token[2])
                    cell(('syslog','structured_data',name,key),value,pos+token.start(2),pos+token.end(2));store(node,key,value)
                    pos+=token.end()
                if raw[pos:pos+1]!=']' or name in data:raise ValueError('REFERENCE_SD_BOUNDARY')
                data[name]=node;pos+=1
        r.tree['syslog']['structured_data']=data
        r.tree['syslog']['structured_data_raw']=raw[start:pos]
        r.composite.append((('syslog','structured_data_raw'),raw[start:pos],len(raw[:start].encode()),len(raw[:pos].encode())))
        return pos
    def kv(pos,node,path):
        while pos<len(raw):
            while pos<len(raw) and raw[pos] in ' \t':pos+=1
            if pos==len(raw):break
            key=re.match(r'([A-Za-z_][A-Za-z0-9_.:-]{0,127})=',raw[pos:])
            if not key:raise ValueError('REFERENCE_KV_KEY')
            name=key[1];pos+=key.end();start=pos
            quote=raw[pos:pos+1]
            if quote in ('"',"'"):
                token=re.match(re.escape(quote)+r'(?:\\.|[^'+re.escape(quote)+r'\\])*'+re.escape(quote),raw[pos:])
                if not token:raise ValueError('REFERENCE_KV_QUOTE_UNCLOSED')
                first=pos+1;last=pos+token.end()-1;pos+=token.end()
            else:
                token=re.match(r'(?:\\[ \t]|[^\s])*',raw[pos:]);first=pos;pos+=token.end();last=pos
            if pos<len(raw) and raw[pos] not in ' \t':raise ValueError('REFERENCE_KV_SUFFIX')
            try:decoded=shlex.split('v='+raw[start:pos],posix=True)
            except ValueError as exc:raise ValueError('REFERENCE_KV_SHLEX') from exc
            if len(decoded)!=1:raise ValueError('REFERENCE_KV_SHLEX_COUNT')
            value=decoded[0].split('=',1)[1];store(node,name,value);cell(path+(name,),value,first,last)
    if family.startswith('checkpoint'):
        pos=ietf_header()
        if re.match(r'\[[ \t]*[A-Za-z_][A-Za-z0-9_.-]*:',raw[pos:]):
            node={};r.tree['body']=node;pos+=1
            pattern=re.compile(r'[ \t]*([A-Za-z_][A-Za-z0-9_.:-]{0,127}):"((?:\\.|[^"\\])*)"[ \t]*(?:;[ \t]*|(?=\]))')
            while token:=pattern.match(raw,pos):
                name=token[1];value=re.sub(r'\\(["\\])',lambda m:m[1],token[2])
                store(node,name,value);cell(('body',name),value,*token.span(2));pos=token.end()
            if raw[pos:].strip(' \t')!=']':raise ValueError('REFERENCE_BRACKET_PAIR_INCOMPLETE')
        else:
            pos=structured_data(pos)
            if raw[pos:].strip():raise ValueError('REFERENCE_SD_TRAILING_MESSAGE')
        return r
    if family.startswith('fortigate'):
        pos=0
        if re.match(r'<\d+>1 ',raw):
            pos=structured_data(ietf_header())
            while raw[pos:pos+1]==' ':pos+=1
            r.tree['body']={};kv(pos,r.tree['body'],('body',))
        else:
            pri=re.match(r'<([0-9]{1,3})>',raw)
            if pri:
                r.tree['syslog']={'pri':pri[1]};cell(('syslog','pri'),pri[1],*pri.span(1));pos=pri.end()
                r.tree['body']={};kv(pos,r.tree['body'],('body',))
            else:kv(pos,r.tree,())
        return r
    if not family.startswith('panos'):raise ValueError('REFERENCE_FAMILY_UNSUPPORTED')
    first_comma=raw.find(',')
    if first_comma<0:raise ValueError('REFERENCE_CSV_MISSING')
    first=re.search(r'[0-9]{1,10}$',raw[:first_comma])
    if not first:raise ValueError('REFERENCE_CSV_SOURCE_START')
    pos=first.start();prefix=raw[:pos];node={}
    if prefix:
        hdr={};r.tree['syslog']=hdr;r.tree['body']=node
        tokens=list(re.finditer(r'\S+',prefix))
        first_token=tokens[0]
        pri=re.match(r'<([0-9]{1,3})>',first_token[0])
        if pri:
            hdr['pri']=pri[1];cell(('syslog','pri'),pri[1],*pri.span(1))
        if pri and first_token[0][pri.end():]=='1':
            if len(tokens)!=3:raise ValueError('REFERENCE_SHORT_IETF_TOKEN_COUNT')
            hdr['version']='1';cell(('syslog','version'),'1',pri.end(),first_token.end())
            for k,t in zip(('timestamp','hostname'),tokens[1:]):hdr[k]=t[0];cell(('syslog',k),t[0],t.start(),t.end())
        else:
            if len(tokens) not in (4,5):raise ValueError('REFERENCE_BSD_TOKEN_COUNT')
            start=pri.end() if pri else 0;hdr['month']=first_token[0][start:];cell(('syslog','month'),hdr['month'],start,first_token.end())
            for k,t in zip(('day','time','hostname','tag'),tokens[1:]):hdr[k]=t[0];cell(('syslog',k),t[0],t.start(),t.end())
        path=('body',)
    else:r.tree=node;path=()
    values=next(csv.reader([raw[pos:]],strict=True))
    for i,value in enumerate(values):
        token=re.match(r'"(?:[^"]|"")*"|[^,]*',raw[pos:])
        if not token:raise ValueError('REFERENCE_CSV_TOKEN')
        text=token[0];quoted=text.startswith('"');start=pos+int(quoted);end=pos+len(text)-int(quoted)
        if (text[1:-1].replace('""','"') if quoted else text)!=value:raise ValueError('REFERENCE_CSV_VALUE')
        key='column_'+str(i);node[key]=value;cell(path+(key,),value,start,end)
        pos+=len(text)
        if i<len(values)-1:
            if raw[pos:pos+1]!=',':raise ValueError('REFERENCE_CSV_SEPARATOR')
            pos+=1
    if pos!=len(raw):raise ValueError('REFERENCE_CSV_TRAILING')
    return r
