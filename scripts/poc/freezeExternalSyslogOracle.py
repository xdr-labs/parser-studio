#!/usr/bin/env python3
"""Independently freeze upstream syslog conformance expectations and byte spans.

This parser reads third-party Go test source, never calls Parser Studio code.
Only explicitly expected upstream field values qualify. Other cases abstain.
"""
import ast
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path.home() / ".local/state/parserstudio-external-syslog-20261017"
PUBLIC = Path(__file__).with_name("externalSyslogOracle.v2.pinned.json")
SOURCE_PINS = Path(__file__).with_name("externalSyslogSources.pinned.json")
GO_VALUE = r'(`[^`]*`|"(?:\\.|[^"\\])*")'
RFC5424_KEYS = ("timestamp","hostname","appname","procid","msgid")
RFC5424_MAP = {"hostname":"hostname","appname":"app_name","procid":"proc_id",
               "msgid":"msg_id","structured_data_raw":"structured_data",
               "message":"message"}
NUMERIC = re.compile(r'^[0-9]{1,3}$')

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def freeze(path:Path, data:bytes) -> None:
    if path.exists():
        if path.read_bytes()!=data:raise RuntimeError("Immutable independent golden changed")
        return
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as out:out.write(data)
def value_of(source:str) -> str:
    if source.startswith(chr(96)):return source[1:-1]
    return ast.literal_eval(source)
def take_go_value(block:str,name:str):
    m=re.search(r'"'+re.escape(name)+r'"\s*:\s*'+GO_VALUE,block,re.S)
    return value_of(m.group(1)) if m else None
def take_number(block:str,name:str):
    m=re.search(r'"'+re.escape(name)+r'"\s*:\s*([0-9]{1,3})\s*,',block)
    return int(m.group(1)) if m else None
def as_span(raw:str,name:str,start:int,end:int, expected:str):
    if raw[start:end]!=expected:
        raise ValueError("Upstream/independent raw span disagreement")
    data=raw.encode('utf8')
    first=len(raw[:start].encode('utf8'));last=len(raw[:end].encode('utf8'))
    if data[first:last].decode('utf8')!=expected:
        raise ValueError("Full original UTF-8 span did not replay")
    return {"name":name,"value":expected,"type":"string",
            "start_byte":first,"end_byte":last}
def expected_timestamp_valid(raw_timestamp:str,block:str)->bool:
    m=re.search(r'"timestamp"\s*:\s*time\.Date\(\s*'
                r'([0-9]+),\s*time\.([A-Za-z]+),\s*([0-9]+),\s*'
                r'([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*'
                r'([0-9]+\*10e[0-9]+|[0-9]+),\s*'
                r'(time\.UTC|tmpTZ\.Location\(\))\s*,?\s*\)',block,re.S)
    if not m:return False
    months=('January','February','March','April','May','June',
            'July','August','September','October','November','December')
    month=months.index(m.group(2))+1 if m.group(2) in months else 0
    if not month:return False
    nanos=m.group(7)
    if '*10e' in nanos:
        coef,exponent=nanos.split('*10e')
        ns=int(coef)*10**(int(exponent)+1)
    else:ns=int(nanos)
    if not 0<=ns<1000000000 or ns%1000!=0:return False
    offset=timezone.utc if m.group(8)=='time.UTC' else timezone(timedelta(hours=-7))
    try:
        upstream=datetime(int(m.group(1)),month,int(m.group(3)),int(m.group(4)),
                          int(m.group(5)),int(m.group(6)),ns//1000,offset)
        actual=datetime.fromisoformat(raw_timestamp.replace('Z','+00:00'))
    except ValueError:return False
    return upstream==actual

def split_full_rfc5424(raw:str,expected:dict)->list:
    pri=re.match(r'^<([0-9]{1,3})>([1-9][0-9]{0,2}) ',raw)
    if not pri or int(pri[1])>191:
        raise ValueError("No independent RFC5424 PRI/version boundary")
    if take_number(expected["block"],"priority")!=int(pri[1]):
        raise ValueError("Upstream expected priority mismatch")
    if take_number(expected["block"],"version")!=int(pri[2]):
        raise ValueError("Upstream expected version mismatch")
    fields=[as_span(raw,"pri",pri.start(1),pri.end(1),pri[1]),
            as_span(raw,"version",pri.start(2),pri.end(2),pri[2])]
    pos=pri.end()
    for key in RFC5424_KEYS:
        end=raw.find(' ',pos)
        if end<0:raise ValueError("Upstream lacks mandatory RFC5424 separator")
        token=raw[pos:end]
        if token!="-":
            upstream=expected.get(RFC5424_MAP.get(key,key))
            if key=='timestamp':
                if not expected_timestamp_valid(token,expected['block']):
                    raise ValueError('Independent Go time.Date does not match original')
                upstream=token
            if upstream is None or token!=upstream:
                raise ValueError("Expected RFC5424 field mismatch")
            fields.append(as_span(raw,key,pos,end,upstream))
        pos=end+1
    sd_start=pos
    if raw[pos:pos+1]=='-':
        pos+=1
    elif raw[pos:pos+1]=='[':
        while pos<len(raw) and raw[pos]=='[':
            pos+=1;in_quotes=False;escaped=False;closed=False
            while pos<len(raw):
                char=raw[pos]
                if escaped:escaped=False;pos+=1;continue
                if char=='\\' and in_quotes:escaped=True;pos+=1;continue
                if char=='"':in_quotes=not in_quotes;pos+=1;continue
                if char==']' and not in_quotes:
                    closed=True;pos+=1;break
                if char in '\r\n':raise ValueError("Unqualified structured-data control")
                pos+=1
            if not closed or in_quotes or escaped:
                raise ValueError("Unqualified structured-data quote boundary")
    else:raise ValueError("No independent SD boundary")
    expected_sd=expected.get('structured_data')
    if expected_sd is None or expected_sd!=raw[sd_start:pos]:
        raise ValueError("Upstream structured-data raw mismatch")
    fields.append(as_span(raw,'structured_data_raw',sd_start,pos,expected_sd))
    if pos<len(raw):
        if raw[pos]!=' ':raise ValueError("No MSG separator")
        pos+=1;msg=raw[pos:]
        if expected.get('message')!=msg:raise ValueError("Upstream expected MSG mismatch")
        if msg:fields.append(as_span(raw,'message',pos,len(raw),msg))
    elif expected.get('message') not in (None,''):
        raise ValueError("Expected MSG missing")
    return fields

def rfc5424_cases(source:str):
    start=source.find('testCases := []struct')
    end=source.find('for _, tc := range testCases',start)
    if start<0 or end<start:raise RuntimeError("Upstream testCase marker changed")
    content=source[start:end]
    blocks=re.findall(r'(?ms)^\t\t\{\s*\n(.*?)^\t\t\},',content)
    result=[]
    for ix,block in enumerate(blocks):
        record={"id":f"jeromer_rfc5424-{ix:03d}","family":"RFC5424",
                "status":"UNSCORABLE","field_triples":[]}
        try:
            inputm=re.search(r'\binput:\s*'+GO_VALUE,block,re.S)
            if inputm is None:raise ValueError("Dynamic upstream input")
            raw=value_of(inputm.group(1))
            raw_bytes=raw.encode('utf8','strict')
            if not raw_bytes or len(raw_bytes)>8192:
                raise ValueError("Unbounded original")
            expected={
                "block":block,
                **{key:take_go_value(block,key) for key in
                   ["hostname","app_name","proc_id","msg_id","structured_data","message"]},
            }
            record['raw']=raw;record['raw_sha256']=sha(raw_bytes)
            record['raw_bytes']=len(raw_bytes)
            triples=split_full_rfc5424(raw,expected)
            record['field_triples']=triples
            record['status']='INDEPENDENT_UPSTREAM_FIELD_TRIPLES'
        except (ValueError,UnicodeError,SyntaxError,OverflowError,TypeError) as exc:
            record['exclusion']=type(exc).__name__
        result.append(record)
    return result

def rfc3164_cases(source:str):
    start=source.index('func TestParserValid(')
    end=source.find('\nfunc ',start+1)
    block=source[start:end if end>=0 else len(source)]
    record={"id":"jeromer_rfc3164-TestParserValid","family":"RFC3164",
            "status":"UNSCORABLE","field_triples":[]}
    try:
        m=re.search(r'\bbuff\s*:=\s*\[\]byte\(\s*'+GO_VALUE,block,re.S)
        if m is None:raise ValueError("Original source not static")
        raw=value_of(m.group(1))
        pat=re.compile(r'^<([0-9]{1,3})>([A-Z][a-z]{2}) +(\d{1,2}) +'
                       r'(\d\d:\d\d:\d\d) +(\S+) +'
                       r'([A-Za-z_][A-Za-z0-9_.-]*): (.*)$')
        match=pat.match(raw)
        if not match or int(match[1])>191:raise ValueError("No unambiguous RFC3164 fields")
        upstream={
            "hostname":take_go_value(block,'hostname'),
            "appname":take_go_value(block,'tag'),
            "message":take_go_value(block,'content'),
        }
        if any(value is None for value in upstream.values()):
            raise ValueError("Upstream expected values incomplete")
        if upstream['hostname']!=match[5] or upstream['appname']!=match[6] or upstream['message']!=match[7]:
            raise ValueError("Independent expected values conflict with raw")
        if take_number(block,'priority')!=int(match[1]):
            raise ValueError("Independent priority disagreement")
        parts=['pri','month','day','time','hostname','appname','message']
        mapping=dict(zip(parts,list(range(1,8))))
        spans=[as_span(raw,key,match.start(mapping[key]),match.end(mapping[key]),match[mapping[key]])
               for key in parts]
        record.update({"raw":raw,"raw_sha256":sha(raw.encode('utf8')),
                       "raw_bytes":len(raw.encode('utf8')),
                       "field_triples":spans,
                       "status":"INDEPENDENT_UPSTREAM_FIELD_TRIPLES"})
    except (ValueError,UnicodeError,SyntaxError,TypeError) as exc:
        record["exclusion"]=type(exc).__name__
    return [record]

def main()->None:
    manifest_bytes=SOURCE_PINS.read_bytes()
    if manifest_bytes!=(ROOT/"sources.pinned.json").read_bytes():
        raise RuntimeError("Independent sources not frozen")
    pins=json.loads(manifest_bytes)
    rows=[]
    for f in pins['files']:
        data=(ROOT/"source"/(f['id']+".go")).read_bytes()
        if sha(data)!=f["source_sha256"] or len(data)!=f["bytes"]:
            raise RuntimeError("Third-party conformance file has changed")
        if f["id"]=='jeromer_rfc5424':rows+=rfc5424_cases(data.decode('utf8'))
        elif f["id"]=='jeromer_rfc3164':rows+=rfc3164_cases(data.decode('utf8'))
    data=(json.dumps(rows,sort_keys=True,ensure_ascii=True,separators=(',',':'))+"\n").encode()
    freeze(ROOT/"golden-source-expected.v2.json",data)
    scored=[r for r in rows if r["status"]=="INDEPENDENT_UPSTREAM_FIELD_TRIPLES"]
    groups={}
    for family in ["RFC3164","RFC5424"]:
        fam=[r for r in rows if r["family"]==family]
        ok=[r for r in fam if r["status"]=="INDEPENDENT_UPSTREAM_FIELD_TRIPLES"]
        groups[family]={"total":len(fam),"scorable":len(ok),"unscorable":len(fam)-len(ok),
                        "source_triples":sum(len(r['field_triples']) for r in ok)}
    result={"schema":"independent-jeromer-conformance-golden-v2",
            "freeze":"BEFORE_CANDIDATE_OR_BASELINE_SCORE",
            "source_pin_sha256":sha(manifest_bytes),
            "oracle_sha256":sha(data),
            "original_events":len(rows),"independent_events":len(scored),
            "source_triples":sum(len(r['field_triples']) for r in scored),
            "unscorable":len(rows)-len(scored),
            "groups":groups,
            "claim_limits":"LIBRARY_UNIT_CONFORMANCE_NOT_AUTHENTIC_DEVICE_OR_NATIVE_STELLAR",
            "negative_handling":"UNSCORABLE_EXCLUDED_NOT_INTERPRETED_AS_FAILURE_OR_SUCCESS"}
    serialized=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
    freeze(ROOT/"oracle-summary.v2.pinned.json",serialized)
    if PUBLIC.exists() and PUBLIC.read_bytes()!=serialized:
        raise RuntimeError("Cannot mutate previously frozen public truth")
    PUBLIC.write_bytes(serialized)
    print(json.dumps(result))
if __name__=="__main__":main()
