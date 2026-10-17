#!/usr/bin/env python3
"""Freeze only unambiguous original-source fields from third-party C assertions.

This is a PARTIAL source-field oracle. It cannot establish full-event exactness,
native/Stellar validity or false positives for fields unasserted by upstream.
"""
import ast
import hashlib
import json
import os
import re
from pathlib import Path

STATE=Path.home()/".local/state/parserstudio-syslogng-independent-20261017"
PUBLIC=Path(__file__).with_name("syslogngIndependentOracle.pinned.json")
QUOTED=r'"(?:\\.|[^"\\])*"'
TEST=re.compile(r'Test\(syslog_format,\s*([^,\)]+)(?:,[^)]*)?\)\s*\{(.*?)^\}',re.S|re.M)
RAW=re.compile(r'const\s+gchar\s*\*\s*data\s*=\s*((?:\s*'+QUOTED+r')+)\s*;',re.S)
VALUE=re.compile(r'assert_log_message_value_by_name\(\s*msg\s*,\s*('+QUOTED+
                 r')\s*,\s*('+QUOTED+r')\s*\)',re.S)
KEYS={'HOST':'hostname','PROGRAM':'appname','PID':'procid','MSG':'message'}
BOUNDS=8192


def sha(x:bytes)->str:
    return hashlib.sha256(x).hexdigest()


def freeze(path:Path,content:bytes)->None:
    if path.exists():
        if path.read_bytes()!=content:raise RuntimeError("Frozen reference changed")
        return
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as out:out.write(content)


def literal(x:str)->str:
    if re.search(r'\\(?:x[0-9A-Fa-f]{2}|[0-7]{3}|u[0-9]|U[0-9])',x):
        raise ValueError("Ambiguous raw-byte encoding")
    value=ast.literal_eval(x)
    if not isinstance(value,str):raise ValueError("Not a literal string")
    value.encode('utf8','strict')
    return value


def raw_data(block:str)->str:
    m=RAW.search(block)
    if not m:raise ValueError("No independent static original")
    quoted=re.findall(QUOTED,m.group(1))
    if not quoted:raise ValueError("No quoted source tokens")
    return ''.join(literal(q) for q in quoted)


def expected(block:str)->list:
    out=[]
    for m in VALUE.finditer(block):
        key=literal(m.group(1))
        if key not in KEYS:continue
        value=literal(m.group(2))
        if not value:continue
        if any(item['name']==KEYS[key] for item in out):
            raise ValueError("Upstream repeated expected key requires review")
        out.append({'name':KEYS[key],'value':value})
    return out


def original_range(raw:str,item:dict)->dict:
    value=item['value']
    if item['name']=='message':
        if not raw.endswith(value):raise ValueError("Message not raw-exact suffix")
        start=len(raw)-len(value)
    elif item['name']=='procid':
        matches=list(re.finditer(r'\['+re.escape(value)+r'\]',raw))
        if len(matches)!=1:raise ValueError("PID source occurrence ambiguous")
        start=matches[0].start()+1
    else:
        indices=[m.start() for m in re.finditer(re.escape(value),raw)]
        if len(indices)!=1:raise ValueError("Upstream expected value source occurrence ambiguous")
        start=indices[0]
    end=start+len(value)
    if raw[start:end]!=value:raise ValueError("Mismatch in independently expected source slice")
    return {'name':item['name'],'type':'string','value':value,
            'start_byte':len(raw[:start].encode('utf8','strict')),
            'end_byte':len(raw[:end].encode('utf8','strict'))}


def main():
    pin=(STATE/'source.pinned.json').read_bytes()
    meta=json.loads(pin)
    source=(STATE/'upstream-original.c').read_bytes()
    if sha(source)!=meta['original_sha256'] or len(source)!=meta['byte_count']:
        raise RuntimeError("Pinned upstream C test source changed")
    cases=TEST.findall(source.decode('utf8','strict'))
    rows=[];stats={'cases':0,'scorable_partial':0,'unscorable':0,
                   'scoped_field_triples':0,'missing_raw_input':0}
    for i,(name,block) in enumerate(cases):
        stats['cases']+=1
        row={'id':'syslogng-%04d'%i,'source_test_name_sha256':sha(name.encode()),
             'source_suite_sha256':meta['original_sha256']}
        try:
            raw=raw_data(block);orig=raw.encode('utf8','strict')
            if not orig or len(orig)>BOUNDS or b'\0' in orig:
                raise ValueError("Outside safe original byte source contract")
            row.update({'raw':raw,'raw_sha256':sha(orig),'raw_bytes':len(orig)})
            predicted=expected(block)
            if len(predicted)<2:raise ValueError("Partial original expectation too shallow")
            pairs=[original_range(raw,item) for item in predicted]
            if len({x['name'] for x in pairs})!=len(pairs):
                raise ValueError("Repeated source field name")
            for field in pairs:
                if orig[field['start_byte']:field['end_byte']].decode('utf8')!=field['value']:
                    raise ValueError("Original byte reference replay failed")
            row.update({'status':'PARTIAL_UPSTREAM_ASSERTED_SOURCE_TRUTH','fields':pairs})
            stats['scorable_partial']+=1;stats['scoped_field_triples']+=len(pairs)
        except (ValueError,SyntaxError,UnicodeError) as ex:
            row['status']='UNSCORABLE_NO_COMPLETE_INDEPENDENT_SOURCE_ASSERTIONS'
            row['fields']=[];row['reason_code']=type(ex).__name__
            if 'raw' not in row:stats['missing_raw_input']+=1
            stats['unscorable']+=1
        rows.append(row)
    if stats['cases']!=len(rows):raise RuntimeError("Case denominator changed")
    serialized=(json.dumps(rows,separators=(',',':'),ensure_ascii=True)+'\n').encode()
    freeze(STATE/'partial-source-oracle.pinned.json',serialized)
    summary={'schema':'syslogng-external-partial-field-oracle-v1',
             'stage':'FROZEN_BEFORE_ANY_CANDIDATE_SCORING',
             'source_manifest_sha256':sha(pin),'original_sha256':sha(source),
             'private_oracle_sha256':sha(serialized),
             'qualification':'THIRD_REPOSITORY_UPSTREAM_C_ASSERTIONS_PARTIAL_ONLY',
             'unsupported_field_fp':'NOT_SCORABLE_NO_COMPLETE_TREE',
             'event_exactness':'NOT_SCORABLE_NO_COMPLETE_TREE',
             'manufacturer_and_native':'NOT_VERIFIED',
             'stats':stats}
    compact=(json.dumps(summary,indent=2)+'\n').encode()
    freeze(STATE/'partial-summary.pinned.json',compact)
    if PUBLIC.exists() and PUBLIC.read_bytes()!=compact:
        raise RuntimeError("Pinned public summary changed")
    PUBLIC.write_bytes(compact)
    print(json.dumps(summary))


if __name__=="__main__":main()
