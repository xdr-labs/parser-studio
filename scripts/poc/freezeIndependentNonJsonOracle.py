#!/usr/bin/env python3
"""Independently derive publisher-asserted source values and UTF-8 offsets.

Read ONLY immutable upstream authored tests/fixtures and source pin manifests.
Do not execute, import or inspect any Parser Studio candidate for golden creation.
"""
from __future__ import annotations
import ast
import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path.home()/".local/state/parserstudio-independent-nonjson-20261017"
HERE = Path(__file__).resolve().parent
def sha(x:bytes)->str: return hashlib.sha256(x).hexdigest()
def freeze(path:Path,contents:bytes):
    if path.exists():
        if path.read_bytes()!=contents: raise ValueError("Immutable golden conflict")
        return
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as f: f.write(contents)
def span_field(raw:str,name:str,value:str,start:int,kind="string"):
    end=start+len(value)
    assert raw[start:end]==value,(name,"source offset drift")
    start_byte=len(raw[:start].encode("utf8"))
    end_byte=len(raw[:end].encode("utf8"))
    assert raw.encode("utf8")[start_byte:end_byte].decode("utf8")==value
    return {"name":name,"value":value,"value_type":kind,
            "start_byte":start_byte,"end_byte":end_byte}
def unique_find(raw:str,value:str,offset:int=0):
    p=raw.find(value,offset)
    if p<0: raise ValueError("Expected publisher literal absent")
    return p
def upstream_inputs():
    pins=(ROOT/"sources.pinned.json").read_bytes()
    info=json.loads(pins)
    assert info["status"]=="UPSTREAM_SOURCE_FROZEN_BEFORE_GOLDENS_OR_CANDIDATE_SCORE"
    data={}
    for f in info["source_files"]:
        source=(ROOT/"upstream"/f["local_original"]).read_bytes()
        if len(source)!=f["bytes"] or sha(source)!=f["sha256"]:
            raise ValueError("Pinned upstream source drift")
        data[f["local_original"]]=source.decode("utf8")
    return pins,data
def row(id,kind,raw,fields,source,status="SCORABLE_SOURCE_ONLY",flags=()):
    b=raw.encode("utf8") if raw is not None else b""
    if len({(f["name"],f["start_byte"],f["end_byte"]) for f in fields})!=len(fields):
        raise ValueError("Duplicate golden source tuple")
    for f in fields:
        if b[f["start_byte"]:f["end_byte"]].decode("utf8")!=f["value"]:
            raise ValueError("Independent value/byte span mismatch")
    return {"id":id,"family":kind,"publisher":source,"status":status,
            "raw":raw,"raw_bytes":len(b),"raw_sha256":sha(b),
            "fields":fields,"flags":list(flags),"scoring_scope":"ONLY_PUBLISHER_ASSERTED_FIELDS_NOT_ALL_EVENT_FIELDS"}
def java_author_values(source:str,which:str):
    m={}
    for key,rhs in re.findall(which+r'\.put\("([^"]+)",\s*(.*?)(?:\);)',source):
        # Only independently authored literal scalars are used as field/value expected.
        q=rhs.strip()
        if re.fullmatch(r'"[^"]*"',q): v=q[1:-1]
        elif re.fullmatch(r'-?\d+(?:\.\d+)?[FLD]?',q): v=q.rstrip('FLD')
        else: continue
        m[key]=v
    return m
def cef_rows(inp,util):
    headers=java_author_values(util,"EXPECTED_HEADER_VALUES")
    extension=java_author_values(util,"EXPECTED_EXTENSION_VALUES")
    assert set(headers)=={
      "version","deviceVendor","deviceProduct","deviceVersion",
      "deviceEventClassId","name","severity"
    }, "Publisher CEF expected field names changed"
    assert "EXPECTED_EXTENSION_VALUES" in util and "EXPECTED_HEADER_VALUES" in inp["00-TestCEFReader.java"]
    assert "TestCEFUtil.EXPECTED_EXTENSION_VALUES" in inp["01-TestCEFRecordReader.java"]
    name_match=re.search(r'static final String CUSTOM_EXTENSION_FIELD_NAME = "([^"]+)";',util)
    value_match=re.search(
        r'Collections\.singletonMap\(TestCEFUtil\.CUSTOM_EXTENSION_FIELD_NAME,\s*"([^"]*)"\)',
        inp["00-TestCEFReader.java"])
    assert name_match and value_match, "No independent publisher custom extension literal"
    ext_allowed={**extension,name_match.group(1):value_match.group(1)}
    names=list(headers.keys())
    results=[]
    seen_sha=set()
    for filename,source in inp.items():
        if not filename.endswith(".txt"):continue
        raw_lines=source.splitlines()
        for pos,raw in enumerate(raw_lines):
            if not raw.strip():continue
            identity="nifi:"+filename+":"+str(pos)
            if "misformatted-row" in filename or "incorrect-header-field" in filename:
                results.append(row(identity,"cef",raw,[],"apache/nifi","UPSTREAM_INVALID_CONTROL",
                                   ("upstream-error-case","not-a-positive-denominator")))
                continue
            if sha(raw.encode()) in seen_sha:
                results.append(row(identity,"cef",raw,[],"apache/nifi","DUPLICATE_SOURCE_EXCLUDED",
                                   ("identical-upstream-event","not-a-positive-denominator")))
                continue
            seen_sha.add(sha(raw.encode()))
            marker=raw.find("CEF:")
            if marker<0:
                results.append(row(identity,"cef",raw,[],"apache/nifi","UNSCORABLE",
                                   ("no-CEF-marker",)))
                continue
            # Original header tokens must agree with upstream-authored Java expected literals.
            cursor=marker+4
            fields=[]
            good=True
            for i,key in enumerate(names):
                end=raw.find("|",cursor)
                if end<0 or raw[cursor:end]!=headers[key]:
                    good=False;break
                fields.append(span_field(raw,key,headers[key],cursor,
                            "integer" if key=="version" else "string"))
                cursor=end+1
            if not good:
                results.append(row(identity,"cef",raw,[],"apache/nifi","UNSCORABLE",
                                   ("upstream-header-not-equal-to-publisher-assertion",)))
                continue
            # Extensions: author asserts these exact original field NAMES. Values and
            # offsets come directly from immutable fixture wire bytes, not a parser.
            body=raw[cursor:]
            for match in re.finditer(r'(?:(?<=^)|(?<=\s))([A-Za-z][A-Za-z0-9_]*)=',body):
                key=match.group(1)
                if key not in ext_allowed:continue
                valstart=cursor+match.end()
                remaining=raw[valstart:]
                nxt=re.search(r'\s+[A-Za-z][A-Za-z0-9_]*=',remaining)
                valend=valstart+(nxt.start() if nxt else len(remaining))
                value=raw[valstart:valend].rstrip(" \t\r")
                fields.append(span_field(raw,key,value,valstart))
            results.append(row(identity,"cef",raw,fields,"apache/nifi",
                               flags=("CEF-header-from-TestCEFUtil","extension-keys-from-TestCEFUtil",
                                      "publisher-types-not-native-certified")))
    return results
def methods(source:str):
    return {m.group(1):m.group(2) for m in re.finditer(
        r'public void (\w+)\(\)\s*\{(.*?)(?=\n    @Test|\n\})',source,re.S)}
def variables(block:str):
    values={}
    for k,v in re.findall(r'final String (\w+)\s*=\s*("(?:\\.|[^"])*");',block):
        values[k]=ast.literal_eval(v)
    return values
def syslog_rows(inp):
    results=[]
    legacy=methods(inp["04-TestSyslogParser.java"])
    for name in ("testRFC3164SingleDigitDay","testRFC3164DoubleDigitDay",
                 "testRFC3164WithVersion","testRFC5424WithVersion",
                 "testRFC5424WithoutVersion"):
        code=legacy[name]; v=variables(code)
        assert all(f'assertEquals({x}, event.' in code for x in ("pri","stamp","host","body"))
        hasversion="version" in v
        raw="<"+v["pri"]+">"+(v["version"]+" " if hasversion else "")+v["stamp"]+" "+v["host"]+" "+v["body"]
        assert 'final String message = "<" + pri + ">"' in code
        fields=[]
        fields.append(span_field(raw,"pri",v["pri"],1))
        if hasversion:
            assert "assertEquals(version, event.getVersion())" in code
            fields.append(span_field(raw,"version",v["version"],len(v["pri"])+2))
        for key,field in (("stamp","timestamp"),("host","hostname"),("body","message")):
            fields.append(span_field(raw,field,v[key],unique_find(raw,v[key],fields[-1]["end_byte"] if False else 0)))
        results.append(row("nifi-syslog:"+name,"syslog",raw,fields,"apache/nifi",
                           flags=("java-getter-assertions","publisher-nonstandard-variants-are-review-only")))
    strict=methods(inp["05-BaseStrictSyslog5424ParserTest.java"])
    code=strict["testRFC5424WithVersion"];v=variables(code)
    for required in ("pri","version","stamp","host","appName","procId","msgId","body"):
        assert required in v
    assert "assertEquals(appName, fieldMap.get" in code and "assertEquals(msgId, fieldMap.get" in code
    raw="<"+v["pri"]+">"+v["version"]+" "+v["stamp"]+" "+v["host"]+" "+v["appName"]+" "+v["procId"]+" "+v["msgId"]+" - "+v["body"]
    names=[("pri","pri"),("version","version"),("stamp","timestamp"),
           ("host","hostname"),("appName","appname"),("msgId","msgid"),("body","message")]
    fields=[]
    cursor=0
    for src,dest in names:
        p=raw.find(v[src],cursor)
        assert p>=0
        fields.append(span_field(raw,dest,v[src],p))
        cursor=p+len(v[src])
    results.append(row("nifi-syslog:strict-valid","syslog",raw,fields,"apache/nifi",
                       flags=("strict-RFC5424","assertions-authored-upstream")))
    fluent=inp["06-test_in_syslog_001.py"]
    publisher_assertion=re.search(r'record\["message"\]\s*==\s*("(?:\\.|[^"])*")',fluent)
    assert publisher_assertion
    expected=ast.literal_eval(publisher_assertion.group(1))
    for name in ("TCP_RFC5424_MESSAGE","UDS_RFC3164_MESSAGE"):
        matched=re.search(r'^'+name+r'\s*=\s*(b"(?:\\.|[^"])*")',fluent,re.M)
        assert matched
        raw=ast.literal_eval(matched.group(1)).decode("utf8")
        fields=[span_field(raw,"message",expected,raw.index(expected))]
        results.append(row("fluent:"+name,"syslog",raw,fields,"fluent/fluent-bit",
                           flags=("publisher-message-assertion","transport-not-authorized")))
    return results
def main():
    pins,source=upstream_inputs()
    oracle=cef_rows(source,source["02-TestCEFUtil.java"])+syslog_rows(source)
    oracle.append(row("nifi:CSVReader","csv",None,[],"apache/nifi","UNSCORABLE",
                      ("publisher-test-only-checks-properties-no-record-values",)))
    scoring=[r for r in oracle if r["status"]=="SCORABLE_SOURCE_ONLY"]
    assert scoring and all(r["fields"] for r in scoring)
    payload=(json.dumps(oracle,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode("utf8")
    freeze(ROOT/"upstream-authored-original-goldens.v1.json",payload)
    status={}
    for r in oracle: status[r["status"]]=status.get(r["status"],0)+1
    summary={
      "schema":"independent-nonjson-original-goldens-v1",
      "stage":"FROZEN_BEFORE_ANY_BASELINE_OR_CANDIDATE_SCORE",
      "license_scope":"Apache-2.0 private evaluation; no source originals or values committed",
      "source_pin_sha256":sha(pins),
      "oracle_sha256":sha(payload),
      "case_count":len(oracle),
      "scorable_originals":len(scoring),
      "scorable_source_triples":sum(len(r["fields"]) for r in scoring),
      "status_counts":status,
      "source_only_not_native_or_vendor_truth":True,
      "independent_expectation":"Java upstream asserted header fields, CEF extension names and fixture original lexical value; FluentBit asserted message",
      "excluded_from_rates":["UPSTREAM_INVALID_CONTROL","DUPLICATE_SOURCE_EXCLUDED","UNSCORABLE"],
      "subgroup_declarations":sorted(set(r["family"] for r in oracle)),
      "scoring_definitions":"name, publisher-backed original lexical value and UTF8 source byte range; type and normalization separate",
      "no_candidate_scored_before_freeze":True
    }
    encoded=(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode()
    freeze(ROOT/"oracle-summary.v1.pinned.json",encoded)
    public=HERE/"independentNonJsonOracle.v1.pinned.json"
    if public.exists() and public.read_bytes()!=encoded:raise ValueError("Published oracle summary changed")
    public.write_bytes(encoded)
    print(json.dumps({k:summary[k] for k in
      ("stage","case_count","scorable_originals","scorable_source_triples",
       "status_counts","oracle_sha256")}))
if __name__=="__main__":main()
