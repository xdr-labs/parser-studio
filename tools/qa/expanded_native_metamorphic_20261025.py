#!/usr/bin/env python3
"""Native security-log source-mutation checks of browser-downloaded draft parsers.

These are source-derived controlled mutants, NOT independent manufacturer holdouts.
"""
import hashlib
import json
import pathlib
import subprocess

ROOT=pathlib.Path("/home/aella/.local/state/parserstudio-expanded-security-20261025")
FOLDER=ROOT/"new-grammar-recovery"
CORPUS={c["id"]:c for c in json.loads((ROOT/"additional-source-manifest.json").read_text())["cases"]}
RUBY="/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin/ruby"
CODE="""require 'json'; k=Class.new; k.class_eval(File.read(ARGV[0]),ARGV[0]);p=k.new;v=JSON.parse(STDIN.read);a=[];v.each{|r|p.parse(r){|t,e|a<<e}};STDOUT.write(JSON.generate(a))"""

def run(case,source):
    rb=FOLDER/case/"draft.rb"
    result=subprocess.run([RUBY,"-e",CODE,str(rb)],input=json.dumps([source]),
        text=True,capture_output=True,timeout=15,check=False)
    if result.returncode:return None,"NONZERO_RUBY_EXIT"
    try:data=json.loads(result.stdout)
    except json.JSONDecodeError:return None,"RUBY_NON_JSON_RESULT"
    if not isinstance(data,list) or len(data)!=1:return None,"WRONG_CALLBACK_COUNT"
    if data[0].get("parser_err_msg"):return None,"NATIVE_PARSER_ERROR"
    return data[0],None

def flattened(value):
    if isinstance(value,dict):return sum((flattened(x) for x in value.values()),[])
    if isinstance(value,list):return sum((flattened(x) for x in value),[])
    if value is None:return []
    return [str(value)]

MUTATIONS={
 "juniper-061":[
  ("src_ip",[("192.0.2.12/52333","203.0.113.12/52333")],["203.0.113.12"]),
  ("dst_ip",[("198.51.100.9/80","192.0.2.99/80")],["192.0.2.99"]),
  ("port_pair",[("52333->198.51.100.9/80","40211->198.51.100.9/443")],["40211","443"])
 ],
 "watchguard-062":[
  ("src_ip",[("192.0.2.12","203.0.113.44")],["203.0.113.44"]),
  ("dst_ip",[("198.51.100.7","192.0.2.21")],["192.0.2.21"]),
  ("decision",[("firewall: deny","firewall: allow"),("action=deny","action=allow")],["allow"])
 ],
 "cisco-068":[
  ("src_endpoint",[("192.0.2.5:50284","198.51.100.5:32011")],["198.51.100.5:32011"]),
  ("dest_endpoint",[("198.51.100.5:80","203.0.113.90:443")],["203.0.113.90:443"]),
  ("rule_number",[("[1:1000000:0]","[1:2000000:1]")],["1:2000000:1"])
 ],
 "cisco-073":[
  ("ip",[("192.0.2.10","203.0.113.30")],["203.0.113.30"]),
  ("domain",[("evil.example.test","other.example.test")],["other.example.test"]),
  ("classification",[("Blocked,Malware","Allowed,Policy")],["Allowed","Policy"])
 ],
 "zeek-077":[
  ("ip",[("192.0.2.10","203.0.113.91")],["203.0.113.91"]),
  ("uid",[("Cw01","Cchange01")],["Cchange01"]),
  ("protocol",[("\ttcp","\tudp")],["udp"])
 ],
 "zeek-078":[
  ("ip",[("192.0.2.11","203.0.113.92")],["203.0.113.92"]),
  ("uid",[("Cw02","Cchange02")],["Cchange02"]),
  ("protocol",[("\tudp","\ttcp")],["tcp"])
 ],
 "microsoft-081":[
  ("ip",[("192.0.2.10","203.0.113.25")],["203.0.113.25"]),
  ("method_uri",[("GET /login","POST /reset")],["POST","/reset"]),
  ("http_status",[("/login 403","/login 200")],["200"])
 ]
}
NEGATIVE={
 "juniper-061":[("separator_removed",[("52333->","52333 ")]),("destination_removed",[("198.51.100.9/80","")])],
 "watchguard-062":[("missing_policy",[("policy=ProxyAction ","")]),("invalid_src_ip",[("192.0.2.12","999.999.999.999")])],
 "cisco-068":[("classification_missing",[("[Classification: Attempted User Privilege Gain] ","")]),("priority_non_numeric",[("[Priority: 1]","[Priority: abc]")])],
 "cisco-073":[("missing_column",[(",Internal Networks","")]),("extra_column",[(",Internal Networks",",Internal Networks,EXTRA")])],
 "zeek-077":[("missing_column",[("\t198.51.100.3","")]),("extra_column",[("\ttcp","\ttcp\tEXTRA")])],
 "zeek-078":[("missing_column",[("\t198.51.100.4","")]),("extra_column",[("\tudp","\tudp\tEXTRA")])],
 "microsoft-081":[("malformed_year",[("2026-10-23","Oct-23")]),("no_method",[(" GET /login"," /login")])]
}
assert len(MUTATIONS)==7 and len(NEGATIVE)==7
rows=[]
for case in sorted(MUTATIONS):
    original=CORPUS[case]["rawSample"]
    baseline,issue=run(case,original)
    assert baseline is not None,(case,issue)
    for name,changes,expected in MUTATIONS[case]:
        sample=original
        for before,after in changes:
            assert before in sample,(case,name,before)
            sample=sample.replace(before,after,1)
        actual,err=run(case,sample)
        values=flattened(actual) if actual else []
        matched=all(x in values for x in expected)
        row={"case":case,"scenario":name,
             "classification":"SYNTHETIC_SOURCE_SUBSTITUTION_NOT_INDEPENDENT",
             "sha256":hashlib.sha256(sample.encode()).hexdigest(),
             "nativeCallback":actual is not None,"valuesMatched":matched,
             "pass":bool(actual is not None and matched)}
        rows.append(row)
        print("SYNTHETIC_CHANGE",case,name,"PASS" if row["pass"] else "FAIL")
    for name,changes in NEGATIVE[case]:
        sample=original
        for before,after in changes:
            assert before in sample,(case,name,before)
            sample=sample.replace(before,after,1)
        actual,err=run(case,sample)
        row={"case":case,"scenario":name,
             "classification":"SYNTHETIC_MALFORMED_NEGATIVE_NOT_INDEPENDENT",
             "sha256":hashlib.sha256(sample.encode()).hexdigest(),
             "failClosed":actual is None,"reason":err if err else "ACCEPTED"}
        rows.append(row)
        print("NEGATIVE",case,name,"REJECTED" if row["failClosed"] else "ACCEPTED")
changed=[r for r in rows if r["classification"].startswith("SYNTHETIC_SOURCE")]
negative=[r for r in rows if r["classification"].startswith("SYNTHETIC_MALFORMED")]
summary={"contract":"parserstudio.expanded-native-metamorphic-qa.v1",
    "testedDistinctRecoveredParsers":7,
    "nativeSourceSubstitutions":{"pass":sum(r["pass"] for r in changed),"total":len(changed)},
    "malformedFailClosed":{"pass":sum(r["failClosed"] for r in negative),"total":len(negative)},
    "notIndependentHoldout":True,"cases":rows}
p=ROOT/"new-grammar-native-mutations.json"
p.write_text(json.dumps(summary,ensure_ascii=False,indent=2))
p.chmod(0o600)
print("FINAL_NATIVE_MUTATIONS",summary["nativeSourceSubstitutions"],summary["malformedFailClosed"])
