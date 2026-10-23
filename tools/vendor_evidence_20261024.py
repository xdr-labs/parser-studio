#!/usr/bin/env python3
"""Official manufacturer-published log examples: private source and byte-exact oracle.
The examples are publisher documentation excerpts, not authenticated device captures.
"""
import hashlib
import os
import html
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

STATE = Path(os.environ.get("PARSER_STUDIO_EVIDENCE_ROOT", "/home/aella/.local/state/parserstudio-real-evidence-20261024"))
BASE = "https://"
SOURCES = [
 {"id":"fortinet_fortios_traffic", "html":"fortinet_traffic.html", "publisher":"Fortinet", "product":"FortiGate/FortiOS", "doc_release":"7.0.0", "event_family":"traffic/forward", "url":BASE+"docs.fortinet.com/document/fortigate/7.0.0/administration-guide/986892/sample-logs-by-log-type", "needle":"date=2019-05-10 time=11:37:47", "block":"pre", "grammar":"kv"},
 {"id":"fortinet_fortios_system", "html":"fortinet_system.html", "publisher":"Fortinet", "product":"FortiGate/FortiOS", "doc_release":"7.0.3", "event_family":"event/system", "url":BASE+"docs.fortinet.com/document/fortigate/7.0.3/fortios-log-message-reference/463430/event-log-support-for-cef", "needle":"date=2018-12-27 time=11:15:40", "block":"p", "grammar":"kv"},
 {"id":"suricata_eve_alert", "html":"suricata_eve.html", "publisher":"OISF/Suricata", "product":"Suricata EVE JSON", "doc_release":"8.0.0", "event_family":"alert", "url":BASE+"docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html", "needle":"2017-04-07T22:24:37.251547", "block":"pre", "grammar":"json"},
 {"id":"aws_cloudtrail_consolelogin", "html":"aws_console_login.html", "publisher":"AWS", "product":"CloudTrail", "doc_release":"UNKNOWN", "event_family":"ConsoleLogin", "url":BASE+"docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html", "needle":"2014-07-16T15:49:27Z", "block":"code", "grammar":"json"},
]
EXPECTED={
 "fortinet_fortios_traffic":{"date":"2019-05-10","time":"11:37:47","logid":"0000000013","type":"traffic","subtype":"forward","eventtime":"1557513467369913239","srcip":"10.1.100.11","srcport":"58012","dstip":"23.59.154.35","dstport":"80","proto":"6","action":"close","service":"HTTP","transip":"172.16.200.2","app":"HTTP.BROWSER_Firefox"},
 "fortinet_fortios_system":{"date":"2018-12-27","time":"11:15:40","type":"event","subtype":"system","logdesc":"Admin login failed","user":"admin1","srcip":"172.16.200.254","dstip":"172.16.200.1","action":"login","status":"failed","reason":"name_invalid","method":"https"},
 "suricata_eve_alert":{"timestamp":"2017-04-07T22:24:37.251547+0100","event_type":"alert","src_ip":"192.168.2.14","src_port":"50096","dest_ip":"209.53.113.5","dest_port":"80","proto":"TCP","flow_id":"586497171462735","alert.action":"allowed","alert.signature_id":"2018358","alert.severity":"2","alert.category":"Potentially Bad Traffic"},
 "aws_cloudtrail_consolelogin":{"eventVersion":"1.05","userIdentity.type":"IAMUser","eventTime":"2014-07-16T15:49:27Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-2","sourceIPAddress":"192.0.2.110","userIdentity.userName":"John"},
}
class Blocks(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True)
  self.stack=[]
  self.blocks=[]
 def handle_starttag(self,tag,attrs):
  if tag in ("pre","code","p"):
   self.stack.append({"tag":tag,"depth":1,"data":[]})
  for s in self.stack:
   if s["tag"]!=tag or s["depth"]!=1 or self.stack[-1] is not s:
    s["depth"]+=1
 def handle_startendtag(self,tag,attrs): pass
 def handle_data(self,data):
  for s in self.stack:s["data"].append(data)
 def handle_endtag(self,tag):
  for s in list(self.stack):
   s["depth"]-=1
   if s["depth"]==0:
    self.blocks.append((s["tag"],"".join(s["data"])))
    self.stack.remove(s)

def find_source(s):
 page=(STATE/"source-pages"/s["html"]).read_bytes()
 h=Blocks();h.feed(page.decode("utf-8"))
 candidates=[text.strip() for tag,text in h.blocks if tag==s["block"] and s["needle"] in text]
 if not candidates:
  raise ValueError("source code block unavailable: "+s["id"])
 candidates.sort(key=len)
 sample=candidates[0]
 if s["grammar"]=="json":
  try: j=json.loads(sample)
  except Exception as exc: raise ValueError(s["id"]+": invalid JSON extracted: "+str(exc))
  assert isinstance(j,dict)
 assert "\ufffd" not in sample
 return page,sample

def labels(s,raw):
 output=[]
 bs=raw.encode("utf-8")
 for fullkey,expected in EXPECTED[s["id"]].items():
  key=fullkey.split(".")[-1]
  if s["grammar"]=="kv":
   pat=r'(?<![A-Za-z0-9_])'+re.escape(key)+r'=(?P<v>"(?:[^"\\]|\\.)*"|[^\s]+)'
  else:
   pat=r'"'+re.escape(key)+r'"\s*:\s*(?P<v>"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'
  m=re.search(pat,raw)
  if not m: raise AssertionError((s["id"],fullkey,"MISSING SOURCE FIELD"))
  value=m.group("v")
  if value.startswith('"') and value.endswith('"'):
   dec=json.loads(value) if s["grammar"]=="json" else value[1:-1]
   assert dec==expected,(s["id"],fullkey,dec,expected)
   p0,p1=m.span("v")
   if s["grammar"]=="kv":
    p0+=1;p1-=1 # KV engine spans point to decoded content, not quote delimiters
  else:
   assert value==expected,(s["id"],fullkey,value,expected)
   p0,p1=m.span("v")
  start=len(raw[:p0].encode("utf-8"));end=len(raw[:p1].encode("utf-8"))
  lexical=bs[start:end].decode("utf-8")
  assert (json.loads(lexical) if s["grammar"]=="json" and lexical.startswith('"') else lexical)==expected,(s["id"],fullkey,"OFFSET MISMATCH")
  output.append({"path":fullkey,"sourceValue":expected,"startByte":start,"endByte":end,
                 "sourceSpanKind":"JSON_TOKEN" if s["grammar"]=="json" else "KV_DECODED_CONTENT"})
 return output

def main():
 import sys
 if '--acquire' in sys.argv:
  import requests
  for source in SOURCES:
   target=STATE/'source-pages'/source['html']
   target.parent.mkdir(parents=True,exist_ok=True)
   if target.exists():continue
   response=requests.get(source['url'],timeout=30,headers={'User-Agent':'ParserStudio-official-evidence/1.0'})
   response.raise_for_status()
   if source['needle'] not in html.unescape(response.text):raise RuntimeError('Publisher sample changed: '+source['id'])
   with target.open('xb') as f:f.write(response.content)
 (STATE/'raw').mkdir(parents=True,exist_ok=True)
 (STATE/'reports').mkdir(parents=True,exist_ok=True)
 result={"purpose":"manufacturer_official_documented_example_validation","retrieved_utc":datetime.now(timezone.utc).isoformat(),"provenance_limit":"Officially published examples, original device/firmware-generated byte stream NOT independently authenticated","sources":[]}
 for s in SOURCES:
  page,raw=find_source(s)
  rawbytes=raw.encode('utf-8')
  target=STATE/"raw"/(s["id"]+".log")
  if target.exists():
   if target.read_bytes()!=rawbytes:raise RuntimeError("Saved original bytes differ: "+s["id"])
  else:
   with target.open("xb") as f:f.write(rawbytes)
  result["sources"].append({k:s[k] for k in ("id","publisher","product","doc_release","event_family","url","grammar")}|{"source_html_sha256":hashlib.sha256(page).hexdigest(),"raw_excerpt_sha256":hashlib.sha256(rawbytes).hexdigest(),"raw_bytes":len(rawbytes),"record_count":1,"original_device_capture":False,"evidence_class":"OFFICIAL_DOCUMENTED_EXAMPLE","golden":labels(s,raw)})
 (STATE/"reports"/"vendor-source-ledger.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
 for x in result["sources"]:
  print(json.dumps({k:x[k] for k in ('id','publisher','product','event_family','raw_excerpt_sha256','raw_bytes','record_count','evidence_class')}|{'labeled_field_count':len(x['golden'])},ensure_ascii=False))
 print("GOLDEN_FIELD_OCCURRENCES",sum(len(x["golden"]) for x in result["sources"]))
if __name__=="__main__":main()
