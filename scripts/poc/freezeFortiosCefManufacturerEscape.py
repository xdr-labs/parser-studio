#!/usr/bin/env python3
"""Freeze a new Fortinet-authored CEF escaped-value example and its original
FortiGate KV counterpart before candidate inspection. All original bytes and
decoded value expectations stay private; public Git carries SHA metadata.
"""
from pathlib import Path
import hashlib
import html
import json
import os
import re
import urllib.request

PAGE_URL = ("https://docs.fortinet.com/document/fortigate/7.4.8/"
            "fortios-log-message-reference/807724/antivirus-log-support-for-cef")
PAGE_SHA = "d4085e6f7363887a88cff469837828ecaebb6647722dbb5eef8cb82d90987a40"
PRIVATE = Path.home() / ".local/state/parserstudio-fortios-cef-document-escape-20261017"
PUBLIC = Path(__file__).with_name("fortiosCefAuthorEscapeManifest.pinned.json")
def sha(data):return hashlib.sha256(data).hexdigest()
def keep(name,data):
    dest=PRIVATE/name
    if dest.exists():
        if dest.read_bytes()!=data:raise ValueError("Immutable author source drift:"+name)
        return
    fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as f:f.write(data)
def to_byte(raw,charpos):return len(raw[:charpos].encode("utf-8"))
def main():
    PRIVATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(PRIVATE,0o700)
    pagefile=PRIVATE/"fortios-cef-doc-page.html"
    if pagefile.exists():page=pagefile.read_bytes()
    else:
        request=urllib.request.Request(PAGE_URL,headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(request,timeout=30) as response:page=response.read()
    if sha(page)!=PAGE_SHA:
        raise ValueError("Fortinet author document SHA changed; do not repin after scoring")
    keep(pagefile.name,page)
    source=page.decode("utf-8")
    lines=[html.unescape(re.sub(r"<[^>]+>","",t).strip())
           for t in re.findall(r'<p class="CLI_1">(.*?)</p>',source,re.S)]
    rawlogs=[x for x in lines if x.startswith("date=2018-12-27 ") and 'ref="' in x]
    ceflogs=[x for x in lines if x.startswith("Dec 27 11:20:48 ") and 'CEF: 0|Fortinet|' in x]
    if len(rawlogs)!=1 or len(ceflogs)!=1:
        raise ValueError("Author-written raw KV / CEF example pair not uniquely identifiable")
    disk,cef=rawlogs[0],ceflogs[0]
    expected_match=re.search(r'(?:^| )ref="([^"]+)"(?: |$)',disk)
    cef_match=re.search(r'(?:^| )(FTNTFGTref)=([^ ]+)(?: |$)',cef)
    if not expected_match or not cef_match:
        raise ValueError("Manufacturer-documented source and CEF field not both found")
    expected=expected_match.group(1)
    wire=cef_match.group(2)
    if "\\=" not in wire or re.search(r"\\(?![=])",wire) or wire.replace("\\=","=")!=expected:
        raise ValueError("Author-defined wire escaped value does not match disk original")
    # The manufacturer's own adjacent field-mapping table independently
    # names the ref -> FTNTFGTref correspondence AND the literal backslash
    # used to escape equals in this CEF rendition.
    if not re.search(r"FTNTFGTref\s*\(There is \\ added to escape =\s*\)",source):
        raise ValueError("Manufacturer-authored CEF escape meaning unavailable")
    begin=cef_match.start(2);end=cef_match.end(2)
    keybegin=cef_match.start(1);keyend=cef_match.end(1)
    src=cef.encode("utf-8")
    if src[to_byte(cef,begin):to_byte(cef,end)].decode("utf-8")!=wire:
        raise ValueError("Independent byte span could not replay manufacturer CEF literal")
    oracle={
        "manufacturer":"Fortinet",
        "sourceVersionOfDocument":"FortiOS 7.4.8",
        "rawDiskExample":disk,
        "rawDiskSha256":sha(disk.encode("utf-8")),
        "receivedCefExample":cef,
        "receivedCefSha256":sha(src),
        "explicitlyAuthorMappedOriginalField":"ref",
        "explicitlyAuthorMappedCefField":"FTNTFGTref",
        "manufacturerAuthorExpectedDecodedValue":expected,
        "sourceWireLexeme":wire,
        "lexemeStartByte":to_byte(cef,begin),
        "lexemeEndByte":to_byte(cef,end),
        "fieldNameStartByte":to_byte(cef,keybegin),
        "fieldNameEndByte":to_byte(cef,keyend),
        "documentedWireEscape":"BACKSLASH_EQUALS_IN_CEF_EXTENSION",
        "actualSamePhysicalEvent":"NOT_VERIFIED",
        "onDeviceWireCapture":"NOT_VERIFIED",
        "nativeStellar":"NOT_VERIFIED",
    }
    bytes_=(json.dumps(oracle,sort_keys=True,ensure_ascii=False,separators=(",",":"))+"\n").encode()
    keep("fortios-cef-author-escape-oracle.v1.json",bytes_)
    pub={
        "manufacturer":"Fortinet","authorDocumentUrl":PAGE_URL,
        "version":"FortiOS 7.4.8",
        "documentSha256":PAGE_SHA,
        "oracleSha256":sha(bytes_),
        "referenceFields":1,
        "originalDiskExamples":1,"authorCefExamples":1,
        "cefExampleSha256":oracle["receivedCefSha256"],
        "originalDiskExampleSha256":oracle["rawDiskSha256"],
        "sourceFieldName":"ref","wireFieldName":"FTNTFGTref",
        "documentedEscape":"backslash escapes literal equals",
        "manufacturerIndependentExpectedDecoder":"original-disk-field-value+explicit-cef-mapping-note",
        "sourceSpans":"evaluator-derived before candidate scoring",
        "originalBytesInGit":False,
        "copyright":"Fortinet proprietary documentation retained privately for evaluation",
        "limitations":["doc samples not verified same physical wire event",
            "no full event field oracle","source byte intervals evaluator-derived",
            "not all FortiOS firmwares or transport modes"],
    }
    metadata=(json.dumps(pub,sort_keys=True,indent=2)+"\n").encode("utf-8")
    if PUBLIC.exists():
        if PUBLIC.read_bytes()!=metadata:raise ValueError("Previously pinned public manifest drift")
    else:PUBLIC.write_bytes(metadata)
    print(json.dumps({"status":"NEW_MANUFACTURER_CEF_ORACLE_FROZEN_BEFORE_CANDIDATE",
      "manufacturerDocumentSha256":PAGE_SHA,"oracleSha256":sha(bytes_),
      "manufacturerExpectedDecodedFields":1,"sourcePairCount":1,
      "privateDataPrinted":False},sort_keys=True))
if __name__=="__main__":main()
