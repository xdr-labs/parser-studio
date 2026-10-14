"""Reproducible comparison for the vendor-agnostic structural parser PoC."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re

from generic_structural_poc import (
    parse_generic_structural,synthesize_recipe,
)
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent

FROZEN_CASES=[
("f5","<131>Sep 19 13:53:34 bigip-4.example ASM:CEF:0|F5|ASM|11.3.0|200021069|Automated client access \"wget\"|5|dvchost=bigip-4.example dvc=172.16.73.34 cs1=topaz4-web4 cs1Label=policy_name act=blocked src=10.4.1.101 spt=52975 dst=10.4.1.200 dpt=80 requestMethod=GET app=HTTP"),
("juniper_rfc5424","<14>1 2012-12-20T17:40:07.758-06:00 tok-srx100 RT_FLOW - RT_FLOW_SESSION_CREATE[junos@2636.1.1.1.2.41 reason=\"unset\" source-address=\"10.140.2.62\" source-port=\"61718\" destination-address=\"10.199.5.255\" destination-port=\"161\" service-name=\"None\" protocol-id=\"17\" policy-name=\"trust_to_trust\"]"),
("zscaler_leef","<4>1 2019-11-21T13:44:37Z ZSCALER NSS - - - LEEF:2.0|Zscaler|NSS|3.6|ALLOW|cat=firewall\tusrName=jane.doe\tsrc=203.0.113.10\tdst=198.51.100.20"),
("sophos_xg","<30>device=\"SFW\" date=2020-05-18 time=14:38:48 timezone=\"CEST\" device_name=\"XG230\" log_type=\"Anti-Spam\" log_component=\"SMTP\" reason=\"Email has been accepted by Device and queued for scanning.\" src_ip=\"\" dst_ip=\"\" protocol=\"TCP\" src_port=0 dst_port=0"),
("netskope_cef","<14>Sep 01 14:39:36 netskopece CEF:0|Netskope|Example Tenant|NULL|application|NULL|Unknown|act=Download appcategory=Cloud Storage browser=Safari dst=192.0.2.20 src=198.51.100.11 suser=julia.moore@example.com"),
("meraki_flow","<134>1 1563246850.048798929 Head_office_Appliance flows allow src=192.168.254.135 dst=192.168.254.7 mac=E8:E8:B7:35:4A:C2 protocol=udp sport=33787 dport=35"),
("watchguard_basic","Jun 17 20:59:55 TXX-PoE firewall: msg_id=\"3000-0148\" Allow 0-SSL-VPN VLAN123 60 tcp 20 63 1.1.1.1 2.2.2.2 33564 8006 offset 10 S 147268851 win 61690 src_user=\"me@Firebox-DB\" (Allow SSLVPN-TEST-00)"),
("juniper_legacy","Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.83.99/40275->192.168.32.1/161 None 192.168.83.99/40275->192.168.32.1/161 None None 17 allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255"),
("meraki_ids","1 1788735305.123456789 MX68-EDGE ids-alerts signature=1:2012034:1 priority=1 timestamp=1788735305.12 direction=ingress protocol=tcp/ip src=185.220.101.5:41200 dst=192.168.128.10:80 message: ET SCAN Suspicious User-Agent"),
("watchguard_proxy","<139>Jan 16 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 (2024-01-19T08:48:15) firewall: msg_id=\"1BFF-000F\" Allow 1-Trusted 0-External tcp 10.0.1.2 175.16.199.1 39398 25 msg=\"SMTP request\" proxy_act=\"SMTP-Outgoing.1\" rcvd_bytes=\"272\" sent_bytes=\"282\" sender=\"tester@testnet.com\" recipients=\"wg@localhost\" (SMTP-proxy-00)"),
]

NEGATIVE_CASES=[
"<131>Sep 19 13:53:34 bigip-4.example ASM:not-cef src=10.0.0.1",
"<14>1 2012-12-20T17:40:07.758-06:00 tok-srx100 RT_FLOW - X[broken",
"LEEF:2.0|Zscaler|NSS|3.6|ALLOW|cat=firewall src=1.1.1.1",
"<134>1 1563246850.048798929 MX68 flows allow src=192.0.2.1 protocol=tcp",
"Jun 17 20:59:55 TXX-PoE firewall: msg_id=\"3000-0148\" Allow Trusted External tcp 192.0.2.1 443",
"Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created without an endpoint tuple",
"ordinary prose with src=192.0.2.1 only one field",
]

PFSENSE=(
"<134>Mar 12 10:04:11 fw01 filterlog: "
"5,,,1000000103,igb0,match,block,in,4,0x0,,63,54321,0,DF,6,tcp,60,"
"203.0.113.10,10.10.5.20,44231,3389,0,S,1234567890,,64240,,"
"mss;sackOK;TS;nop;wscale"
)

ISE=(
"<134>Apr 25 15:23:01 ise-psn-01 CISE_Passed_Authentications "
"0001234567 1 0 2026-04-25 15:23:01.123 +00:00 0001234567 "
"5200 NOTICE Passed-Authentication: Authentication succeeded, "
"ConfigVersionId=12345, Device IP Address=10.10.10.5, "
"DestinationIPAddress=10.20.30.40, DestinationPort=1812, "
"UserName=jdoe@CORP.LOCAL, Protocol=Radius, RequestLatency=15, "
"NetworkDeviceName=core-switch-bldg5, User-Name=jdoe@CORP.LOCAL, "
"NAS-IP-Address=10.10.10.5, NAS-Port=Gi1/0/24, EAP-Key-Name=, "
"cisco-av-pair=service-type=Framed, "
"cisco-av-pair=audit-session-id=0A0A0A050000ABCDE, "
"AcsSessionID=ise-psn-01/123456789/12345, "
"IdentityGroup=Endpoint Identity Groups:Profiled:Workstation"
)
ISE_HOLDOUT=ISE.replace(
    "ConfigVersionId=12345","ConfigVersionId=54321"
).replace(
    "DestinationIPAddress=10.20.30.40",
    "DestinationIPAddress=192.0.2.77"
).replace(
    "UserName=jdoe@CORP.LOCAL","UserName=analyst@EXAMPLE.NET"
)

ISE_EXPECTED={
"ConfigVersionId":"12345",
"Device IP Address":"10.10.10.5",
"DestinationIPAddress":"10.20.30.40",
"DestinationPort":"1812",
"UserName":"jdoe@CORP.LOCAL",
"Protocol":"Radius",
"RequestLatency":"15",
"NetworkDeviceName":"core-switch-bldg5",
"User-Name":"jdoe@CORP.LOCAL",
"NAS-IP-Address":"10.10.10.5",
"NAS-Port":"Gi1/0/24",
"EAP-Key-Name":"",
"cisco-av-pair":["service-type=Framed","audit-session-id=0A0A0A050000ABCDE"],
"AcsSessionID":"ise-psn-01/123456789/12345",
"IdentityGroup":"Endpoint Identity Groups:Profiled:Workstation",
}


def _spans(event):
    return {(s.start_byte,s.end_byte) for s in event.value_spans}


def _metric(tp:int,fp:int,fn:int):
    p=tp/(tp+fp) if tp+fp else 0.0
    r=tp/(tp+fn) if tp+fn else 0.0
    f=2*p*r/(p+r) if p+r else 0.0
    return {"tp":tp,"fp":fp,"fn":fn,
            "precision":round(p,6),"recall":round(r,6),"f1":round(f,6)}


def frozen_oracle_eval():
    totals=Counter();rows=[];exact=0
    for name,raw in FROZEN_CASES:
        oracle=parse_security_multipass(raw)
        candidate=parse_generic_structural(raw)
        assert_source_accounting(candidate)
        expected=_spans(oracle);actual=_spans(candidate)
        tp=len(expected&actual);fp=len(actual-expected);fn=len(expected-actual)
        totals.update(tp=tp,fp=fp,fn=fn)
        is_exact=(fp==0 and fn==0 and candidate.status=="SOURCE_PARSED")
        exact+=is_exact
        rows.append({
            "case":name,"oracle_status":oracle.status,
            "candidate_status":candidate.status,"candidate_syntax":candidate.syntax,
            **_metric(tp,fp,fn),"exact":bool(is_exact),
        })
    return {
        "events":len(FROZEN_CASES),"exact_events":exact,
        "span_metrics":_metric(totals["tp"],totals["fp"],totals["fn"]),
        "cases":rows,
    }


def negative_eval():
    rows=[]
    for raw in NEGATIVE_CASES:
        event=parse_generic_structural(raw)
        rows.append({"status":event.status,"syntax":event.syntax,
                     "false_complete":event.status=="SOURCE_PARSED"})
    return {
        "controls":len(rows),
        "false_complete":sum(x["false_complete"] for x in rows),
        "rows":rows,
    }


def pfsense_eval():
    baseline=parse_security_multipass(PFSENSE)
    candidate=parse_generic_structural(PFSENSE)
    return {
        "baseline_status":baseline.status,
        "candidate_status":candidate.status,
        "span_sets_equal":_spans(baseline)==_spans(candidate),
        "candidate_fields":candidate.primitive_fields,
        "candidate_residual_bytes":candidate.residual_bytes,
        "candidate_syntax":candidate.syntax,
    }


def ise_eval(raw=ISE,expected=ISE_EXPECTED):
    baseline=parse_security_multipass(raw)
    candidate=parse_generic_structural(raw)
    fields=candidate.vendor_fields.get("generic",{}).get("fields",{})
    exact_fields=(fields==expected)
    exact_slices=True
    for span in candidate.value_spans:
        if span.path.startswith("generic.kv."):
            text=raw.encode()[span.start_byte:span.end_byte].decode()
            key=span.path[len("generic.kv."):]
            value=fields[key]
            if isinstance(value,list):
                exact_slices &= text in value
            else:
                exact_slices &= text==value
    return {
        "baseline_status":baseline.status,
        "baseline_fields":baseline.primitive_fields,
        "candidate_status":candidate.status,
        "candidate_fields":candidate.primitive_fields,
        "candidate_residual_bytes":candidate.residual_bytes,
        "expected_kv_exact":exact_fields,
        "kv_source_slices_exact":bool(exact_slices),
        "repeated_cisco_av_pair_occurrences":(
            len(fields.get("cisco-av-pair",[]))
            if isinstance(fields.get("cisco-av-pair"),list) else 0
        ),
    }


def recipe_eval():
    mapping={name:raw for name,raw in FROZEN_CASES}
    pairs=[
        ("meraki",mapping["meraki_flow"],mapping["meraki_ids"]),
        ("watchguard",mapping["watchguard_basic"],mapping["watchguard_proxy"]),
    ]
    rows=[];exact=0
    for name,train,holdout in pairs:
        recipe=synthesize_recipe([train])
        candidate=parse_generic_structural(holdout,recipe)
        oracle=parse_security_multipass(holdout)
        same=_spans(candidate)==_spans(oracle) and candidate.status=="SOURCE_PARSED"
        exact+=same
        rows.append({
            "family":name,"recipe":recipe.__dict__,
            "holdout_exact":bool(same),"holdout_status":candidate.status,
        })
    ise_recipe=synthesize_recipe([ISE])
    ise_candidate=parse_generic_structural(ISE_HOLDOUT,ise_recipe)
    ise_fields=ise_candidate.vendor_fields.get("generic",{}).get("fields",{})
    ise_ok=(
        ise_candidate.status=="SOURCE_PARSED"
        and ise_fields.get("ConfigVersionId")=="54321"
        and ise_fields.get("DestinationIPAddress")=="192.0.2.77"
        and ise_fields.get("UserName")=="analyst@EXAMPLE.NET"
        and len(ise_fields.get("cisco-av-pair",[]))==2
    )
    exact+=ise_ok
    rows.append({
        "family":"cisco_ise","recipe":ise_recipe.__dict__,
        "holdout_exact":bool(ise_ok),"holdout_status":ise_candidate.status,
    })
    return {"holdouts":len(rows),"exact_holdouts":exact,"rows":rows}


def post_tuning_fresh_eval():
    cases=[
        ("meraki_vpnfirewall",
         "1677007711 vpnfirewall 10.0.1.1 accept "
         "src=192.168.1.10 dst=10.10.1.5 protocol=UDP sport=12345 dport=443"),
        ("meraki_ipflow",
         "1677007712 ipflow 10.0.1.1 flow "
         "src=192.168.1.10 dst=10.10.1.5 protocol=TCP sport=23456 dport=80 "
         "translated_src_ip=203.0.113.5 translated_port=54321"),
        ("watchguard_noserial",
         '<142>Apr  4 10:35:35 WatchGuard-Firebox '
         '(2025-04-04T05:05:35) firewall: msg_id="3000-0151" Allow '
         'Firebox Firebox tcp 10.10.10.10 127.0.0.1 57576 705 flags="SR" '
         'duration="0" sent_pkts="1" rcvd_pkts="1" sent_bytes="52" '
         'rcvd_bytes="40" (Any From Firebox-00)'),
        ("sophos_modern",
         'device_name="SFW" timestamp="2024-05-02T11:03:12+0200" '
         'device_model="XGS2100" device_serial_id="X1234" '
         'log_id="010101600001" log_type="Event" log_component="IPSec" '
         'log_subtype="System" severity="Information" con_name="HQ-Branch1" '
         'src_ip="10.171.4.117" dst_ip="10.171.4.118" status="Terminated" '
         'message="IPSec Connection HQ-Branch1 between 10.171.4.117 and '
         '10.171.4.118 terminated."'),
        ("checkpoint_bracket",
         '<134>1 2026-10-14T10:11:12Z gateway CheckPoint 42 - '
         '[action:"Prevent"; resource:"https://example.test/a?q=x=y;z=1"; '
         'group:"ops"; group:"admins"; __nsons:"0"; empty:""]'),
        ("fortigate_kv",'<189>date=2026-10-14 user="Zoë" action=deny'),
    ]
    rows=[];qualified_exact=0;qualified=0;improved=0
    for name,raw in cases:
        baseline=parse_security_multipass(raw)
        candidate=parse_generic_structural(raw)
        expected=_spans(baseline);actual=_spans(candidate)
        tp=len(expected&actual);fp=len(actual-expected);fn=len(expected-actual)
        row={
            "case":name,"baseline_status":baseline.status,
            "candidate_status":candidate.status,"candidate_syntax":candidate.syntax,
            "candidate_residual_bytes":candidate.residual_bytes,
            **_metric(tp,fp,fn),
        }
        if baseline.status=="SOURCE_PARSED":
            qualified+=1
            row["qualified_oracle_exact"]=(fp==0 and fn==0 and candidate.status=="SOURCE_PARSED")
            qualified_exact+=row["qualified_oracle_exact"]
        else:
            # Baseline is not a complete oracle. Confirm only source-backed
            # additive extraction and preserve the incompleteness distinction.
            extra=actual-expected
            row["baseline_incomplete_extra_spans"]=len(extra)
            row["all_extra_spans_nonempty_source_slices"]=all(
                raw.encode()[a:b].decode() for a,b in extra
            )
            row["candidate_improved_complete"]=(
                candidate.status=="SOURCE_PARSED"
                and candidate.residual_bytes==0
                and row["all_extra_spans_nonempty_source_slices"]
            )
            improved+=row["candidate_improved_complete"]
        rows.append(row)
    return {
        "events":len(rows),
        "qualified_complete_oracle_events":qualified,
        "qualified_exact_events":qualified_exact,
        "baseline_incomplete_events":len(rows)-qualified,
        "baseline_incomplete_promoted_with_source_backing":improved,
        "rows":rows,
    }


def residual_template_eval():
    try:
        from residual_miner import miner,aligned_candidate
    except Exception as exc:
        return {"available":False,"reason":type(exc).__name__}
    train=[
        "%ASA-4-106023: Deny udp src outside:192.0.2.1/53 dst inside:198.51.100.1/53",
        "%ASA-4-106023: Deny udp src outside:203.0.113.7/5353 dst inside:10.0.0.4/1053",
    ]
    hold=(
        "%ASA-4-106023: Deny udp src outside:198.18.0.10/161 "
        "dst inside:172.16.1.20/9161"
    )
    generic=parse_generic_structural(hold)
    try:
        model=miner("typed")
    except RuntimeError as exc:
        return {"available":False,"reason":str(exc),
                "generic_status":generic.status}
    for raw in train:model.add_log_message(raw)
    match=model.match(hold,full_search_strategy="always")
    if match is None:
        return {"available":True,"generic_status":generic.status,
                "template_match":False}
    template=match.get_template()
    aligned=aligned_candidate(template,hold,0,hold,match.size)
    expected=[]
    pattern=re.compile(
        r"%ASA-(?P<sev>\d+)-(?P<id>\d+): Deny udp src outside:"
        r"(?P<src>[^/]+)/(?P<spt>\d+) dst inside:"
        r"(?P<dst>[^/]+)/(?P<dpt>\d+)"
    )
    m=pattern.fullmatch(hold)
    assert m is not None
    for name in ("sev","id","src","spt","dst","dpt"):
        a,b=m.span(name)
        expected.append((len(hold[:a].encode()),len(hold[:b].encode())))
    actual=[(x["start_byte"],x["end_byte"]) for x in aligned["captures"]]
    return {
        "available":True,"generic_status":generic.status,
        "template_match":True,"template":template,
        "alignment_status":aligned["status"],
        "expected_variable_spans":len(expected),
        "candidate_variable_spans":len(actual),
        "exact_variable_spans":sorted(expected)==sorted(actual),
        "semantic_names_inferred":False,
        "automatic_apply_allowed":False,
    }


def run():
    result={
        "contract":"parser-studio.poc.generic-structural.v0.1",
        "baseline_commit":"dc73fc83854383de89656f10e3bbb477769a9747",
        "field_semantics_scored":False,
        "vendor_specific_modules_imported_by_candidate":False,
        "frozen_oracle":frozen_oracle_eval(),
        "negative_controls":negative_eval(),
        "pfsense_positional_csv":pfsense_eval(),
        "cisco_ise_comma_kv":ise_eval(),
        "recipe_synthesis":recipe_eval(),
        "post_tuning_fresh_holdout":post_tuning_fresh_eval(),
        "residual_template":residual_template_eval(),
    }
    return result


if __name__=="__main__":
    result=run()
    output=HERE/"generic-structural-poc-summary.json"
    output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True,indent=2))
