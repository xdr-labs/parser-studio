"""No-network, no-vendor-binary security invariants for POC parsing."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from corpus import entries,load_case
from engine import parse_event,SpanJsonDecoder,ParseResult,mine_residual_templates
from evaluate import ensure_ranges,evaluate,CORE_FIELDS,expected_field,score_field


class EngineUnitTests(unittest.TestCase):
    def test_fortinet_profile_and_exact_quoted_value(self):
        sample='<189>date=2026-10-13 type="utm" subtype="webfilter" srcip=192.0.2.10 dstip=198.51.100.9 srcport=2000 dstport=443 action="blocked" msg="A two-word blocked request"'
        r=parse_event(sample)
        self.assertEqual("fortinet:utm:webfilter",r.variant)
        self.assertEqual("192.0.2.10",r.fields["source.ip"])
        self.assertEqual("198.51.100.9",r.fields["destination.ip"])
        self.assertEqual(2000,r.fields["source.port"])
        self.assertEqual("blocked",r.fields["event.action"])
        self.assertEqual("LOCAL_EXTRACTED",r.status)
        self.assertEqual([],r.unparsed)
        ensure_ranges(r)
        self.assertTrue(r.native_verified is False and r.target_verified is False)

    def test_fortinet_can_start_with_devname(self):
        sample='<190>devname="branch-fw" devid="FG100" vd="root" date=2026-10-13 type="event" subtype="connector" level=information'
        r=parse_event(sample)
        self.assertEqual("fortinet:event:connector",r.variant)
        self.assertEqual("STRUCTURED_UNMAPPED",r.status)
        self.assertFalse(r.fields)
        self.assertFalse(r.unparsed)

    def test_invalid_ip_is_never_silently_mapped(self):
        sample='<189>date=2026-10-13 type="traffic" srcip=999.0.0.1 dstip=192.0.2.2 action=deny'
        r=parse_event(sample)
        self.assertNotIn("source.ip",r.fields)
        self.assertEqual("192.0.2.2",r.fields["destination.ip"])
        self.assertEqual("PARTIAL",r.status)
        self.assertTrue(any(x.startswith("INVALID_IP") for x in r.issues))
        ensure_ranges(r)

    def test_kv_duplicate_and_unclosed_quote_are_visible(self):
        one=parse_event('<189>date=2026-10-13 type=event srcip=192.0.2.4 srcip=198.51.100.8')
        self.assertEqual("PARTIAL",one.status)
        self.assertTrue(any(x.startswith("KV_DUPLICATE_KEY") for x in one.issues))
        self.assertEqual("192.0.2.4",one.fields["source.ip"])
        self.assertGreater(sum(b-a for a,b in one.unparsed),0)
        two=parse_event('<189>date=2026-10-13 type=event action=allow msg="open')
        self.assertIn("KV_QUOTE_UNCLOSED",two.issues)
        self.assertEqual("allow",two.fields["event.action"])
        self.assertEqual("PARTIAL",two.status)
        ensure_ranges(one);ensure_ranges(two)

    def test_panos_separates_subtype_from_action(self):
        prefix="Nov 30 16:09:08 PA-220 "
        cells=[""]*40
        for index,value in {0:"1",1:"2018/11/30 16:09:07",3:"TRAFFIC",
            4:"end",7:"192.0.2.8",8:"198.51.100.7",
            24:"50000",25:"443",30:"allow"}.items():
            cells[index]=value
        traffic=parse_event(prefix+",".join(cells))
        self.assertEqual("flow_terminated",traffic.fields["event.action"])
        self.assertEqual("192.0.2.8",traffic.fields["source.ip"])
        self.assertEqual("198.51.100.7",traffic.fields["destination.ip"])
        self.assertEqual("LOCAL_EXTRACTED",traffic.status)
        cells[3]="THREAT";cells[4]="url"
        threat=parse_event(prefix+",".join(cells))
        self.assertEqual("url_filtering",threat.fields["event.action"])
        self.assertEqual("paloalto:threat:url",threat.variant)
        cells[3]="UNKNOWN"
        unknown=parse_event(prefix+",".join(cells))
        self.assertNotIn("source.ip",unknown.fields)
        self.assertNotIn("event.action",unknown.fields)
        self.assertIn("PANOS_VARIANT_UNKNOWN",unknown.issues)

    def test_csv_quote_and_empty_fields_preserved(self):
        prefix="Nov 30 16:09:08 PA-220 "
        cells=[""]*42
        for index,value in {0:"1",3:"THREAT",4:"url",7:"192.0.2.1",
            8:"198.51.100.2",24:"5555",25:"443",30:"block-url",
            31:"GET /x?a=1,b=2"}.items():cells[index]=value
        import csv,io
        buf=io.StringIO();w=csv.writer(buf,lineterminator="");w.writerow(cells)
        r=parse_event(prefix+buf.getvalue())
        self.assertEqual("url_filtering",r.fields["event.action"])
        self.assertEqual("LOCAL_EXTRACTED",r.status)
        self.assertEqual([],r.unparsed)
        self.assertGreaterEqual(r.parsed_source_fields,42)
        ensure_ranges(r)

    def test_nested_json_exact_unicode_byte_spans(self):
        s='{"_serverId":"ABC","_eventType":"Changed","sourceAddress":"192.0.2.1","userName":"한😀","destAddress":"198.51.100.1"}'
        r=parse_event(s)
        self.assertEqual("한😀",r.fields["user.name"])
        self.assertEqual("192.0.2.1",r.fields["source.ip"])
        names=[x for x in r.summary()["capture_provenance"] if x["semantic_role"]=="user.name"]
        self.assertEqual(1,len(names))
        span=names[0]
        data=s.encode("utf8")[span["start_byte"]:span["end_byte"]]
        self.assertEqual('"한😀"'.encode("utf8"),data)
        ensure_ranges(r)

    def test_json_duplicate_key_and_malformed_source_rejected(self):
        for x in ['{"_eventType":"a","_serverId":"b","sourceAddress":"1.1.1.1","sourceAddress":"2.2.2.2"}',
                  '{"_eventType":"a","_serverId":"b","sourceAddress":"1.1.1.1",']:
            r=parse_event(x)
            self.assertEqual("RAW_ONLY",r.status)
            self.assertEqual([(0,len(x))],r.unparsed)
            self.assertFalse(r.native_verified)
            ensure_ranges(r)

    def test_malicious_proto_keys_fail_closed(self):
        r=parse_event('{"__proto__":{},"_eventType":"a","_serverId":"b"}')
        self.assertEqual("RAW_ONLY",r.status)
        self.assertTrue(any("UNSAFE_KEY" in item for item in r.issues))

    def test_unknown_event_never_disappears(self):
        s="unknown|alarm urgent two source=192.0.2.2 and destination=198.51.100.3"
        r=parse_event(s)
        self.assertEqual("RAW_ONLY",r.status)
        self.assertFalse(r.fields)
        self.assertEqual([(0,len(s))],r.unparsed)
        ensure_ranges(r)

    def test_residual_cluster_fingerprint_no_semantic_claim(self):
        first=parse_event("unknown error 123 from 192.0.2.2")
        second=parse_event("unknown error 124 from 192.0.2.7")
        mined=mine_residual_templates([first,second])
        self.assertEqual(1,len(mined))
        self.assertEqual(2,next(iter(mined.values())))
        self.assertNotIn("source.ip",first.fields)

    @unittest.skipUnless(all((Path(__file__).resolve().parent/".cache"/(e["id"]+".raw")).is_file() and (Path(__file__).resolve().parent/".cache"/(e["id"]+".gold.json")).is_file() for e in entries()),"Licensed vendor fixtures are not checked in")
    def test_manifest_pin_and_256_upstream_aligned_records(self):
        total=0
        for item in entries():
            raw,gold=load_case(item)
            self.assertEqual(len(raw),len(gold))
            total+=len(raw)
            for s in raw:
                ensure_ranges(parse_event(s))
        self.assertEqual(256,total)

    @unittest.skipUnless(all((Path(__file__).resolve().parent/".cache"/(e["id"]+".raw")).is_file() and (Path(__file__).resolve().parent/".cache"/(e["id"]+".gold.json")).is_file() for e in entries()),"Licensed vendor fixtures are not checked in")
    def test_actual_gold_high_value_report_is_honest(self):
        r=evaluate()
        self.assertEqual(256,r["total_input_records"])
        self.assertEqual(False,r["native_verified"])
        self.assertEqual(False,r["target_verified"])
        self.assertEqual(8,len(r["fixtures"]))
        self.assertEqual(set(CORE_FIELDS),set(r["roles"]))
        stats=r["overall_field_value_metrics"]
        self.assertEqual(stats["TP"],sum(x["TP"] for x in r["roles"].values()))
        self.assertGreater(stats["FN"],0)  # no magic 100% claim
        self.assertGreater(r["within_fixture_last_half_field_metrics"]["TP"],0)


if __name__=="__main__":
    unittest.main()
