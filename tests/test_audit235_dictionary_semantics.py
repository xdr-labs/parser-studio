"""Source-preserving semantic parity for reviewed Multi-Pass dictionary proposals."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime"/"multipass"))
from multipass_preview_api import preview

def targets(raw):
    result=preview(raw)
    return ({item["targetField"] for item in result["dictionary"]["mapped"]},
            result["dictionary"]["issues"],result)

class DictionarySemanticGuard(unittest.TestCase):
    def test_session_close_is_not_an_enforcement_action(self):
        mapped,issues,event=targets(
            "action=close srcip=192.0.2.1 dstip=198.51.100.2 dstport=443")
        self.assertNotIn("action",mapped)
        self.assertIn("DICTIONARY_ACTION_NOT_ENFORCEMENT:action",issues)
        self.assertEqual("close",event["fields"]["action"])
        self.assertEqual("SOURCE_PARSED",event["status"])

    def test_icmp_pseudo_ports_stay_vendor_source(self):
        mapped,issues,event=targets(
            "proto=1 srcport=594 dstport=10400 srcip=192.0.2.1 dstip=198.51.100.2")
        self.assertIn("proto",mapped)
        self.assertNotIn("srcport",mapped)
        self.assertNotIn("dstport",mapped)
        self.assertIn("DICTIONARY_ICMP_HAS_NO_L4_PORT:srcport",issues)
        self.assertIn("DICTIONARY_ICMP_HAS_NO_L4_PORT:dstport",issues)
        self.assertEqual("594",str(event["fields"]["srcport"]))

    def test_positive_control_preserves_enforcement_and_udp(self):
        mapped,issues,_=targets(
            "action=block proto=17 srcport=53215 dstport=443 srcip=192.0.2.1 dstip=198.51.100.2")
        self.assertTrue({"action","proto","srcport","dstport"}.issubset(mapped))
        self.assertEqual([],issues)

    def test_proto_name_icmp_also_rejects_ports(self):
        mapped,issues,event=targets(
            "proto_name=icmp srcport=8 dstport=0 srcip=192.0.2.1")
        self.assertNotIn("srcport",mapped)
        self.assertNotIn("dstport",mapped)
        self.assertIn("DICTIONARY_ICMP_HAS_NO_L4_PORT:srcport",issues)
        self.assertEqual("8",str(event["fields"]["srcport"]))

if __name__=="__main__":
    unittest.main()
