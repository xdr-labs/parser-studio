"""Deterministic Python Multi-Pass conformance from the shared fixture corpus."""
import json
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime"/"multipass"))
from multipass_preview_api import preview
from stellar_dictionary import _POLICY

CASES=json.loads((ROOT/"contracts"/"conformance-cases.v1.json").read_text())
POLICY=json.loads((ROOT/"runtime"/"multipass"/"semantic-policy.v1.json").read_text())

class SharedSemanticConformance(unittest.TestCase):
    def test_canonical_versioned_policy(self):
        self.assertEqual("parser-studio.cross-engine-corpus.v1",CASES["contract"])
        self.assertEqual("independently-authored-synthetic",CASES["origin"])
        self.assertEqual(_POLICY,POLICY)
        self.assertEqual([6,17],POLICY["transportPortProtocols"]["numeric"])

    def test_protocol_evidence_does_not_map_false_official_ports(self):
        for item in CASES["portEvidence"]:
            with self.subTest(id=item["id"]):
                field="proto" if "proto" in item else "proto_name"
                raw=f'{field}={item[field]} srcport=594 dstport=10400 srcip=192.0.2.1'
                result=preview(raw)
                mapped={m["targetField"] for m in result["dictionary"]["mapped"]}
                if item["allow"]:
                    self.assertTrue({"srcport","dstport"}.issubset(mapped),item["id"])
                else:
                    self.assertTrue({"srcport","dstport"}.isdisjoint(mapped),item["id"])
                self.assertEqual("SOURCE_PARSED",result["status"])
                self.assertEqual("594",str(result["fields"]["srcport"]))

    def test_versioned_named_source_aliases_are_cross_engine_and_value_guarded(self):
        self.assertEqual({'source-port':'srcport','destination-port':'dstport'},
                         POLICY['explicitPortSourceAliases'])
        for case in CASES['explicitPortAliasEvidence']:
            with self.subTest(case=case['id']):
                raw=(f'proto={case["proto"]} source-port={case["sourcePort"]} '
                     f'destination-port={case["destinationPort"]} srcip=192.0.2.1')
                result=preview(raw)
                mapped={item['targetField']:item for item in result['dictionary']['mapped']}
                self.assertEqual('SOURCE_PARSED',result['status'])
                self.assertEqual(case['sourcePort'],str(result['fields']['source-port']))
                self.assertEqual(case['destinationPort'],str(result['fields']['destination-port']))
                for key,source in [('srcport','source-port'),('dstport','destination-port')]:
                    if case[key] is None:
                        self.assertNotIn(key,mapped)
                    else:
                        self.assertEqual(source,mapped[key]['sourcePath'])
                        self.assertEqual('EXPLICIT_SOURCE_ALIAS',mapped[key]['mappingClass'])
                        self.assertEqual('integer',mapped[key]['documentedType'])
        nat=preview('proto=1 nat-source-port=594 srcip=192.0.2.1')
        self.assertNotIn('srcport',
            {item['targetField'] for item in nat['dictionary']['mapped']})
        for source in ['nat.source-port','translated.destination-port']:
            nested=preview(f'proto=6 {source}=594 srcip=192.0.2.1')
            self.assertFalse({'srcport','dstport'}.intersection(
                {item['targetField'] for item in nested['dictionary']['mapped']}),source)


    def test_unknown_proto_name_preserved_but_not_official(self):
        for value in ["unknown","https","gre","ospf","icmpv6"]:
            with self.subTest(name=value):
                result=preview(f"proto_name={value} srcip=192.0.2.1")
                mapped={m["targetField"] for m in result["dictionary"]["mapped"]}
                self.assertNotIn("proto_name",mapped)
                self.assertIn("DICTIONARY_PROTOCOL_NAME_UNSUPPORTED:proto_name",
                              result["dictionary"]["issues"])
                self.assertEqual(value,result["fields"]["proto_name"])
        for value in POLICY["officialProtocolNames"]:
            result=preview(f"proto_name={value} srcip=192.0.2.1")
            self.assertIn("proto_name",{m["targetField"] for m in result["dictionary"]["mapped"]})

    def test_preview_package_contains_canonical_policy(self):
        package_script=(ROOT/"ops"/"preview-domain"/"prepare-private-preview.sh").read_text()
        self.assertIn(
            'cp runtime/multipass/semantic-policy.v1.json "$STAGE/multipass/"',
            package_script,
        )
        self.assertEqual("parser-studio.semantic-policy.v1",_POLICY["contract"])

    def test_fixed_seed_protocol_mutations(self):
        seed=0x512042
        illegal=[1,2,47,50,58,89,132,253]
        for index in range(128):
            seed=(seed*1664525+1013904223)&0xffffffff
            proto=illegal[seed%len(illegal)]
            seed=(seed*1664525+1013904223)&0xffffffff
            port=1+seed%65535
            result=preview(f"proto={proto} srcport={port} dstport=443")
            mapped={m["targetField"] for m in result["dictionary"]["mapped"]}
            self.assertNotIn("srcport",mapped,(index,proto))
            self.assertNotIn("dstport",mapped,(index,proto))

if __name__=="__main__":
    unittest.main()
