"""Train-only, exact-byte human span corrections never silently certify aliases."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from evaluate import ensure_ranges
from learn import canonical, digest, fit, observe, predict
from span_feedback import (
    _byte_range, _source_assertion, repair_frozen_rule_from_confirmed_train_span,
)
from test_learn import csv_event


def sample_train():
    rows=[]
    for i in range(1,5):
        src=f"192.0.2.{i}"
        dst=f"198.51.100.{i}"
        # In training, real destination and a translated/NAT alias are
        # observationally identical, so unique semantics cannot be learned.
        raw=csv_event("TRAFFIC","end",src,dst,"allow",i).replace("203.0.113.251",dst)
        rows.append({"fixture":"traffic","source_index":i-1,"raw":raw,
                     "gold":{"destination":{"ip":dst}}})
    payload={"contract":"parser-studio.poc.isolated-train-only.v1",
             "split_sha256":"synthetic-feedback-only", "rows":rows}
    with tempfile.TemporaryDirectory() as root:
        file=Path(root)/"train.json"
        file.write_bytes(canonical(payload)+b"\n")
        frozen=fit(file)
    return payload,frozen


def selection(raw,path):
    o=observe(raw)
    entry=o.tokens[path]
    start,end=_byte_range(raw,entry[1],entry[2])
    return {"source_path":path,"start_byte":start,"end_byte":end}


class SourceSpanRepairTests(unittest.TestCase):
    def test_explicit_positive_and_negative_approve_one_role_only(self):
        train,frozen=sample_train()
        grammar=frozen["grammars"][0]
        self.assertEqual("csv[8]",grammar["role_rules"]["destination.ip"]["path"])
        self.assertTrue(grammar["role_rules"]["destination.ip"][
            "role_assignment_not_uniquely_identified"])
        sample=train["rows"][0]["raw"]
        before,_=predict(sample,frozen["grammars"],require_unique_train_source=True)
        self.assertNotIn("destination.ip",before.fields)
        positive=selection(sample,"csv[8]")
        negatives=[selection(sample,"csv[10]")]
        repaired=repair_frozen_rule_from_confirmed_train_span(
            frozen,train,"traffic",0,"destination.ip",positive,negatives)
        self.assertEqual(digest({k:v for k,v in repaired.items()
                                 if k!="grammar_sha256"}),repaired["grammar_sha256"])
        after,_=predict(sample,repaired["grammars"],require_unique_train_source=True)
        self.assertEqual("198.51.100.1",after.fields["destination.ip"])
        self.assertTrue(after.spans)
        ensure_ranges(after)
        self.assertTrue(frozen["grammars"][0]["role_rules"]["destination.ip"][
            "role_assignment_not_uniquely_identified"])
        self.assertEqual(set(repaired["grammars"][0]["role_rules"]),
                         set(frozen["grammars"][0]["role_rules"]))
        self.assertFalse(repaired["native_verified"] if
                         "native_verified" in repaired else False)

    def test_unverified_spans_and_nontrain_rows_cannot_update(self):
        train,frozen=sample_train()
        raw=train["rows"][0]["raw"]
        positive=selection(raw,"csv[8]")
        negative=selection(raw,"csv[10]")
        tampered=dict(positive,start_byte=positive["start_byte"]+1)
        def denied(fixture,index,role,pos,neg):
            with self.assertRaises(ValueError):
                repair_frozen_rule_from_confirmed_train_span(
                    frozen,train,fixture,index,role,pos,neg)
        denied("traffic",0,"destination.ip",tampered,[negative])
        denied("traffic",42,"destination.ip",positive,[negative])
        denied("other",0,"destination.ip",positive,[negative])
        denied("traffic",0,"event.action",positive,[negative])
        denied("traffic",0,"destination.ip",positive,[positive])
        denied("traffic",0,"destination.ip",positive,[])
        bad=copy.deepcopy(frozen)
        bad["grammars"][0]["role_rules"]["destination.ip"]["path"]="csv[11]"
        with self.assertRaisesRegex(ValueError,"GRAMMAR_DIGEST"):
            repair_frozen_rule_from_confirmed_train_span(
                bad,train,"traffic",0,"destination.ip",positive,[negative])

    def test_unicode_span_stays_utf8_not_python_character_offsets(self):
        raw='{"message":"한😀","first":"192.0.2.9","second":"192.0.2.9"}'
        o=observe(raw)
        good=selection(raw,"json:second")
        self.assertGreater(good["start_byte"],o.tokens["json:second"][1])
        self.assertEqual("json:second",_source_assertion(raw,o.tokens,good)[0])
        with self.assertRaisesRegex(ValueError,"BYTE_SPAN"):
            _source_assertion(raw,o.tokens,dict(
                good,start_byte=o.tokens["json:second"][1]))
        ensure_ranges(o.result.close())


if __name__=="__main__":
    unittest.main()
