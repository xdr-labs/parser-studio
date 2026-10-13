"""Offline grammar learning RED/GREEN, PBE, anti-overcapture and split gates."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from corpus import entries
from learn import (
    TRAIN_FILE, SPLIT_FILE, RULES_FILE, available_features, canonical, digest,
    evaluate_frozen, fit, guard_matches, observe, partition, predict, read_json,
)
from evaluate import ensure_ranges


def synthetic_train(rows):
    with tempfile.TemporaryDirectory() as dirname:
        file=Path(dirname)/"training.json"
        file.write_bytes(canonical({
            "contract":"parser-studio.poc.isolated-train-only.v1",
            "split_sha256":"synthetic-split",
            "rows":rows,
        }))
        with patch("corpus.load_file",side_effect=AssertionError("FIT_READ_UPSTREAM_GOLD")):
            return fit(file)


def row(fixture,raw,expected):
    return {"fixture":fixture,"raw":raw,"gold":expected}


def kv(family,ip,n):
    return (f'<189>date=2026-10-13 type={family} srcip={ip} '
            f'dstip=198.51.100.{n} srcport={4000+n} dstport=443 '
            f'action=accept devid=FGTEST')


def csv_event(kind,subtype,source,dest,action,n):
    fields=[""]*38
    fields[0]=str(n);fields[3]=kind;fields[4]=subtype
    fields[7]=source;fields[8]=dest
    fields[9]="203.0.113.250";fields[10]="203.0.113.251"
    fields[24]=str(10000+n);fields[25]="443"
    fields[30]=action
    return "Nov 30 16:09:08 PA-220 "+",".join(fields)


class TrainOnlyLearningTests(unittest.TestCase):
    def test_two_competing_grammars_learn_discriminative_type_without_vendor_rules(self):
        rows=[]
        for i in range(1,5):
            for family,fixture in [("flow","sample_a"),("audit","sample_b")]:
                ip=f"192.0.2.{i}" if family=="flow" else f"203.0.113.{i}"
                rows.append(row(fixture,kv(family,ip,i),
                                {"source":{"ip":ip},"destination":{"port":443},
                                 "event":{"action":"accept"}}))
        rules=synthetic_train(rows)
        self.assertEqual(2,len(rules["grammars"]))
        for grammar in rules["grammars"]:
            self.assertEqual("equals",grammar["guard"]["kind"])
            self.assertEqual("kv:type",grammar["guard"]["path"])
        for sample in rows:
            result,matches=predict(sample["raw"],rules["grammars"])
            self.assertEqual(1,len(matches))
            self.assertTrue(matches[0].startswith(sample["fixture"]+":"))
            self.assertEqual(sample["gold"]["source"]["ip"],result.fields["source.ip"])
            self.assertEqual("accept",result.fields["event.action"])
            ensure_ranges(result)
        unknown,matches=predict(kv("rogue","192.0.2.9",9),rules["grammars"])
        self.assertEqual([],matches)
        self.assertEqual({},unknown.fields)

    def test_off_brand_record_reusing_type_must_not_route_without_schema(self):
        training=[]
        for i in range(1,5):
            for family,fixture in (("flow","sample_a"),("audit","sample_b")):
                s=kv(family,f"192.0.2.{i}",i)
                training.append(row(fixture,s,{
                    "source":{"ip":f"192.0.2.{i}"},
                    "event":{"action":"accept"},
                }))
        rules=synthetic_train(training)
        self.assertTrue(any(g["guard"]["path"]=="kv:type"
                            for g in rules["grammars"]))
        # Negative sample copies the trained type literal, but not the
        # surrounding field grammar or manufacturer-specific structure.
        off_brand='<189>type=flow srcip=192.0.2.55 dstip=198.51.100.55'
        blocked,matches=predict(off_brand,rules["grammars"])
        self.assertEqual([],matches)
        self.assertFalse(blocked.fields)
        ensure_ranges(blocked)

    def test_identical_nat_alias_training_cannot_certify_destination_role(self):
        training=[]
        for i in range(1,5):
            src=f"192.0.2.{i}"
            dst=f"198.51.100.{i}"
            raw=csv_event("TRAFFIC","end",src,dst,"allow",i)
            raw=raw.replace("203.0.113.251",dst)
            training.append(row("traffic",raw,{"destination":{"ip":dst}}))
        rules=synthetic_train(training)
        candidate=rules["grammars"][0]["role_rules"]["destination.ip"]
        self.assertEqual("csv[8]",candidate["path"])
        self.assertTrue(candidate["role_assignment_not_uniquely_identified"])
        raw=csv_event("TRAFFIC","end","192.0.2.9","198.51.100.9","allow",9)
        raw=raw.replace("203.0.113.251","198.51.100.9")
        exploratory,_=predict(raw,rules["grammars"])
        strict,_=predict(raw,rules["grammars"],require_unique_train_source=True)
        self.assertEqual("198.51.100.9",exploratory.fields["destination.ip"])
        self.assertNotIn("destination.ip",strict.fields)
        ensure_ranges(strict)

    def test_json_fingerprint_is_only_schema_not_payload_value(self):
        for raw in [
            '{"type":"MVEvents","data":"SECRET_RANDOM_VALUE","attributes":{"src":"192.0.2.2"}}',
            '{"_serverId":"server-token","_eventType":"Changed","sourceAddress":"192.0.2.2"}',
        ]:
            o=observe(raw)
            self.assertEqual("JSON",o.syntax)
            self.assertTrue(available_features(o))
            self.assertTrue(all(x[0]=="exists" for x in available_features(o)))
            ensure_ranges(o.result)

    def test_train_labeled_counterexample_disambiguates_real_ip_from_nat_decoy(self):
        rows=[]
        for i in range(1,5):
            raw=csv_event("TRAFFIC","end",f"192.0.2.{i}",
                          f"198.51.100.{i}","allow",i)
            rows.append(row("traffic",raw,{
                "source":{"ip":f"192.0.2.{i}"},
                "destination":{"ip":f"198.51.100.{i}"},
            }))
        rules=synthetic_train(rows)
        self.assertEqual("csv[8]",rules["grammars"][0]["role_rules"]["destination.ip"]["path"])
        result,_=predict(csv_event("TRAFFIC","end","192.0.2.77",
                                  "198.51.100.77","allow",77),rules["grammars"])
        self.assertEqual("198.51.100.77",result.fields["destination.ip"])
        self.assertNotEqual("203.0.113.251",result.fields["destination.ip"])
        ensure_ranges(result)

    def test_negative_unseen_action_subtype_abstains_instead_of_reusing_type_action(self):
        rows=[]
        for i in range(1,5):
            for kind,subtype,action,output,fixture in [
                ("TRAFFIC","end","allow","flow_terminated","traffic"),
                ("THREAT","url","block-url","url_filtering","threat"),
            ]:
                s=csv_event(kind,subtype,f"192.0.2.{i}",
                            f"198.51.100.{i}",action,i)
                rows.append(row(fixture,s,{
                    "source":{"ip":f"192.0.2.{i}"},
                    "destination":{"ip":f"198.51.100.{i}"},
                    "event":{"action":output},
                }))
        rules=synthetic_train(rows)
        for grammar in rules["grammars"]:
            self.assertEqual("csv[4]",grammar["role_rules"]["event.action"]["path"])
            self.assertEqual("lookup",grammar["role_rules"]["event.action"]["kind"])
        normal,_=predict(csv_event("TRAFFIC","end","192.0.2.6",
                                   "198.51.100.6","allow",6),rules["grammars"])
        self.assertEqual("flow_terminated",normal.fields["event.action"])
        novel,_=predict(csv_event("TRAFFIC","drop","192.0.2.7",
                                  "198.51.100.7","deny",7),rules["grammars"])
        self.assertNotIn("event.action",novel.fields)
        self.assertEqual("192.0.2.7",novel.fields["source.ip"])
        ensure_ranges(novel)

    def test_invalid_typed_ip_and_port_never_emitted(self):
        rows=[row("traffic",kv("flow",f"192.0.2.{i}",i),
                  {"source":{"ip":f"192.0.2.{i}","port":4000+i}})
              for i in range(1,5)]
        rules=synthetic_train(rows)
        bad,_=predict(kv("flow","999.999.0.1",1).replace(
            "srcport=4001","srcport=70000"),rules["grammars"])
        self.assertNotIn("source.ip",bad.fields)
        self.assertNotIn("source.port",bad.fields)
        self.assertGreaterEqual(len(bad.issues),2)
        ensure_ranges(bad)

    def test_malformed_event_cannot_resurrect_partial_prefix_as_verified(self):
        sample='<189>date=2026-10-13 type=flow action=deny msg="unterminated'
        o=observe(sample)
        self.assertIn("KV_QUOTE_UNCLOSED",o.result.issues)
        self.assertGreater(len(o.result.close().unparsed),0)
        self.assertEqual("RAW_ONLY",o.result.status)

    def test_bad_frozen_digest_is_rejected_before_reading_holdout_gold(self):
        fake={"contract":"parser-studio.poc.frozen-trained-grammar.v1",
              "split_sha256":"abc","grammars":[]}
        fake["grammar_sha256"]=digest(fake)
        tampered=copy.deepcopy(fake)
        tampered["grammars"].append({"id":"untrusted"})
        with patch("corpus.load_case",side_effect=AssertionError("LEAKAGE")) as forbidden:
            with self.assertRaisesRegex(ValueError,"GRAMMAR_DIGEST_INVALID"):
                evaluate_frozen(tampered,{"hello":"world"})
            forbidden.assert_not_called()

    @unittest.skipUnless(all((Path(__file__).resolve().parent/".cache"/(e["id"]+".raw")).is_file()
                             and (Path(__file__).resolve().parent/".cache"/(e["id"]+".gold.json")).is_file()
                             for e in entries()),"License-reviewed local pinned corpus absent")
    def test_real_pinned_corpus_has_disjoint_split_frozen_gold_and_negative_vendor_routes(self):
        split=partition()
        self.assertEqual(256,sum(x["records"] for x in split["fixtures"].values()))
        self.assertEqual(8,len(split["fixtures"]))
        for row in split["fixtures"].values():
            train=set(row["train_indices"]);test=set(row["holdout_indices"])
            self.assertFalse(train&test)
            self.assertEqual(row["records"],len(train)+len(test))
            self.assertTrue(set(row["zero_shot_subtype_indices"])<=test)
        rules=fit()
        self.assertEqual(digest(split),rules["split_sha256"])
        self.assertTrue(rules["blind_holdout_gold_unread_in_fit"])
        # Train rules are FROZEN before the evaluation function imports gold.
        result=evaluate_frozen(rules,split)
        self.assertGreater(result["holdout_records"],0)
        self.assertGreater(result["holdout_field_metrics"]["TP"],0)
        self.assertGreater(sum(x["zero_shot_subtype_records"] for x in result["fixtures"]),0)
        self.assertEqual(0,result["wrong_vendor_grammar_activations"])
        self.assertEqual(0,result["multiple_matching_grammars"])
        self.assertFalse(result["native_verified"])
        self.assertFalse(result["stellar_target_verified"])


if __name__=="__main__":
    unittest.main()
