"""Regression of ACC-2 isolated auditors and ACC-3/4 read-only experiments.

No private publisher files or customer logs are required by these CI tests.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime"/"multipass"))
sys.path.insert(0,str(ROOT/"scripts"/"verification"))
from field_accuracy_generalization_blind_20261022 import _pointer, _compare
from field_accuracy_nonjson_publisher_20261022 import _published_claims, _extracted_claims
from field_accuracy_publisher_w3c_20261022 import _claim_hits
from lowshot_role_shadow_20261022 import run_lowshot, run_roles
from role_evidence_shadow import infer_directional_roles
from multipass_adjudicator import parse_security_multipass
from multipass_contract import CandidateEvidence, CandidateOccurrence, candidate_from_event

EVIDENCE=CandidateEvidence("research-unit",None,None,"FALLBACK",False,"testing")


class IndependentScorerTest(unittest.TestCase):
    def test_publisher_partial_field_names_do_not_define_source_path(self):
        row={"fields":[{"name":"deviceVendor","start_byte":2,"end_byte":6,"value":"Acme"}]}
        source=SimpleNamespace(occurrences=(
            SimpleNamespace(display_path="body.cef_header.vendor",
                            start_byte=2,end_byte=6,value="Acme"),
        ))
        self.assertEqual(_published_claims(row),_extracted_claims(source))
        # Publisher has not asserted completeness, so this only checks one
        # source value and its exact span, not a field-level precision score.

    def test_partial_duplicate_value_claims_preserve_multiplicity(self):
        row={"fields":[
            {"name":"first","start_byte":2,"end_byte":6,"value":"Acme"},
            {"name":"second","start_byte":2,"end_byte":6,"value":"Acme"},
        ]}
        self.assertEqual(_published_claims(row).total(),2)
        self.assertEqual(_published_claims(row)[(2,6,"Acme")],2)

    def test_sealed_json_oracle_detects_false_complete_name_change(self):
        raw='{"srcip":"192.0.2.1"}'
        candidate=candidate_from_event(parse_security_multipass(raw),EVIDENCE)
        self.assertEqual(len(candidate.occurrences),1)
        wrong=replace(candidate.occurrences[0],
                      display_path="wrong",source_segments=("wrong",))
        bad=replace(candidate,occurrences=(wrong,))
        gold={"fields":[{
            "path":"/srcip","value":"192.0.2.1",
            "value_start_byte":9,"value_end_byte":20,
        }]}
        correct=_compare(candidate,gold)
        self.assertEqual((correct["tp"],correct["fp"],correct["fn"]),(1,0,0))
        incorrect=_compare(bad,gold)
        self.assertEqual((incorrect["tp"],incorrect["fp"],incorrect["fn"]),(0,1,1))
        self.assertTrue(incorrect["false_complete"])

    def test_pointer_escaped_segment_and_array_path(self):
        self.assertEqual(_pointer(("field/name",0,"~test")),"/field~1name/0/~0test")

    def test_w3c_published_oracle_requires_matching_name_value_and_span(self):
        raw="time=12:00:01"
        candidate=candidate_from_event(parse_security_multipass(raw),EVIDENCE)
        expected=[{
            "name":"time","startByte":5,"endByte":13,
            "decodedSha256":sha256(b"12:00:01").hexdigest(),
        }]
        self.assertEqual(_claim_hits(candidate,expected,0),1)
        self.assertEqual(_claim_hits(candidate,expected,1),0)


class ResidualAndRoleTest(unittest.TestCase):
    def test_three_five_ten_sample_learning_never_loses_existing_claims(self):
        result=run_lowshot()
        self.assertEqual([x["train_count"] for x in result["results"]],[3,5,10])
        self.assertTrue(result["training_holdout_disjoint"])
        self.assertEqual([x["source_loss_regressions"] for x in result["results"]],[0,0,0])
        self.assertTrue(all(x["source_value_precision"].startswith("NOT_SCORABLE")
                            for x in result["results"]))

    def test_exact_direction_source_and_destination_provenance(self):
        raw="192.0.2.1:51000 -> 198.51.100.20:443 TCP allow"
        result=infer_directional_roles(raw)
        self.assertEqual(result.state,"EVIDENCED_SUGGESTION_REVIEW_ONLY")
        self.assertEqual(
            {proposal.role for proposal in result.suggestions},
            {"srcip","srcport","dstip","dstport"}
        )
        for entry in result.suggestions:
            self.assertEqual(raw.encode()[entry.start_byte:entry.end_byte].decode(),entry.value)

    def test_role_ambiguous_bad_port_and_embedded_text_abstain(self):
        for text in (
            "192.0.2.1|198.51.100.2|allow",
            "192.0.2.1:99999 -> 198.51.100.2:443",
            'message="192.0.2.1:80 -> 198.51.100.2:443"',
            "999.0.2.1:80 -> 198.51.100.2:443",
        ):
            with self.subTest(source_length=len(text)):
                self.assertEqual(infer_directional_roles(text).state,"ABSTAIN")

    def test_role_output_only_synthetic_no_normalization_mutation(self):
        result=run_roles()
        self.assertEqual(result["cases"],8)
        self.assertEqual(result["ambiguous_or_invalid_abstentions"],6)
        self.assertEqual(result["positive_proposals_review_only"],2)
        self.assertEqual(result["wrong_role_tests"],0)
        self.assertEqual(result["source_span_errors"],0)
        self.assertEqual(result["normalization_changes"],0)


if __name__=="__main__":
    unittest.main()
