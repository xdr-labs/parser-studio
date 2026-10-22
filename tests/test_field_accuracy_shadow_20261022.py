"""Source, oracle, and shadow-adjudication regressions (no live engine switch)."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "multipass"))
sys.path.insert(0, str(ROOT / "scripts" / "verification"))
from accuracy_shadow import audit_candidate, choose_shadow, score_candidate
from field_accuracy_shadow_poc import FIXTURE, run, summarize, validate_fixture
from field_accuracy_publisher_w3c_20261022 import (
    _validate_publisher, PUBLISHER_PIN_SHA256,
)
from field_accuracy_generalization_blind_20261022 import (
    _pointer, _compare as compare_frozen_json, _verified_oracle,
)
from field_accuracy_nonjson_publisher_20261022 import validate_oracle as validate_nonjson
from multipass_contract import CandidateEvidence, CandidateOccurrence, candidate_from_event
from multipass_adjudicator import parse_security_multipass

EVIDENCE = CandidateEvidence(
    "shadow-unit", "offline", None, "HEURISTIC_RESIDUAL", False, "20261022"
)


def snapshot(raw: str):
    return candidate_from_event(parse_security_multipass(raw), EVIDENCE)


class FieldAccuracyShadowTest(unittest.TestCase):
    def test_pinned_synthetic_oracle_is_explicitly_not_vendor_independent(self):
        doc, sha = validate_fixture(FIXTURE)
        self.assertEqual(len(sha), 64)
        self.assertIn("NOT_INDEPENDENT", doc["provenance"])
        self.assertEqual(len(doc["cases"]), 7)
        report = run(FIXTURE)
        self.assertEqual(report["scorable_cases"], 6)
        self.assertEqual(report["unscorable_or_error_cases"], 1)
        self.assertEqual(report["product_single_event_baseline"]["tp"], 26)
        self.assertEqual(report["product_single_event_baseline"]["fp"], 0)
        self.assertEqual(report["same_pool_mdl_proxy_shadow"]["tp"], 26)
        self.assertFalse(report["holdout_independent_vendor_oracle"])
        self.assertFalse(report["runtime_or_export_modified"])
        self.assertIsNone(report["per_family"]["UNKNOWN"]["product"]["f1"])

    def test_oracle_tampered_byte_claim_fails_before_scoring(self):
        data = json.loads(FIXTURE.read_text())
        data["cases"][0]["fields"][0]["startByte"] += 1
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "wrong.json"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "ORACLE_LEXEME_MISMATCH"):
                validate_fixture(path)

    def test_oracle_false_completeness_does_not_hide_unscorable(self):
        data = json.loads(FIXTURE.read_text())
        data["cases"][-1]["fields"].append(data["cases"][0]["fields"][0])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "wrong.json"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "UNSCORABLE"):
                validate_fixture(path)

    def test_json_escape_uses_decoded_value_without_false_raw_mismatch(self):
        raw = '{"src":"192.0.2.1","msg":"hello \\uD55C"}'
        candidate = snapshot(raw)
        audit = audit_candidate(raw, candidate, candidate)
        self.assertTrue(audit.valid, audit.errors)
        self.assertEqual(audit.json_decoded_matches, 2)
        self.assertEqual(audit.decoding_unverified, 0)

    def test_utf8_boundary_split_is_rejected(self):
        raw = '<134>1 2026-10-19T09:15:22Z fw01 app - evt - 접근 차단'
        candidate = snapshot(raw)
        text_span = next(o for o in candidate.occurrences if o.display_path == "body.message")
        broken = replace(text_span, start_byte=text_span.start_byte + 1)
        changed = replace(candidate, occurrences=tuple(
            broken if o is text_span else o for o in candidate.occurrences
        ))
        audit = audit_candidate(raw, changed)
        self.assertFalse(audit.valid)
        self.assertIn("FIELD_UTF8_BOUNDARY_INVALID", audit.errors)

    def test_schema_framing_protection_prevents_false_complete(self):
        raw = "src=192.0.2.1 action=deny"
        original = snapshot(raw)
        protected = replace(
            original, completeness="PARTIAL",
            issues=("SCHEMA_CONTEXT_NOT_IN_DRAFT_COMPILER",),
        )
        result = audit_candidate(raw, original, protected)
        self.assertFalse(result.valid)
        self.assertIn("PROTECTED_SOURCE_ISSUES_DROPPED", result.errors)
        self.assertIn("PROTECTED_PARTIAL_FALSE_COMPLETE", result.errors)
        self.assertFalse(score_candidate(raw, original, protected).valid)
        self.assertTrue(audit_candidate(raw, protected, protected).valid)

    def test_complete_baseline_status_remains_immutable(self):
        raw = "src=192.0.2.1 action=deny"
        original = snapshot(raw)
        downgraded = replace(original, completeness="PARTIAL")
        self.assertIn(
            "COMPLETE_BASELINE_DOWNGRADED",
            audit_candidate(raw, downgraded, original).errors,
        )

    def test_original_source_hash_identity_fail_closed(self):
        raw = "src=192.0.2.1 action=deny"
        candidate = snapshot(raw)
        bad = replace(candidate, raw_sha256="0" * 64)
        self.assertIn("SOURCE_IDENTITY_MISMATCH", audit_candidate(raw, bad).errors)

    def test_previous_fields_cannot_be_dropped(self):
        raw = "src=192.0.2.1 action=deny"
        candidate = snapshot(raw)
        modified = replace(candidate, occurrences=candidate.occurrences[:-1])
        result = audit_candidate(raw, modified, candidate)
        self.assertFalse(result.valid)
        self.assertIn("BASELINE_CLAIMS_LOST", result.errors)
        self.assertIn("COMPLETE_BASELINE_REINTERPRETED", result.errors)

    def test_incompatible_overlap_is_rejected(self):
        raw = "src=192.0.2.1 action=deny"
        candidate = snapshot(raw)
        first = candidate.occurrences[0]
        impostor = CandidateOccurrence(
            "impostor", None, 0, "92.0", "str",
            first.start_byte + 1, first.start_byte + 5
        )
        bad = replace(candidate, occurrences=candidate.occurrences + (impostor,))
        self.assertIn("INCOMPATIBLE_FIELD_SPAN_OVERLAP", audit_candidate(raw, bad).errors)

    def test_ancestor_span_can_overlap_when_nested_by_schema(self):
        raw = '{"root":{"name":"alpha"}}'
        candidate = snapshot(raw)
        child = candidate.occurrences[0]
        parent = CandidateOccurrence(
            "root", ("root",), 0, {"name": "alpha"}, "dict",
            8, len(raw.encode()) - 1,
        )
        nested = replace(
            child, display_path="root.name", source_segments=("root", "name")
        )
        candidate = replace(candidate, occurrences=(parent, nested))
        result = audit_candidate(raw, candidate)
        self.assertNotIn("INCOMPATIBLE_FIELD_SPAN_OVERLAP", result.errors)

    def test_unverified_decoder_does_not_claim_an_error_or_exact_value(self):
        raw = 'action=deny message="reason=invalid credentials"'
        candidate = snapshot(raw)
        changed = replace(
            candidate.occurrences[1], value="different",
        )
        bad = replace(candidate, occurrences=(candidate.occurrences[0], changed))
        result = audit_candidate(raw, bad)
        # Only source byte invariants are proven; semantic mismatch requires a
        # separate oracle. This code must not certify an unknown decoder.
        self.assertTrue(result.valid)
        self.assertGreater(result.decoding_unverified, 0)

    def test_unknown_decoder_is_not_eligible_for_new_field_promotion(self):
        raw = "raw prose with no delimited fields"
        baseline = snapshot(raw)
        invented = CandidateOccurrence("invented", None, 0, "not-in-source", "str", 0, 3)
        modified = replace(
            baseline, occurrences=baseline.occurrences + (invented,),
            completeness="PARTIAL",
        )
        result = score_candidate(raw, modified, baseline)
        self.assertFalse(result.valid)
        self.assertIn("INFERRED_FIELD_DECODING_UNVERIFIED", result.errors)

    def test_parent_path_with_partial_overlap_not_containment_is_rejected(self):
        raw = '{"root":{"name":"alpha"}}'
        candidate = snapshot(raw)
        original = candidate.occurrences[0]
        overlapping_parent = CandidateOccurrence(
            "root", ("root",), 0, {"name": "alpha"}, "dict",
            original.end_byte - 2, len(raw.encode()) - 1,
        )
        nested = replace(
            original, display_path="root.name", source_segments=("root", "name")
        )
        modified = replace(candidate, occurrences=(overlapping_parent, nested))
        self.assertIn(
            "INCOMPATIBLE_FIELD_SPAN_OVERLAP",
            audit_candidate(raw, modified).errors,
        )

    def test_mdl_proxy_rejects_free_field_when_residual_does_not_improve(self):
        raw = "raw prose with no delimited fields"
        baseline = snapshot(raw)
        new = CandidateOccurrence("spurious", None, 0, "raw", "str", 0, 3)
        padded = replace(
            baseline, occurrences=baseline.occurrences + (new,),
            completeness="PARTIAL",
        )
        selection = choose_shadow(raw, (padded, baseline), baseline)
        self.assertEqual(selection.selected_index, 1)
        self.assertTrue(selection.baseline_preserved)
        self.assertGreater(
            score_candidate(raw, padded, baseline).description_bits,
            score_candidate(raw, baseline, baseline).description_bits,
        )

    def test_empty_goldens_cannot_fake_macro_f1(self):
        self.assertIsNone(summarize([])["f1"])
        self.assertEqual(summarize([{"tp": 0, "fp": 1, "fn": 0, "false_complete": True}])["f1"], 0.0)


    def test_independent_json_pointer_escapes_and_exact_typed_span(self):
        raw = '{"a/b":{"~":7}}'
        position = raw.encode("utf8").index(b"7")
        row = {"fields": [{
            "path": "/a~1b/~0",
            "value_start_byte": position, "value_end_byte": position + 1,
            "value": 7,
        }]}
        self.assertEqual(_pointer(("a/b", "~")), "/a~1b/~0")
        self.assertEqual(
            compare_frozen_json(snapshot(raw), row),
            {"tp": 1, "fp": 0, "fn": 0, "false_complete": False},
        )

    def test_independent_json_typed_value_mismatch_is_not_silent(self):
        raw = '{"count":7}'
        position = raw.encode("utf8").index(b"7")
        row = {"fields": [{
            "path": "/count",
            "value_start_byte": position, "value_end_byte": position + 1,
            "value": "7",
        }]}
        actual = compare_frozen_json(snapshot(raw), row)
        self.assertEqual((actual["tp"], actual["fp"], actual["fn"]), (0, 1, 1))
        self.assertTrue(actual["false_complete"])

    def test_publisher_reference_pin_rejects_unqualified_bytes(self):
        with self.assertRaisesRegex(ValueError, "PUBLISHER_ORACLE_PIN_MISMATCH"):
            _validate_publisher(b'{"data":"untrusted"}', b"{}")
        self.assertEqual(len(PUBLISHER_PIN_SHA256), 64)

    def test_sealed_independent_oracle_requires_exact_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            oracle = base / "oracle.json"
            summary = base / "summary.json"
            oracle.write_text("[]")
            summary.write_text("{}")
            with self.assertRaisesRegex(ValueError, "SEALED_ORACLE_SHA256_CHANGED"):
                _verified_oracle(oracle, summary)

    def test_nonjson_publisher_oracle_requires_exact_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            oracle = base / "oracle.json"
            summary = base / "summary.json"
            sources = base / "sources.json"
            for path in (oracle, summary, sources):
                path.write_text("{}")
            with self.assertRaisesRegex(ValueError, "PUBLISHER_FIELD_ORACLE_CHANGED"):
                validate_nonjson(oracle, summary, sources)


if __name__ == "__main__":
    unittest.main()
