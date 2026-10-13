"""Independent synthetic positive/negative controls for residual captures."""
import unittest
from span_alignment import align_template


class AnchorAlignmentTests(unittest.TestCase):
    def test_repeated_equal_values_have_different_provenance(self):
        body="src=192.0.2.8 dst=192.0.2.8 outcome=blocked"
        template="src=<:IP:> dst=<:IP:> outcome=blocked"
        res=align_template(template, body)
        self.assertEqual("SOURCE_SPAN_CANDIDATE_ONLY", res.status)
        self.assertEqual(2, len(res.captures))
        self.assertEqual(["192.0.2.8", "192.0.2.8"], [c.value for c in res.captures])
        self.assertNotEqual(res.captures[0].start_byte, res.captures[1].start_byte)

    def test_known_prefix_and_suffix_extract_unicode_byte_positions(self):
        raw="<123>date=2026-10-14 | account=한😀 | access=granted"
        body_start=raw.index("account=")
        body=raw[body_start:]
        result=align_template("account=<*> | access=granted",body,raw=raw,body_start_char=body_start)
        self.assertEqual("SOURCE_SPAN_CANDIDATE_ONLY",result.status)
        value=result.captures[0]
        self.assertEqual("한😀",raw.encode("utf8")[value.start_byte:value.end_byte].decode("utf8"))
        self.assertGreater(value.start_byte,body.index("한"))

    def test_repeated_literal_anchor_is_ambiguous(self):
        res=align_template("prefix <*> and <*> end", "prefix one and two and three end")
        self.assertEqual("AMBIGUOUS_ANCHOR_LAYOUT",res.status)
        self.assertEqual((),res.captures)

    def test_prefix_spoofing_and_suffix_overcapture_rejected(self):
        for body in ["xx user alice signed in", "user alice signed in EXFIL"]:
            self.assertNotEqual("SOURCE_SPAN_CANDIDATE_ONLY",align_template("user <*> signed in",body).status)

    def test_adjacent_wildcards_are_not_source_spans(self):
        # Adjacent masks with no source anchor between them.
        res=align_template("prefix <*><*> suffix suffix", "prefix twowords suffix suffix")
        self.assertEqual("ABSTAIN_ADJACENT_VARIABLES",res.status)

    def test_ip_and_number_type_validators_fail_closed(self):
        cases=[("event src=<:IP:> severity=HIGH","event src=999.999.999.999 severity=HIGH"),
               ("event port=<:NUMBER:> severity=HIGH","event port=abc severity=HIGH")]
        for template,body in cases:
            with self.subTest(body=body):
                self.assertNotEqual("SOURCE_SPAN_CANDIDATE_ONLY",align_template(template,body).status)

    def test_no_magic_meaning_assignment(self):
        result=align_template("User <*> logged in from <:IP:> safely", "User bob logged in from 192.0.2.33 safely")
        self.assertEqual("SOURCE_SPAN_CANDIDATE_ONLY",result.status)
        self.assertEqual(["residual.variable_0","residual.variable_1"], [x.path for x in result.captures])
        self.assertEqual(["*","IP"],[x.mask for x in result.captures])

    def test_empty_unbounded_template_and_tiny_support_abstain(self):
        self.assertNotEqual("SOURCE_SPAN_CANDIDATE_ONLY",align_template("<*>","any message").status)
        self.assertEqual("ABSTAIN_UNQUALIFIED_CLUSTER",align_template("user <*> signed in","user abc signed in",cluster_support=1).status)

    def test_mutated_source_without_exact_slice_is_rejected(self):
        raw="header: account bob event ok"
        res=align_template("account <*> event ok", "account bob event ok", raw=raw, body_start_char=0)
        self.assertEqual("SOURCE_SLICE_MISMATCH",res.status)

    def test_truncated_and_invalid_utf8_offsets_are_bounded(self):
        res=align_template("prefix <*> completed ok","prefix " + "a"*257 + " completed ok")
        self.assertNotEqual("SOURCE_SPAN_CANDIDATE_ONLY",res.status)

    def test_exact_param_with_multiword_value(self):
        res=align_template("failed for <*> from node <*>","failed for Mary Jane from node server01")
        self.assertEqual("SOURCE_SPAN_CANDIDATE_ONLY",res.status)
        self.assertEqual("Mary Jane",res.captures[0].value)


if __name__ == "__main__":
    unittest.main()
