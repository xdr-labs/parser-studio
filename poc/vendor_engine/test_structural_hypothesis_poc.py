import unittest

from structural_hypothesis_poc import (
    candidate_improves,
    confirm_positional_csv,
    learn_best_hypothesis,
    learn_positional_csv_hypothesis,
    parse_with_hypothesis,
)
from source_parse import SourceEvent, assert_source_accounting


class StructuralHypothesisPocTests(unittest.TestCase):
    def setUp(self):
        self.train = [
            "prefix one Domain=example.local, Controller=dc01, Message=user login succeeded, Result=allow",
            "prefix two Domain=example.local, Controller=dc02, Message=user login failed, bad password, Result=deny",
            "prefix three Domain=example.org, Controller=dc03, Message=group lookup completed, Result=allow",
            "prefix four Domain=example.net, Controller=dc04, Message=timeout waiting for remote service, Result=deny",
        ]

    def test_learns_cross_event_anchor_grammar(self):
        hypothesis = learn_best_hypothesis(self.train)
        self.assertIsNotNone(hypothesis)
        self.assertEqual(",", hypothesis.delimiter)
        self.assertIn("Controller", hypothesis.stable_anchors)
        self.assertIn("Message", hypothesis.stable_anchors)
        self.assertIn("Result", hypothesis.stable_anchors)

    def test_unquoted_delimiter_inside_value_is_not_split_without_next_anchor(self):
        hypothesis = learn_best_hypothesis(self.train)
        raw = (
            "prefix holdout Domain=example.test, Controller=dc09, "
            "Message=authentication failed, remote endpoint unavailable, "
            "Result=deny"
        )
        event = parse_with_hypothesis(raw, hypothesis)
        self.assertIsNotNone(event)
        assert_source_accounting(event)
        self.assertEqual("SOURCE_PARSED", event.status)
        fields = event.vendor_fields["hypothesis"]["fields"]
        self.assertEqual(
            "authentication failed, remote endpoint unavailable",
            fields["Message"],
        )
        self.assertEqual("deny", fields["Result"])

    def test_unseen_field_is_retained_after_hypothesis_qualification(self):
        hypothesis = learn_best_hypothesis(self.train)
        raw = (
            "prefix holdout Domain=example.test, Controller=dc09, "
            "Message=ok, Session-Type=admin, Result=allow"
        )
        event = parse_with_hypothesis(raw, hypothesis)
        self.assertIsNotNone(event)
        self.assertEqual(
            "admin",
            event.vendor_fields["hypothesis"]["fields"]["Session-Type"],
        )

    def test_quoted_delimiter_is_preserved(self):
        hypothesis = learn_best_hypothesis(self.train)
        raw = (
            "prefix holdout Domain=example.test, Controller=dc09, "
            'Message="alpha, beta, gamma", Result=allow'
        )
        event = parse_with_hypothesis(raw, hypothesis)
        self.assertIsNotNone(event)
        self.assertEqual(
            "alpha, beta, gamma",
            event.vendor_fields["hypothesis"]["fields"]["Message"],
        )

    def test_weak_training_set_does_not_create_hypothesis(self):
        weak = [
            "ordinary free text one",
            "ordinary free text two",
            "ordinary free text three",
        ]
        self.assertIsNone(learn_best_hypothesis(weak))

    def test_known_structured_roots_are_not_reinterpreted(self):
        hypothesis = learn_best_hypothesis(self.train)
        for raw in (
            '{"Controller":"dc01","Message":"hello","Result":"allow"}',
            "CEF:0|V|P|1|100|name|5|src=192.0.2.1",
            "LEEF:2.0|V|P|1|x09|src=192.0.2.1",
        ):
            with self.subTest(raw=raw[:12]):
                self.assertIsNone(parse_with_hypothesis(raw, hypothesis))

    def test_truncated_holdout_fails_closed(self):
        hypothesis = learn_best_hypothesis(self.train)
        raw = "prefix Domain=example.test, Controller=dc09, trailing prose"
        self.assertIsNone(parse_with_hypothesis(raw, hypothesis))

    def test_candidate_improvement_never_replaces_complete_baseline(self):
        hypothesis = learn_best_hypothesis(self.train)
        raw = (
            "prefix Domain=example.test, Controller=dc09, "
            "Message=ok, Result=allow"
        )
        candidate = parse_with_hypothesis(raw, hypothesis)
        incomplete = SourceEvent(raw, syntax="UNKNOWN")
        incomplete.unparsed = [(0, len(raw))]
        self.assertTrue(candidate_improves(incomplete, candidate))
        complete = SourceEvent(raw, syntax="TEST")
        complete.vendor_fields = {"a": "b"}
        complete.covered = [(0, len(raw))]
        self.assertFalse(candidate_improves(complete, candidate))

    def _csv_event(self, width):
        values = [f"v{index}" for index in range(width)]
        raw = ",".join(values)
        event = SourceEvent(raw, syntax="CSV_UNLABELED_CANDIDATE")
        cursor = 0
        for index, value in enumerate(values):
            start = cursor
            end = start + len(value)
            event.value_spans.append(
                __import__("source_parse").ValueSpan(
                    f"column_{index}",
                    start,
                    end,
                    ("column_" + str(index),),
                )
            )
            cursor = end + (1 if index + 1 < width else 0)
        event.vendor_fields = {
            f"column_{index}": value for index, value in enumerate(values)
        }
        event.primitive_fields = width
        event.covered = [(0, len(raw))]
        event.issues = ["UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION"]
        assert_source_accounting(event)
        return event

    def test_csv_corpus_confirmation_preserves_existing_spans(self):
        training = [self._csv_event(8) for _ in range(4)]
        hypothesis = learn_positional_csv_hypothesis(training)
        self.assertIsNotNone(hypothesis)
        holdout = self._csv_event(8)
        before = list(holdout.value_spans)
        candidate = confirm_positional_csv(holdout, hypothesis)
        self.assertIsNotNone(candidate)
        self.assertEqual("SOURCE_PARSED", candidate.status)
        self.assertEqual(before, candidate.value_spans)

    def test_csv_corpus_confirmation_rejects_unstable_width(self):
        training = [
            self._csv_event(7),
            self._csv_event(8),
            self._csv_event(9),
            self._csv_event(10),
        ]
        self.assertIsNone(learn_positional_csv_hypothesis(training))


if __name__ == "__main__":
    unittest.main()
