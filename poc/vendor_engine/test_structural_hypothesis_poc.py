import unittest

from structural_hypothesis_poc import (
    candidate_improves,
    confirm_positional_csv,
    learn_best_hypothesis,
    delete_required_rgram_literal,
    learn_event_template_hypotheses,
    learn_positional_csv_hypothesis,
    learn_relative_rgram_hypotheses,
    learn_masked_residual_rgram_hypotheses,
    learn_typed_residual_hypotheses,
    merge_residual_hypothesis,
    augment_residual_hypothesis,
    parse_with_event_template,
    parse_with_hypothesis,
    parse_with_relative_rgram,
    parse_with_masked_residual_rgram,
    parse_with_typed_residual_hypotheses,
    delete_required_masked_rgram_literal,
)
from source_parse import SourceEvent, ValueSpan, assert_source_accounting


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

    def test_residual_merge_preserves_baseline_spans_and_adds_only_residual_values(self):
        hypothesis = learn_best_hypothesis(self.train)
        raw = (
            "prefix Domain=example.test, Controller=dc09, "
            "Message=ok, Result=allow"
        )
        candidate = parse_with_hypothesis(raw, hypothesis)
        baseline = SourceEvent(raw, syntax="BASE")
        baseline.vendor_fields = {"existing": "prefix"}
        baseline.value_spans = [
            ValueSpan("existing", 0, 6, ("existing",))
        ]
        baseline.primitive_fields = 1
        baseline.covered = [(0, 6)]
        baseline.unparsed = [(6, len(raw))]
        assert_source_accounting(baseline)

        merged = merge_residual_hypothesis(baseline, candidate)
        self.assertIsNotNone(merged)
        self.assertEqual("SOURCE_PARSED", merged.status)
        self.assertEqual(baseline.value_spans[0], merged.value_spans[0])
        self.assertEqual("prefix", merged.vendor_fields["existing"])
        baseline_ranges = {
            (span.start_byte, span.end_byte) for span in baseline.value_spans
        }
        for span in merged.value_spans[1:]:
            self.assertNotIn((span.start_byte, span.end_byte), baseline_ranges)
            self.assertGreaterEqual(span.start_byte, 6)

    def test_residual_merge_rejects_unrepresented_candidate_value_span(self):
        raw = "prefix alpha beta gamma"
        baseline = SourceEvent(raw, syntax="BASE")
        baseline.vendor_fields = {"existing": "alpha beta"}
        baseline.value_spans = [
            ValueSpan("existing", 7, 17, ("existing",))
        ]
        baseline.primitive_fields = 1
        baseline.covered = [(0, 18)]
        baseline.unparsed = [(18, len(raw))]
        assert_source_accounting(baseline)

        candidate = SourceEvent(
            raw,
            syntax="CANDIDATE",
            vendor_fields={"candidate": {"wide": "alpha beta gamma"}},
            value_spans=[
                ValueSpan("candidate.wide", 7, len(raw), ("candidate", "wide"))
            ],
            covered=[(0, len(raw))],
            primitive_fields=1,
        )
        assert_source_accounting(candidate)
        self.assertEqual("SOURCE_PARSED", candidate.status)
        self.assertIsNone(
            merge_residual_hypothesis(baseline, candidate)
        )

    def test_residual_merge_never_clears_malformed_or_resource_limit_issues(self):
        hypothesis = learn_best_hypothesis(self.train)
        raw = (
            "prefix Domain=example.test, Controller=dc09, "
            "Message=ok, Result=allow"
        )
        candidate = parse_with_hypothesis(raw, hypothesis)
        for issue in (
            "KV_QUOTE_UNCLOSED",
            "SOURCE_SIZE_OR_NUL_INVALID",
            "RFC5424_SD_BYTE_LIMIT",
            "JSON_TRUNCATED",
        ):
            with self.subTest(issue=issue):
                baseline = SourceEvent(raw, syntax="BASE")
                baseline.vendor_fields = {"existing": "prefix"}
                baseline.value_spans = [
                    ValueSpan("existing", 0, 6, ("existing",))
                ]
                baseline.primitive_fields = 1
                baseline.covered = [(0, 6)]
                baseline.unparsed = [(6, len(raw))]
                baseline.issues = [issue]
                assert_source_accounting(baseline)
                self.assertIsNone(
                    merge_residual_hypothesis(baseline, candidate)
                )

    def test_event_template_learns_literal_anchors_and_variable_slots(self):
        training = [
            "<166>Oct 15 edge %EDGE-6-100001: User alice connected from 192.0.2.1 to gateway blue request allowed",
            "<166>Oct 15 edge %EDGE-6-100001: User bob connected from 192.0.2.2 to gateway green request allowed",
            "<166>Oct 15 edge %EDGE-6-100001: User carol connected from 192.0.2.3 to gateway red request allowed",
        ]
        hypotheses = learn_event_template_hypotheses(training)
        self.assertEqual(1, len(hypotheses))
        raw = (
            "<166>Oct 15 edge %EDGE-6-100001: User dave connected from "
            "198.51.100.9 to gateway amber request allowed"
        )
        event = parse_with_event_template(raw, hypotheses)
        self.assertIsNotNone(event)
        assert_source_accounting(event)
        self.assertEqual("SOURCE_PARSED", event.status)
        slots = event.vendor_fields["template"]["slots"]
        self.assertTrue(any("dave" in value for value in slots))
        self.assertTrue(any("198.51.100.9" in value for value in slots))
        self.assertTrue(any("amber" in value for value in slots))

    def test_event_template_rejects_truncated_holdout(self):
        training = [
            "<166>Oct 15 edge %EDGE-6-100001: User alice connected from 192.0.2.1 to gateway blue request allowed",
            "<166>Oct 15 edge %EDGE-6-100001: User bob connected from 192.0.2.2 to gateway green request allowed",
            "<166>Oct 15 edge %EDGE-6-100001: User carol connected from 192.0.2.3 to gateway red request allowed",
        ]
        hypotheses = learn_event_template_hypotheses(training)
        truncated = (
            "<166>Oct 15 edge %EDGE-6-100001: User dave connected from "
            "198.51.100.9"
        )
        self.assertIsNone(parse_with_event_template(truncated, hypotheses))

    def _rgram_view(self, body):
        raw = "header " + body
        start = len("header ")
        event = SourceEvent(raw, syntax="BASE")
        event.vendor_fields = {"header": "header"}
        event.value_spans = [
            ValueSpan("header", 0, len("header"), ("header",))
        ]
        event.primitive_fields = 1
        event.covered = [(0, start)]
        event.unparsed = [(start, len(raw))]
        assert_source_accounting(event)
        return event

    def test_relative_rgram_learns_repeated_security_body_signature(self):
        training = [
            self._rgram_view(
                "Info: MID 101 URL https://a.test/a has reputation 0.0 "
                "matched Condition: URL Reputation Rule"
            ),
            self._rgram_view(
                "Info: MID 202 URL https://b.test/b has reputation 3.0 "
                "matched Condition: URL Reputation Rule"
            ),
            self._rgram_view(
                "Info: MID 303 URL https://c.test/c has reputation 5.7 "
                "matched Condition: URL Reputation Rule"
            ),
        ]
        hypotheses = learn_relative_rgram_hypotheses(training)
        self.assertEqual(1, len(hypotheses))

        holdout = self._rgram_view(
            "Info: MID 404 URL https://d.test/d has reputation 9.1 "
            "matched Condition: URL Reputation Rule"
        )
        candidate = parse_with_relative_rgram(
            holdout.raw, holdout, hypotheses
        )
        self.assertIsNotNone(candidate)
        assert_source_accounting(candidate)
        self.assertEqual("SOURCE_PARSED", candidate.status)
        slots = candidate.vendor_fields["rgram"]["slots"]
        self.assertIn("404", slots.values())
        self.assertIn("https://d.test/d", slots.values())
        self.assertIn("9.1", slots.values())

        merged = merge_residual_hypothesis(holdout, candidate)
        self.assertIsNotNone(merged)
        self.assertEqual("SOURCE_PARSED", merged.status)
        self.assertEqual(holdout.value_spans[0], merged.value_spans[0])

    def test_relative_rgram_rejects_truncation_and_required_literal_deletion(self):
        training = [
            self._rgram_view(
                "Info: MID 101 URL https://a.test/a has reputation 0.0 "
                "matched Condition: URL Reputation Rule"
            ),
            self._rgram_view(
                "Info: MID 202 URL https://b.test/b has reputation 3.0 "
                "matched Condition: URL Reputation Rule"
            ),
            self._rgram_view(
                "Info: MID 303 URL https://c.test/c has reputation 5.7 "
                "matched Condition: URL Reputation Rule"
            ),
        ]
        hypotheses = learn_relative_rgram_hypotheses(training)
        full = self._rgram_view(
            "Info: MID 404 URL https://d.test/d has reputation 9.1 "
            "matched Condition: URL Reputation Rule"
        )
        truncated = self._rgram_view(
            "Info: MID 404 URL https://d.test/d has reputation 9.1"
        )
        self.assertIsNone(
            parse_with_relative_rgram(
                truncated.raw, truncated, hypotheses
            )
        )

        mutated_raw = delete_required_rgram_literal(
            full.raw, full, hypotheses
        )
        self.assertIsNotNone(mutated_raw)
        mutated_body = mutated_raw[len("header "):]
        mutated_view = self._rgram_view(mutated_body)
        self.assertIsNone(
            parse_with_relative_rgram(
                mutated_view.raw, mutated_view, hypotheses
            )
        )

    def test_relative_rgram_requires_three_training_examples(self):
        training = [
            self._rgram_view(
                "Info: MID 101 URL https://a.test/a has reputation 0.0 "
                "matched Condition: URL Reputation Rule"
            ),
            self._rgram_view(
                "Info: MID 202 URL https://b.test/b has reputation 3.0 "
                "matched Condition: URL Reputation Rule"
            ),
        ]
        self.assertEqual({}, learn_relative_rgram_hypotheses(training))

    def test_residual_augmentation_adds_only_residual_values_without_status_promotion(self):
        raw = "prefix Domain=example.test, Controller=dc09, Message=ok, Result=allow"
        hypothesis = learn_best_hypothesis(self.train)
        candidate = parse_with_hypothesis(raw, hypothesis)
        self.assertIsNotNone(candidate)

        baseline = SourceEvent(raw, syntax="BASE")
        baseline.vendor_fields = {"existing": "prefix"}
        baseline.value_spans = [
            ValueSpan("existing", 0, 6, ("existing",))
        ]
        baseline.covered = [(0, 6)]
        baseline.unparsed = [(6, len(raw))]
        baseline.issues = ["BASE_INCOMPLETE"]
        assert_source_accounting(baseline)

        augmented = augment_residual_hypothesis(baseline, candidate)
        self.assertIsNotNone(augmented)
        self.assertEqual("PARTIAL", augmented.status)
        self.assertEqual(baseline.unparsed, augmented.unparsed)
        self.assertEqual(baseline.issues, augmented.issues)
        self.assertGreater(len(augmented.value_spans), len(baseline.value_spans))
        self.assertEqual(
            baseline.value_spans[0],
            next(span for span in augmented.value_spans if span.path == "existing"),
        )

    def test_residual_augmentation_rejects_hard_malformed_baseline(self):
        raw = "prefix Domain=example.test, Controller=dc09, Message=ok, Result=allow"
        hypothesis = learn_best_hypothesis(self.train)
        candidate = parse_with_hypothesis(raw, hypothesis)
        baseline = SourceEvent(raw, syntax="BASE")
        baseline.covered = [(0, 6)]
        baseline.unparsed = [(6, len(raw))]
        baseline.issues = ["SOURCE_SIZE_OR_NUL_INVALID"]
        assert_source_accounting(baseline)
        self.assertIsNone(augment_residual_hypothesis(baseline, candidate))

    def _masked_baseline(self, raw):
        left = raw.index("192.0.2.1:443")
        left_end = left + len("192.0.2.1:443")
        right = raw.index("198.51.100.2:80")
        right_end = right + len("198.51.100.2:80")
        event = SourceEvent(raw, syntax="BASE_NETWORK_ATOMS")
        event.vendor_fields = {
            "src_endpoint": raw[left:left_end],
            "dst_endpoint": raw[right:right_end],
        }
        event.value_spans = [
            ValueSpan(
                "src_endpoint",
                len(raw[:left].encode("utf8")),
                len(raw[:left_end].encode("utf8")),
                ("src_endpoint",),
            ),
            ValueSpan(
                "dst_endpoint",
                len(raw[:right].encode("utf8")),
                len(raw[:right_end].encode("utf8")),
                ("dst_endpoint",),
            ),
        ]
        event.primitive_fields = 2
        event.covered = [(left, left_end), (right, right_end)]
        event.unparsed = [
            (0, left),
            (left_end, right),
            (right_end, len(raw)),
        ]
        assert_source_accounting(event)
        return event

    def test_masked_rgram_keeps_baseline_values_opaque_and_emits_only_residual(self):
        raws = [
            "03/12-10:11:12 src=192.0.2.1:443 -> dst=198.51.100.2:80",
            "04/13-11:12:13 src=192.0.2.1:443 -> dst=198.51.100.2:80",
            "05/14-12:13:14 src=192.0.2.1:443 -> dst=198.51.100.2:80",
        ]
        training = [self._masked_baseline(raw) for raw in raws]
        hypotheses = learn_masked_residual_rgram_hypotheses(training)
        self.assertEqual(1, len(hypotheses))

        raw = "06/15-13:14:15 src=192.0.2.1:443 -> dst=198.51.100.2:80"
        baseline = self._masked_baseline(raw)
        candidate = parse_with_masked_residual_rgram(
            raw, baseline, hypotheses
        )
        self.assertIsNotNone(candidate)
        self.assertEqual("SOURCE_PARSED", candidate.status)
        baseline_ranges = {
            (span.start_byte, span.end_byte)
            for span in baseline.value_spans
        }
        self.assertEqual(1, len(candidate.value_spans))
        timestamp_span = candidate.value_spans[0]
        self.assertEqual(
            "06/15-13:14:15",
            raw.encode()[timestamp_span.start_byte:timestamp_span.end_byte].decode(),
        )
        self.assertTrue(all(
            (span.start_byte, span.end_byte) not in baseline_ranges
            for span in candidate.value_spans
        ))
        merged = merge_residual_hypothesis(baseline, candidate)
        self.assertIsNotNone(merged)
        before = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in baseline.value_spans
        }
        after = {
            (span.path, span.source_segments, span.start_byte, span.end_byte)
            for span in merged.value_spans
        }
        self.assertTrue(before <= after)

    def test_masked_rgram_requires_three_examples_and_fails_on_literal_deletion(self):
        raw1 = "03/12-10:11:12 src=192.0.2.1:443 -> dst=198.51.100.2:80"
        raw2 = "04/13-11:12:13 src=192.0.2.1:443 -> dst=198.51.100.2:80"
        raw3 = "05/14-12:13:14 src=192.0.2.1:443 -> dst=198.51.100.2:80"
        two = [self._masked_baseline(raw1), self._masked_baseline(raw2)]
        self.assertEqual({}, learn_masked_residual_rgram_hypotheses(two))
        training = two + [self._masked_baseline(raw3)]
        hypotheses = learn_masked_residual_rgram_hypotheses(training)
        self.assertEqual(1, len(hypotheses))
        corrupted = delete_required_masked_rgram_literal(
            raw3, training[-1], hypotheses
        )
        self.assertIsNotNone(corrupted)
        corrupted_baseline = self._masked_baseline(corrupted)
        self.assertIsNone(
            parse_with_masked_residual_rgram(
                corrupted, corrupted_baseline, hypotheses
            )
        )

    def test_typed_residual_learns_full_snort_date_field(self):
        raws = [
            "03/12-10:11:12 src=192.0.2.1:443 -> dst=198.51.100.2:80",
            "04/13-11:12:13 src=192.0.2.1:443 -> dst=198.51.100.2:80",
            "05/14-12:13:14 src=192.0.2.1:443 -> dst=198.51.100.2:80",
        ]
        training = [self._masked_baseline(raw) for raw in raws]
        hypotheses = learn_typed_residual_hypotheses(training)
        self.assertIn("SNORT_DATE", hypotheses)

        raw = "06/15-13:14:15 src=192.0.2.1:443 -> dst=198.51.100.2:80"
        baseline = self._masked_baseline(raw)
        candidate = parse_with_typed_residual_hypotheses(
            raw, baseline, hypotheses
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(1, len(candidate.value_spans))
        span = candidate.value_spans[0]
        self.assertEqual(
            "06/15-13:14:15",
            raw.encode()[span.start_byte:span.end_byte].decode(),
        )
        augmented = augment_residual_hypothesis(baseline, candidate)
        self.assertIsNotNone(augmented)
        self.assertEqual(baseline.status, augmented.status)
        self.assertEqual(baseline.unparsed, augmented.unparsed)
        self.assertEqual(baseline.issues, augmented.issues)

    def _typed_syslog_baseline(self, raw):
        host = "host01"
        start = raw.index(host)
        end = start + len(host)
        event = SourceEvent(raw, syntax="BASE_PARTIAL_SYSLOG")
        event.vendor_fields = {"host": host}
        event.value_spans = [
            ValueSpan(
                "host",
                len(raw[:start].encode("utf8")),
                len(raw[:end].encode("utf8")),
                ("host",),
            )
        ]
        event.primitive_fields = 1
        event.covered = [(start, end)]
        event.unparsed = [(0, start), (end, len(raw))]
        event.issues = ["UNSUPPORTED_PRI_BODY"]
        assert_source_accounting(event)
        return event

    def test_typed_residual_learns_full_syslog_timestamp_field(self):
        raws = [
            "<178>Sep 24 16:03:27 host01 CISE_Alarm WARN: one",
            "<178>Sep 25 17:04:28 host01 CISE_Alarm WARN: two",
            "<178>Sep 26 18:05:29 host01 CISE_Alarm WARN: three",
        ]
        training = [self._typed_syslog_baseline(raw) for raw in raws]
        hypotheses = learn_typed_residual_hypotheses(training)
        self.assertIn("SYSLOG_TIMESTAMP", hypotheses)

        raw = "<178>Sep 27 19:06:30 host01 CISE_Alarm WARN: holdout"
        baseline = self._typed_syslog_baseline(raw)
        candidate = parse_with_typed_residual_hypotheses(
            raw, baseline, hypotheses
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(1, len(candidate.value_spans))
        span = candidate.value_spans[0]
        self.assertEqual(
            "Sep 27 19:06:30",
            raw.encode()[span.start_byte:span.end_byte].decode(),
        )
        augmented = augment_residual_hypothesis(baseline, candidate)
        self.assertIsNotNone(augmented)
        self.assertEqual("PARTIAL", augmented.status)

        invalid = "<178>Sep 31 25:99:99 host01 CISE_Alarm WARN: invalid"
        invalid_baseline = self._typed_syslog_baseline(invalid)
        self.assertIsNone(
            parse_with_typed_residual_hypotheses(
                invalid, invalid_baseline, hypotheses
            )
        )

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
