import unittest

from structural_funnel import (
    candidate_improves,
    confirm_positional_csv,
    learn_best_hypothesis,
    learn_csv_cell_label_hypotheses,
    delete_required_rgram_literal,
    learn_event_template_hypotheses,
    learn_extended_bsd_envelope_hypotheses,
    learn_positional_csv_hypothesis,
    learn_relative_rgram_hypotheses,
    learn_residual_typed_label_hypotheses,
    learn_leading_numeric_hypotheses,
    merge_residual_hypothesis,
    parse_leading_numeric_slots,
    parse_with_event_template,
    parse_extended_bsd_envelope,
    parse_with_hypothesis,
    parse_with_relative_rgram,
    augment_partial_with_numeric_prefix,
    augment_partial_with_extended_bsd_envelope,
    augment_partial_with_residual_typed_labels,
    refine_csv_cell_labels,
)
from source_parse import SourceEvent, ValueSpan, assert_source_accounting


class StructuralFunnelProductTests(unittest.TestCase):
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

    def test_leading_numeric_skeleton_recovers_partial_slots_without_completion(self):
        training = [
            "05/30-19:09:10.917356  alert one",
            "12/30-14:09:21.116402  alert two",
            "01/21-02:23:42.327730  alert three",
            "09/04-21:55:02.041364  alert four",
        ]
        hypotheses = learn_leading_numeric_hypotheses(training)
        self.assertEqual(1, len(hypotheses))
        raw = "10/31-07:08:09.123456  alert holdout"
        candidate = parse_leading_numeric_slots(raw, hypotheses)
        self.assertIsNotNone(candidate)
        self.assertEqual(5, len(candidate.value_spans))

        baseline = SourceEvent(raw, syntax="UNKNOWN")
        baseline.issues = ["NO_SUPPORTED_GRAMMAR"]
        baseline.unparsed = [(0, len(raw))]
        assert_source_accounting(baseline)

        augmented = augment_partial_with_numeric_prefix(baseline, candidate)
        self.assertIsNotNone(augmented)
        self.assertEqual("PARTIAL", augmented.status)
        self.assertEqual(["NO_SUPPORTED_GRAMMAR"], augmented.issues)
        self.assertEqual([(0, len(raw))], augmented.unparsed)
        self.assertEqual(5, len(augmented.value_spans))
        self.assertEqual(
            ["10", "31", "07", "08", "09.123456"],
            list(
                augmented.vendor_fields["hypothesis_partial"][
                    "numeric_prefix"
                ].values()
            ),
        )

    def test_leading_numeric_skeleton_requires_repeated_shape(self):
        training = [
            "05/30-19:09:10.917356  first",
            "2026-10-15T10:11:12Z second",
            "1234 random",
            "09/04-21:55:02.041364  fourth",
        ]
        self.assertEqual({}, learn_leading_numeric_hypotheses(training))

    def test_numeric_partial_recovery_only_adds_residual_spans(self):
        training = [
            "05/30-19:09:10.917356  first",
            "12/30-14:09:21.116402  second",
            "01/21-02:23:42.327730  third",
        ]
        hypotheses = learn_leading_numeric_hypotheses(training)
        raw = "09/04-21:55:02.041364  alert"
        candidate = parse_leading_numeric_slots(raw, hypotheses)
        self.assertIsNotNone(candidate)

        baseline = SourceEvent(raw, syntax="BASE")
        baseline.vendor_fields = {"existing": "09"}
        baseline.value_spans = [ValueSpan("existing", 0, 2, ("existing",))]
        baseline.primitive_fields = 1
        baseline.covered = [(0, 2)]
        baseline.unparsed = [(2, len(raw))]
        baseline.issues = ["NO_SUPPORTED_GRAMMAR"]
        assert_source_accounting(baseline)

        augmented = augment_partial_with_numeric_prefix(baseline, candidate)
        self.assertIsNotNone(augmented)
        self.assertEqual((0, 2), (
            augmented.value_spans[0].start_byte,
            augmented.value_spans[0].end_byte,
        ))
        self.assertEqual(5, len(augmented.value_spans))
        self.assertTrue(all(
            span.start_byte >= 2
            for span in augmented.value_spans[1:]
        ))

    def test_numeric_partial_recovery_respects_nul_safety_boundary(self):
        training = [
            "05/30-19:09:10.917356  first",
            "12/30-14:09:21.116402  second",
            "01/21-02:23:42.327730  third",
        ]
        hypotheses = learn_leading_numeric_hypotheses(training)
        raw = "09/04-21:55:02.041364\x00alert"
        self.assertIsNone(parse_leading_numeric_slots(raw, hypotheses))

        clean = "09/04-21:55:02.041364  alert"
        candidate = parse_leading_numeric_slots(clean, hypotheses)
        baseline = SourceEvent(clean, syntax="UNKNOWN")
        baseline.issues = ["SOURCE_SIZE_OR_NUL_INVALID"]
        baseline.unparsed = [(0, len(clean))]
        assert_source_accounting(baseline)
        self.assertIsNone(
            augment_partial_with_numeric_prefix(baseline, candidate)
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

    def _labeled_csv_event(self, raw):
        cells = raw.split(",")
        event = SourceEvent(raw, syntax="CSV_UNLABELED_CANDIDATE")
        cursor = 0
        for index, cell in enumerate(cells):
            start = cursor
            end = start + len(cell)
            event.value_spans.append(
                ValueSpan(
                    f"column_{index}",
                    start,
                    end,
                    None,
                )
            )
            event.vendor_fields[f"column_{index}"] = cell
            cursor = end + (1 if index + 1 < len(cells) else 0)
        event.primitive_fields = len(event.value_spans)
        event.covered = [(0, len(raw))]
        event.issues = ["UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION"]
        assert_source_accounting(event)
        return event

    def test_csv_cell_label_refinement_preserves_parent_spans(self):
        training = [
            self._labeled_csv_event(
                "Site: alpha,Server: edge1,Message: login allowed"
            ),
            self._labeled_csv_event(
                "Site: beta,Server: edge2,Message: login denied"
            ),
            self._labeled_csv_event(
                "Site: gamma,Server: edge3,Message: policy updated"
            ),
        ]
        hypotheses = learn_csv_cell_label_hypotheses(training)
        self.assertIn(3, hypotheses)

        baseline = self._labeled_csv_event(
            "Site: delta,Server: edge4,Message: session expired"
        )
        parents = list(baseline.value_spans)
        refined = refine_csv_cell_labels(baseline, hypotheses)
        self.assertIsNotNone(refined)
        self.assertEqual("PARTIAL", refined.status)
        self.assertEqual(parents, refined.value_spans[: len(parents)])
        child_spans = refined.value_spans[len(parents) :]
        self.assertEqual(3, len(child_spans))
        for child in child_spans:
            self.assertTrue(any(
                parent.start_byte <= child.start_byte
                and child.end_byte <= parent.end_byte
                for parent in parents
            ))
        self.assertEqual(
            {
                "Site": "delta",
                "Server": "edge4",
                "Message": "session expired",
            },
            refined.vendor_fields["csv_refined"],
        )

    def test_csv_cell_label_refinement_abstains_on_one_stable_label(self):
        training = [
            self._labeled_csv_event("Site: alpha,ordinary prose one,tail one"),
            self._labeled_csv_event("Site: beta,ordinary prose two,tail two"),
            self._labeled_csv_event("Site: gamma,ordinary prose three,tail three"),
        ]
        self.assertEqual({}, learn_csv_cell_label_hypotheses(training))

    def test_extended_bsd_envelope_learns_composite_header_fields(self):
        training = [
            '<142>May 10 15:19:05 edge-a SERIAL001 (2024-05-10T09:49:05) firewall[10]: msg_id="a" body',
            '<143>May 11 16:20:06 edge-b SERIAL002 (2024-05-11T10:50:06) firewall[11]: msg_id="b" body',
            '<144>May 12 17:21:07 edge-c SERIAL003 (2024-05-12T11:51:07) firewall[12]: msg_id="c" body',
        ]
        hypotheses = learn_extended_bsd_envelope_hypotheses(training)
        self.assertIn((1, True), hypotheses)

        raw = '<145>May 13 18:22:08 edge-d SERIAL004 (2024-05-13T12:52:08) firewall[13]: msg_id="d" body'
        candidate = parse_extended_bsd_envelope(raw, hypotheses)
        self.assertIsNotNone(candidate)
        fields = candidate.vendor_fields["extended_bsd"]
        self.assertEqual("145", fields["priority"])
        self.assertEqual("May 13 18:22:08", fields["syslog_timestamp"])
        self.assertEqual("edge-d", fields["hostname"])
        self.assertEqual("SERIAL004", fields["prefix_token_0"])
        self.assertEqual("2024-05-13T12:52:08", fields["inner_timestamp"])
        self.assertEqual("firewall", fields["appname"])
        self.assertEqual("13", fields["procid"])

        msg_start = raw.index('d"')
        baseline = SourceEvent(raw, syntax="BASE")
        baseline.vendor_fields = {"existing": "d"}
        baseline.value_spans = [
            ValueSpan("existing", msg_start, msg_start + 1, ("existing",))
        ]
        baseline.primitive_fields = 1
        baseline.covered = [(0, len(raw))]
        baseline.issues = ["UNSUPPORTED_PRI_BODY"]
        assert_source_accounting(baseline)

        augmented = augment_partial_with_extended_bsd_envelope(
            baseline, candidate
        )
        self.assertIsNotNone(augmented)
        self.assertEqual("PARTIAL", augmented.status)
        self.assertEqual(
            baseline.value_spans,
            augmented.value_spans[: len(baseline.value_spans)],
        )

    def test_extended_bsd_envelope_fails_closed_on_bad_time_or_low_support(self):
        training = [
            '<142>May 10 15:19:05 edge-a SERIAL001 (2024-05-10T09:49:05) app[10]: body',
            '<143>May 11 16:20:06 edge-b SERIAL002 (2024-05-11T10:50:06) app[11]: body',
        ]
        self.assertEqual(
            {}, learn_extended_bsd_envelope_hypotheses(training)
        )
        hypotheses = learn_extended_bsd_envelope_hypotheses(training * 2)
        bad = '<142>May 99 99:99:99 edge-a SERIAL001 (2024-99-99T99:99:99) app[10]: body'
        self.assertIsNone(parse_extended_bsd_envelope(bad, hypotheses))


    def _typed_label_residual_event(self, raw):
        event = SourceEvent(raw, syntax="TEST_TYPED_LABEL_RESIDUAL")
        event.covered = []
        event.unparsed = [(0, len(raw))]
        event.issues = ["NO_SUPPORTED_GRAMMAR"]
        assert_source_accounting(event)
        return event

    def test_residual_typed_labels_recover_only_repeated_explicit_values(self):
        training = [
            self._typed_label_residual_event(
                'failure GatewayEndpoint=192.0.2.1 done Tunnel="vpn-a" end'
            ),
            self._typed_label_residual_event(
                'failure GatewayEndpoint=192.0.2.2 done Tunnel="vpn-b" end'
            ),
            self._typed_label_residual_event(
                'failure GatewayEndpoint=192.0.2.3 done Tunnel="vpn-c" end'
            ),
        ]
        hypotheses = learn_residual_typed_label_hypotheses(training)
        self.assertEqual({"GatewayEndpoint", "Tunnel"}, set(hypotheses))
        baseline = self._typed_label_residual_event(
            'failure GatewayEndpoint=198.51.100.9 done Tunnel="vpn-z" end'
        )
        augmented = augment_partial_with_residual_typed_labels(
            baseline, hypotheses
        )
        self.assertIsNotNone(augmented)
        self.assertEqual("PARTIAL", augmented.status)
        self.assertEqual(baseline.unparsed, augmented.unparsed)
        self.assertEqual(baseline.issues, augmented.issues)
        self.assertEqual(
            {
                "GatewayEndpoint": "198.51.100.9",
                "Tunnel": "vpn-z",
            },
            augmented.vendor_fields["hypothesis_partial"][
                "residual_typed_labels"
            ],
        )

    def test_residual_typed_labels_ignore_common_lowercase_kv(self):
        training = [
            self._typed_label_residual_event("msg=192.0.2.1 end"),
            self._typed_label_residual_event("msg=192.0.2.2 end"),
            self._typed_label_residual_event("msg=192.0.2.3 end"),
        ]
        self.assertEqual({}, learn_residual_typed_label_hypotheses(training))

    def test_residual_typed_labels_require_three_event_support(self):
        training = [
            self._typed_label_residual_event(
                "failure GatewayEndpoint=192.0.2.1 end"
            ),
            self._typed_label_residual_event(
                "failure GatewayEndpoint=192.0.2.2 end"
            ),
        ]
        self.assertEqual(
            {},
            learn_residual_typed_label_hypotheses(training),
        )


if __name__ == "__main__":
    unittest.main()
