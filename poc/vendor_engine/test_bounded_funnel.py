from __future__ import annotations

import unittest

from bounded_funnel import (
    FunnelConfig,
    _guard_complete_candidate,
    _partialize_learned_candidate,
    _residual_fanout,
    learn_funnel_hypotheses,
    replay_training,
    run_funnel_batch,
    run_funnel_event,
)
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting


class BoundedFunnelProductTest(unittest.TestCase):
    def test_product_default_is_greedy_beam_one(self):
        self.assertEqual(1, FunnelConfig().beam_width)
        self.assertEqual(6, FunnelConfig().max_passes)

    def test_all_complete_batch_skips_structural_replay(self):
        raws = [
            '{"event":{"action":"allow","src":"192.0.2.10"},"count":7}',
            '{"event":{"action":"deny","src":"192.0.2.11"},"count":8}',
        ]
        result = run_funnel_batch(raws)
        self.assertEqual(0, result.passes_run)
        self.assertEqual(2, len(result.selected))
        for baseline, selected in zip(result.baselines, result.selected):
            self.assertEqual("SOURCE_PARSED", baseline.status)
            self.assertEqual(baseline.raw, selected.raw)
            self.assertEqual(baseline.vendor_fields, selected.vendor_fields)
            self.assertEqual(baseline.value_spans, selected.value_spans)
            self.assertEqual(baseline.issues, selected.issues)
            self.assertEqual(baseline.unparsed, selected.unparsed)

    def test_product_batch_entrypoint_freezes_complete_and_enforces_bounds(self):
        raws = [
            '{"event":{"action":"allow","src":"192.0.2.10"},"count":7}',
            "05/30-19:09:10.917356  alert one",
            "12/30-14:09:21.116402  alert two",
            "01/21-02:23:42.327730  alert three",
        ]
        result = run_funnel_batch(raws)
        self.assertLessEqual(result.passes_run, 6)
        self.assertEqual("SOURCE_PARSED", result.baselines[0].status)
        self.assertEqual(result.baselines[0].vendor_fields, result.selected[0].vendor_fields)
        self.assertEqual(result.baselines[0].value_spans, result.selected[0].value_spans)
        for baseline, selected in zip(result.baselines, result.selected):
            assert_source_accounting(baseline)
            assert_source_accounting(selected)
            self.assertEqual(baseline.raw, selected.raw)
        with self.assertRaisesRegex(ValueError, "FUNNEL_BATCH_BOUND"):
            run_funnel_batch([])
        with self.assertRaisesRegex(ValueError, "FUNNEL_BATCH_BOUND"):
            run_funnel_batch(["x"] * 501)

    def test_complete_product_result_is_not_reinterpreted(self):
        raw = '{"event":{"action":"allow","src":"192.0.2.10","dst":"198.51.100.2"},"count":7}'
        training = [
            '{"event":{"action":"deny","src":"192.0.2.1"},"count":1}',
            '{"event":{"action":"allow","src":"192.0.2.2"},"count":2}',
            '{"event":{"action":"deny","src":"192.0.2.3"},"count":3}',
        ]
        hypotheses, _, _ = replay_training(training)
        baseline = parse_security_multipass(raw)
        self.assertEqual("SOURCE_PARSED", baseline.status)
        result = run_funnel_event(raw, hypotheses)
        self.assertEqual(baseline.vendor_fields, result.selected.vendor_fields)
        self.assertEqual(baseline.value_spans, result.selected.value_spans)
        self.assertEqual(baseline.raw, result.selected.raw)
        self.assertTrue(result.stopped_no_improvement)

    def test_numeric_training_adds_exact_partial_spans_without_completion(self):
        training = [
            "05/30-19:09:10.917356  alert one",
            "12/30-14:09:21.116402  alert two",
            "01/21-02:23:42.327730  alert three",
            "09/04-21:55:02.041364  alert four",
        ]
        hypotheses, _, _ = replay_training(training)
        raw = "10/31-07:08:09.123456  alert holdout"
        result = run_funnel_event(raw, hypotheses)
        assert_source_accounting(result.baseline)
        assert_source_accounting(result.selected)
        self.assertEqual(result.baseline.raw, result.selected.raw)
        self.assertGreater(len(result.selected.value_spans), len(result.baseline.value_spans))
        self.assertNotEqual("SOURCE_PARSED", result.selected.status)
        baseline_claims = {
            (s.path, s.source_segments, s.start_byte, s.end_byte)
            for s in result.baseline.value_spans
        }
        selected_claims = {
            (s.path, s.source_segments, s.start_byte, s.end_byte)
            for s in result.selected.value_spans
        }
        self.assertTrue(baseline_claims <= selected_claims)

    def test_adversarial_complete_guard_rejects_mutation_survival(self):
        from source_parse import SourceEvent, ValueSpan

        raw = "opaque value=123 tail"
        parent = SourceEvent(raw, syntax="BASE")
        parent.issues = ["NO_SUPPORTED_GRAMMAR"]
        parent.unparsed = [(0, len(raw))]
        assert_source_accounting(parent)

        def candidate_for(text: str):
            event = SourceEvent(text, syntax="OVERFIT")
            start = text.find("123")
            if start < 0:
                start = max(0, len(text) - 1)
            end = min(len(text), start + 1)
            if end <= start:
                return None
            event.vendor_fields = {"slot": text[start:end]}
            event.value_spans = [ValueSpan("slot", start, end, ("slot",))]
            event.primitive_fields = 1
            event.covered = [(0, len(text))]
            assert_source_accounting(event)
            return event

        merged = __import__("structural_funnel").merge_residual_hypothesis(
            parent, candidate_for(raw)
        )
        self.assertIsNotNone(merged)
        guarded = _guard_complete_candidate(
            parent, merged, parse_candidate=candidate_for
        )
        self.assertIsNone(guarded)

    def test_learned_complete_failure_can_retain_residual_spans_as_partial(self):
        from source_parse import SourceEvent, ValueSpan

        raw = "prefix opaque-value tail"
        parent = SourceEvent(raw, syntax="BASE")
        parent.vendor_fields = {"prefix": "prefix"}
        parent.value_spans = [ValueSpan("prefix", 0, 6, ("prefix",))]
        parent.primitive_fields = 1
        parent.covered = [(0, 6)]
        parent.unparsed = [(6, len(raw))]
        parent.issues = ["NO_SUPPORTED_GRAMMAR"]
        assert_source_accounting(parent)

        start = raw.index("opaque-value")
        end = start + len("opaque-value")
        candidate = SourceEvent(raw, syntax="LEARNED")
        candidate.vendor_fields = {"slot": "opaque-value"}
        candidate.value_spans = [ValueSpan("slot", start, end, ("slot",))]
        candidate.primitive_fields = 1
        candidate.covered = [(0, len(raw))]
        assert_source_accounting(candidate)

        partial = _partialize_learned_candidate(
            parent, candidate, hypothesis_name="rgram"
        )
        self.assertIsNotNone(partial)
        self.assertEqual("PARTIAL", partial.status)
        self.assertEqual(parent.issues, partial.issues)
        self.assertEqual(parent.unparsed, partial.unparsed)
        self.assertEqual(raw, partial.raw)
        before = {
            (span.start_byte, span.end_byte) for span in parent.value_spans
        }
        added = [
            span for span in partial.value_spans
            if (span.start_byte, span.end_byte) not in before
        ]
        self.assertEqual([(start, end)], [
            (span.start_byte, span.end_byte) for span in added
        ])

    def test_bare_residual_generic_candidate_is_observation_only(self):
        from unittest.mock import patch
        from source_parse import SourceEvent, ValueSpan

        raw = "opaque alpha beta"
        parent = SourceEvent(raw, syntax="BASE")
        parent.unparsed = [(0, len(raw))]
        parent.issues = ["NO_SUPPORTED_GRAMMAR"]
        assert_source_accounting(parent)

        child = SourceEvent(raw, syntax="GENERIC")
        child.vendor_fields = {"tokens": ["opaque", "alpha", "beta"]}
        child.value_spans = [
            ValueSpan("tokens.0", 0, 6, ("tokens", 0)),
            ValueSpan("tokens.1", 7, 12, ("tokens", 1)),
            ValueSpan("tokens.2", 13, 17, ("tokens", 2)),
        ]
        child.primitive_fields = 3
        child.covered = [(0, len(raw))]
        assert_source_accounting(child)
        self.assertEqual("SOURCE_PARSED", child.status)

        with patch(
            "bounded_funnel._whole_record_candidates",
            return_value=[("generic", child)],
        ):
            self.assertEqual([], _residual_fanout(parent, 1))

    def test_pass_and_beam_are_hard_bounded(self):
        training = [
            "05/30-19:09:10.917356  alert one",
            "12/30-14:09:21.116402  alert two",
            "01/21-02:23:42.327730  alert three",
        ]
        hypotheses = learn_funnel_hypotheses(
            training, [parse_security_multipass(raw) for raw in training]
        )
        result = run_funnel_event(
            "09/04-21:55:02.041364  alert holdout",
            hypotheses,
            config=FunnelConfig(max_passes=3, beam_width=2),
        )
        self.assertLessEqual(result.passes_run, 3)
        self.assertLessEqual(len(result.beam), 2)

    def test_low_support_does_not_invent_structure(self):
        training = [
            "05/30-19:09:10.917356  alert one",
            "ordinary unrelated security message",
        ]
        hypotheses = learn_funnel_hypotheses(
            training, [parse_security_multipass(raw) for raw in training]
        )
        raw = "10/31-07:08:09.123456  alert holdout"
        result = run_funnel_event(raw, hypotheses)
        baseline = parse_security_multipass(raw)
        self.assertEqual(baseline.value_spans, result.selected.value_spans)
        self.assertEqual(baseline.status, result.selected.status)


    def test_partial_downgrade_preserves_learned_source_identity(self):
        from source_parse import SourceEvent, ValueSpan

        raw = "prefix learned-value tail"
        parent = SourceEvent(raw, syntax="BASE")
        parent.vendor_fields = {"prefix": "prefix"}
        parent.value_spans = [ValueSpan("prefix", 0, 6, ("prefix",))]
        parent.primitive_fields = 1
        parent.covered = [(0, 6)]
        parent.unparsed = [(6, len(raw))]
        parent.issues = ["NO_SUPPORTED_GRAMMAR"]

        start = raw.index("learned-value")
        end = start + len("learned-value")
        candidate = SourceEvent(raw, syntax="RGRAM")
        candidate.vendor_fields = {"slot": "learned-value"}
        candidate.value_spans = [
            ValueSpan("rgram.slot_2", start, end, ("rgram", "slot_2"))
        ]
        candidate.primitive_fields = 1
        candidate.covered = [(0, len(raw))]

        partial = _partialize_learned_candidate(
            parent, candidate, hypothesis_name="rgram"
        )
        self.assertIsNotNone(partial)
        added = [
            span for span in partial.value_spans
            if span.start_byte == start and span.end_byte == end
        ]
        self.assertEqual(1, len(added))
        self.assertTrue(added[0].path.endswith("rgram.slot_2"))
        self.assertEqual(
            ("funnel_learned_partial", "rgram", "rgram.slot_2"),
            added[0].source_segments,
        )

    def test_beam_can_stack_two_nonoverlapping_layers_across_passes(self):
        from copy import deepcopy
        from unittest.mock import patch
        from bounded_funnel import BeamState, FunnelHypotheses, _beam_step
        from source_parse import SourceEvent, ValueSpan

        raw = "abcdefghij"
        base = SourceEvent(raw, syntax="BASE")
        base.vendor_fields = {"base": "a"}
        base.value_spans = [ValueSpan("base", 0, 1, ("base",))]
        base.primitive_fields = 1
        base.covered = [(0, 1)]
        base.unparsed = [(1, len(raw))]
        base.issues = ["NO_SUPPORTED_GRAMMAR"]

        def add_span(parent, name, start, end):
            out = deepcopy(parent)
            out.vendor_fields = deepcopy(parent.vendor_fields)
            out.vendor_fields[name] = raw[start:end]
            out.value_spans.append(
                ValueSpan(name, start, end, (name,))
            )
            out.primitive_fields = len(out.value_spans)
            return out

        def expansions(parent, _hypotheses, pass_index):
            paths = {span.path for span in parent.value_spans}
            if pass_index == 1 and "layer_a" not in paths:
                return [("layer:a", add_span(parent, "layer_a", 2, 3))]
            if pass_index == 2 and "layer_a" in paths and "layer_b" not in paths:
                return [("layer:b", add_span(parent, "layer_b", 4, 5))]
            return []

        hypotheses = FunnelHypotheses(None, {}, {}, {}, {}, {}, {})
        beam = [BeamState(base, ("baseline",))]
        with patch("bounded_funnel._whole_record_candidates", return_value=[]), patch(
            "bounded_funnel._learned_expansions", side_effect=expansions
        ):
            beam, improved1 = _beam_step(beam, hypotheses, 1, 4)
            beam, improved2 = _beam_step(beam, hypotheses, 2, 4)

        self.assertTrue(improved1)
        self.assertTrue(improved2)
        self.assertEqual(
            ("baseline", "layer:a", "layer:b"),
            beam[0].provenance,
        )
        self.assertEqual(
            {"base", "layer_a", "layer_b"},
            {span.path for span in beam[0].event.value_spans},
        )


if __name__ == "__main__":
    unittest.main()
