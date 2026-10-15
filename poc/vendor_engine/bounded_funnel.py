"""Bounded accuracy-first Funnel orchestration for the Auto Parser product.

The qualified Multi-Pass / Generic Structural engine remains the immutable
baseline. Funnel adds bounded parser fan-out, residual-only recovery,
cross-event structural learning, replay, and deterministic no-loss selection.
Runtime is deliberately not an acceptance metric.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from typing import Callable, Iterable

from generic_structural_poc import parse_generic_structural
from multipass_adjudicator import parse_security_multipass, parse_security_once
from security_asa import parse_asa_message
from security_cef import parse_security_cef
from security_juniper import parse_juniper_rtflow_profile
from security_leef import parse_security_leef
from security_meraki import parse_meraki_profile
from security_sonicwall import parse_sonicwall_host_kv
from security_source import parse_security_source
from security_watchguard import parse_watchguard_profile
from source_parse import SourceEvent, ValueSpan, assert_source_accounting
from structural_funnel import (
    augment_partial_with_extended_bsd_envelope,
    augment_partial_with_numeric_prefix,
    augment_partial_with_residual_typed_labels,
    delete_required_delimited_anchors,
    delete_required_rgram_literal,
    delete_required_template_anchor,
    learn_best_hypothesis,
    learn_csv_cell_label_hypotheses,
    learn_event_template_hypotheses,
    learn_extended_bsd_envelope_hypotheses,
    learn_leading_numeric_hypotheses,
    learn_relative_rgram_hypotheses,
    learn_residual_typed_label_hypotheses,
    merge_residual_hypothesis,
    parse_extended_bsd_envelope,
    parse_leading_numeric_slots,
    parse_with_event_template,
    parse_with_hypothesis,
    parse_with_relative_rgram,
    refine_csv_cell_labels,
)

MAX_PASSES = 6
MAX_BEAM = 4
MAX_CHILDREN_PER_REGION = 8
MAX_BATCH_EVENTS = 500
DEFAULT_BEAM = 1


@dataclass(frozen=True)
class FunnelConfig:
    max_passes: int = MAX_PASSES
    beam_width: int = DEFAULT_BEAM

    def __post_init__(self) -> None:
        if not 1 <= self.max_passes <= MAX_PASSES:
            raise ValueError("FUNNEL_PASS_BOUND")
        if not 1 <= self.beam_width <= MAX_BEAM:
            raise ValueError("FUNNEL_BEAM_BOUND")


@dataclass(frozen=True)
class FunnelHypotheses:
    delimited: object | None
    templates: dict
    rgrams: dict
    numeric: dict
    csv_labels: dict
    extended_bsd: dict
    typed_labels: dict


@dataclass(frozen=True)
class BeamState:
    event: SourceEvent
    provenance: tuple[str, ...]


@dataclass(frozen=True)
class FunnelResult:
    baseline: SourceEvent
    selected: SourceEvent
    beam: tuple[BeamState, ...]
    passes_run: int
    stopped_no_improvement: bool

    @property
    def added_spans(self) -> int:
        return max(0, len(self.selected.value_spans) - len(self.baseline.value_spans))


def _claim(span: ValueSpan) -> tuple:
    return (span.path, span.source_segments, span.start_byte, span.end_byte)


def _claims(event: SourceEvent) -> set[tuple]:
    return {_claim(span) for span in event.value_spans}


def _span_ranges(event: SourceEvent) -> set[tuple[int, int]]:
    return {(span.start_byte, span.end_byte) for span in event.value_spans}


def _state_signature(state: BeamState) -> tuple:
    event = state.event
    return (
        event.status,
        tuple(sorted(_claims(event))),
        tuple(event.unparsed),
        tuple(event.issues),
    )


def _score(event: SourceEvent) -> tuple:
    # Source recall first. Runtime is intentionally absent.
    status_rank = {"RAW_ONLY": 0, "STRUCTURED_EMPTY": 0, "PARTIAL": 1, "SOURCE_PARSED": 2}.get(event.status, 0)
    return (
        len(_claims(event)),
        -event.residual_bytes,
        status_rank,
        -len(event.issues),
    )


def _strict_no_loss(parent: SourceEvent, child: SourceEvent) -> bool:
    try:
        assert_source_accounting(parent)
        assert_source_accounting(child)
    except (AssertionError, ValueError, TypeError):
        return False
    if child.raw != parent.raw:
        return False
    if not _claims(parent) <= _claims(child):
        return False
    return True


def _improves(parent: SourceEvent, child: SourceEvent) -> bool:
    if not _strict_no_loss(parent, child):
        return False
    return _score(child) > _score(parent)


def _whole_record_candidates(raw: str) -> list[tuple[str, SourceEvent]]:
    """Run independent qualified/strict parser families on the same raw source."""
    out: list[tuple[str, SourceEvent]] = []

    def add(name: str, value: SourceEvent | None) -> None:
        if value is None:
            return
        try:
            assert_source_accounting(value)
        except (AssertionError, ValueError, TypeError):
            return
        if value.raw == raw and value.vendor_fields:
            out.append((name, value))

    add("source", parse_security_source(raw))
    add("cef", parse_security_cef(raw, base_parser=parse_security_source))
    add("leef", parse_security_leef(raw, base_parser=parse_security_source))
    add("generic", parse_generic_structural(raw))
    add("asa", parse_asa_message(raw))
    add("meraki", parse_meraki_profile(raw))
    add("watchguard", parse_watchguard_profile(raw))
    add("juniper", parse_juniper_rtflow_profile(raw))
    add("sonicwall", parse_sonicwall_host_kv(raw))

    # Stable de-duplication by extraction, not parser name.
    seen: set[tuple] = set()
    unique: list[tuple[str, SourceEvent]] = []
    for name, event in out:
        sig = (
            event.status,
            tuple(sorted(_claims(event))),
            tuple(event.unparsed),
            tuple(event.issues),
        )
        if sig not in seen:
            seen.add(sig)
            unique.append((name, event))
    return unique[:MAX_CHILDREN_PER_REGION]


def _byte_to_char(raw: str, byte_offset: int) -> int | None:
    if not 0 <= byte_offset <= len(raw.encode("utf8")):
        return None
    total = 0
    for index, char in enumerate(raw):
        if total == byte_offset:
            return index
        total += len(char.encode("utf8"))
    return len(raw) if total == byte_offset else None


def _residual_byte_ranges(event: SourceEvent) -> list[tuple[int, int, int, int]]:
    out = []
    for char_start, char_end in event.unparsed:
        if not 0 <= char_start < char_end <= len(event.raw):
            continue
        byte_start = len(event.raw[:char_start].encode("utf8"))
        byte_end = len(event.raw[:char_end].encode("utf8"))
        out.append((char_start, char_end, byte_start, byte_end))
    return out


def _add_residual_child(
    parent: SourceEvent,
    child: SourceEvent,
    *,
    char_start: int,
    byte_start: int,
    parser_name: str,
    pass_index: int,
    region_index: int,
) -> SourceEvent | None:
    """Add exact child values inside one residual; never certify completeness."""
    if child.status != "SOURCE_PARSED" or not child.value_spans:
        return None
    if child.raw != parent.raw[char_start:char_start + len(child.raw)]:
        return None

    parent_claims = _claims(parent)
    parent_ranges = _span_ranges(parent)
    shifted: list[ValueSpan] = []
    tree_values: dict[str, str] = {}
    raw_bytes = parent.raw.encode("utf8")

    for index, span in enumerate(child.value_spans):
        start = byte_start + span.start_byte
        end = byte_start + span.end_byte
        if not byte_start <= start < end <= byte_start + len(child.raw.encode("utf8")):
            return None
        if (start, end) in parent_ranges:
            continue
        # Residual fan-out is additive only; do not reinterpret accepted spans.
        if any(max(start, old.start_byte) < min(end, old.end_byte) for old in parent.value_spans):
            return None
        key = f"value_{index}"
        tree_values[key] = raw_bytes[start:end].decode("utf8")
        shifted.append(
            ValueSpan(
                f"funnel_residual.p{pass_index}.r{region_index}.{parser_name}.{key}",
                start,
                end,
                ("funnel_residual", f"p{pass_index}", f"r{region_index}", parser_name, key),
            )
        )

    if not shifted:
        return None

    result = deepcopy(parent)
    result.vendor_fields = deepcopy(parent.vendor_fields)
    bucket = result.vendor_fields.setdefault("funnel_residual", {})
    bucket[f"p{pass_index}_r{region_index}_{parser_name}"] = tree_values
    result.value_spans.extend(shifted)
    result.value_spans.sort(key=lambda s: (s.start_byte, s.end_byte, s.path))
    result.primitive_fields = len(result.value_spans)
    result.syntax = parent.syntax + f"+FUNNEL_RESIDUAL_{parser_name.upper()}"
    # Deliberately keep parent issues/unparsed. This pass recovers values only.
    assert_source_accounting(result)
    if result.status == "SOURCE_PARSED":
        return None
    if not parent_claims <= _claims(result):
        return None
    return result


def _residual_fanout(parent: SourceEvent, pass_index: int) -> list[tuple[str, SourceEvent]]:
    if parent.status == "SOURCE_PARSED":
        return []
    if any("LIMIT" in issue or "SIZE_OR_NUL" in issue for issue in parent.issues):
        return []
    out: list[tuple[str, SourceEvent]] = []
    for region_index, (char_start, char_end, byte_start, _byte_end) in enumerate(_residual_byte_ranges(parent)):
        piece = parent.raw[char_start:char_end]
        if not piece:
            continue
        for parser_name, child in _whole_record_candidates(piece):
            # Generic Structural is intentionally observation-only on a bare
            # residual. Broad security controls found that a locally complete
            # Generic segmentation can atomize an opaque vendor payload: exact
            # source accounting alone is not enough to prove field boundaries.
            # Generic remains available as a whole-record qualified parser and
            # through cross-event learned hypotheses; it is not directly
            # admitted from one residual sample.
            if parser_name == "generic":
                continue
            candidate = _add_residual_child(
                parent,
                child,
                char_start=char_start,
                byte_start=byte_start,
                parser_name=parser_name,
                pass_index=pass_index,
                region_index=region_index,
            )
            if candidate is not None and _improves(parent, candidate):
                out.append((f"residual:{parser_name}", candidate))
    return out


def learn_funnel_hypotheses(
    training_raws: Iterable[str],
    training_events: Iterable[SourceEvent],
) -> FunnelHypotheses:
    raws = list(training_raws)
    events = list(training_events)
    # R-gram intentionally uses the less-postprocessed single-pass structural
    # view because its residual signature is evidence, not a final result.
    rgram_views = [parse_security_once(raw) for raw in raws]
    return FunnelHypotheses(
        delimited=learn_best_hypothesis(raws),
        templates=learn_event_template_hypotheses(raws),
        rgrams=learn_relative_rgram_hypotheses(rgram_views),
        numeric=learn_leading_numeric_hypotheses(raws),
        csv_labels=learn_csv_cell_label_hypotheses(events),
        extended_bsd=learn_extended_bsd_envelope_hypotheses(raws),
        typed_labels=learn_residual_typed_label_hypotheses(events),
    )


def _generic_adversarial_mutations(raw: str, structural: str | None = None) -> list[str]:
    if len(raw) < 8:
        candidates = [raw + "\x00"]
    else:
        cut60 = max(1, int(len(raw) * 0.60))
        cut80 = max(1, int(len(raw) * 0.80))
        left = max(1, int(len(raw) * 0.45))
        right = min(len(raw) - 1, max(left + 1, int(len(raw) * 0.55)))
        candidates = [
            raw[:cut60],
            raw[:cut80],
            raw[:left] + raw[right:],
            raw[: len(raw) // 2] + "\x00" + raw[len(raw) // 2 :],
        ]
    if structural is not None and structural != raw:
        candidates.append(structural)
    return list(dict.fromkeys(item for item in candidates if item != raw))


def _partialize_learned_candidate(
    parent: SourceEvent,
    candidate: SourceEvent | None,
    *,
    hypothesis_name: str,
) -> SourceEvent | None:
    """Keep proven residual values when whole-record completeness is unproven.

    The learned candidate may have useful exact source spans even when an
    adversarial mutation shows that its whole-record grammar is too permissive
    to certify SOURCE_PARSED. In that case, retain only values fully contained
    in the parent's residual byte ranges, preserve all baseline claims/issues,
    and deliberately keep the event incomplete.
    """
    if candidate is None or parent.status == "SOURCE_PARSED":
        return None
    if candidate.raw != parent.raw:
        return None
    if any("LIMIT" in issue or "SIZE_OR_NUL" in issue for issue in parent.issues):
        return None
    try:
        assert_source_accounting(parent)
        assert_source_accounting(candidate)
    except (AssertionError, ValueError, TypeError):
        return None

    residual_ranges = [
        (byte_start, byte_end)
        for _char_start, _char_end, byte_start, byte_end
        in _residual_byte_ranges(parent)
    ]
    if not residual_ranges:
        return None
    existing_ranges = _span_ranges(parent)
    additions: list[ValueSpan] = []
    raw_bytes = parent.raw.encode("utf8")
    values: dict[str, str] = {}
    for span in candidate.value_spans:
        key = (span.start_byte, span.end_byte)
        if key in existing_ranges:
            continue
        if any(
            max(span.start_byte, old.start_byte) < min(span.end_byte, old.end_byte)
            for old in parent.value_spans
        ):
            return None
        if not any(
            start <= span.start_byte < span.end_byte <= end
            for start, end in residual_ranges
        ):
            continue
        # Preserve the learned candidate source identity across a partial
        # downgrade. A later validation/replay pass must still know that this
        # exact byte span came from its learned structural slot.
        source_identity = span.path
        if not source_identity or len(source_identity) > 192:
            return None
        if source_identity in values:
            return None
        values[source_identity] = raw_bytes[span.start_byte:span.end_byte].decode("utf8")
        additions.append(
            ValueSpan(
                f"funnel_learned_partial.{hypothesis_name}.{source_identity}",
                span.start_byte,
                span.end_byte,
                ("funnel_learned_partial", hypothesis_name, source_identity),
            )
        )
    if not additions:
        return None

    result = deepcopy(parent)
    result.vendor_fields = deepcopy(parent.vendor_fields)
    bucket = result.vendor_fields.setdefault("funnel_learned_partial", {})
    bucket[hypothesis_name] = values
    result.value_spans.extend(additions)
    result.value_spans.sort(key=lambda span: (span.start_byte, span.end_byte, span.path))
    result.primitive_fields = len(result.value_spans)
    result.syntax = parent.syntax + "+FUNNEL_LEARNED_" + hypothesis_name.upper() + "_PARTIAL"
    assert_source_accounting(result)
    if result.status == "SOURCE_PARSED" or not _claims(parent) <= _claims(result):
        return None
    return result


def _guard_complete_candidate(
    parent: SourceEvent,
    merged: SourceEvent | None,
    *,
    parse_candidate: Callable[[str], SourceEvent | None],
    structural_mutation: str | None = None,
) -> SourceEvent | None:
    """Per-event adversarial proof gate for any learned complete promotion."""
    if merged is None or merged.status != "SOURCE_PARSED":
        return None
    for mutated in _generic_adversarial_mutations(parent.raw, structural_mutation):
        mutated_parent = parse_security_multipass(mutated)
        if mutated_parent.status == "SOURCE_PARSED":
            # Not a funnel-created false complete; the qualified baseline already
            # accepts this source independently.
            continue
        try:
            mutated_candidate = parse_candidate(mutated)
            mutated_merged = merge_residual_hypothesis(
                mutated_parent, mutated_candidate
            )
        except (AssertionError, ValueError, TypeError, KeyError, IndexError):
            mutated_merged = None
        if mutated_merged is not None:
            return None
    return merged


def _learned_expansions(
    parent: SourceEvent,
    hypotheses: FunnelHypotheses,
    pass_index: int,
) -> list[tuple[str, SourceEvent]]:
    raw = parent.raw
    out: list[tuple[str, SourceEvent]] = []

    def add(name: str, candidate: SourceEvent | None) -> None:
        if candidate is not None and _improves(parent, candidate):
            out.append((name, candidate))

    # Complete candidates. They must preserve every parent claim and can only
    # add values from parent residuals through merge_residual_hypothesis.
    if hypotheses.delimited is not None:
        structural = delete_required_delimited_anchors(raw, hypotheses.delimited)
        candidate = parse_with_hypothesis(raw, hypotheses.delimited)
        add(
            "learned:delimited",
            _guard_complete_candidate(
                parent,
                merge_residual_hypothesis(parent, candidate),
                parse_candidate=lambda mutated: parse_with_hypothesis(
                    mutated, hypotheses.delimited
                ),
                structural_mutation=structural,
            ),
        )
    if hypotheses.templates:
        structural = delete_required_template_anchor(raw, hypotheses.templates)
        candidate = parse_with_event_template(raw, hypotheses.templates)
        add(
            "learned:template",
            _guard_complete_candidate(
                parent,
                merge_residual_hypothesis(parent, candidate),
                parse_candidate=lambda mutated: parse_with_event_template(
                    mutated, hypotheses.templates
                ),
                structural_mutation=structural,
            ),
        )
    if hypotheses.rgrams:
        view = parse_security_once(raw)
        structural = delete_required_rgram_literal(raw, view, hypotheses.rgrams)
        candidate = parse_with_relative_rgram(raw, view, hypotheses.rgrams)
        merged = merge_residual_hypothesis(parent, candidate)
        guarded = _guard_complete_candidate(
            parent,
            merged,
            parse_candidate=lambda mutated: parse_with_relative_rgram(
                mutated, parse_security_once(mutated), hypotheses.rgrams
            ),
            structural_mutation=structural,
        )
        if guarded is not None:
            add("learned:rgram", guarded)
        elif merged is not None:
            # A failed completeness proof does not invalidate independently
            # learned source boundaries. Keep residual-only values, but never
            # claim the event is fully parsed.
            add(
                "partial-learned:rgram",
                _partialize_learned_candidate(
                    parent, candidate, hypothesis_name="rgram"
                ),
            )

    # Partial-only exact-span recovery.
    if hypotheses.numeric:
        add(
            "partial:numeric",
            augment_partial_with_numeric_prefix(
                parent, parse_leading_numeric_slots(raw, hypotheses.numeric)
            ),
        )
    if hypotheses.csv_labels:
        add("partial:csv-label", refine_csv_cell_labels(parent, hypotheses.csv_labels))
    if hypotheses.extended_bsd:
        add(
            "partial:extended-bsd",
            augment_partial_with_extended_bsd_envelope(
                parent, parse_extended_bsd_envelope(raw, hypotheses.extended_bsd)
            ),
        )
    if hypotheses.typed_labels:
        add(
            "partial:typed-label",
            augment_partial_with_residual_typed_labels(parent, hypotheses.typed_labels),
        )

    out.extend(_residual_fanout(parent, pass_index))
    return out


def _beam_step(
    beam: list[BeamState],
    hypotheses: FunnelHypotheses,
    pass_index: int,
    beam_width: int,
) -> tuple[list[BeamState], bool]:
    expanded = list(beam)
    before_signatures = {_state_signature(state) for state in beam}
    for state in beam:
        parent = state.event
        # Existing SOURCE_PARSED results are immutable product truth. Funnel
        # never reinterprets or replaces their fields, spans, or tree.
        if parent.status == "SOURCE_PARSED":
            continue

        # Existing whole-record parsers also compete as strict no-loss complete
        # hypotheses rather than winner-takes-all guesses.
        if parent.status != "SOURCE_PARSED":
            for parser_name, candidate in _whole_record_candidates(parent.raw):
                merged = merge_residual_hypothesis(parent, candidate)
                if merged is not None and _improves(parent, merged):
                    expanded.append(
                        BeamState(merged, state.provenance + (f"whole:{parser_name}",))
                    )

        for name, candidate in _learned_expansions(parent, hypotheses, pass_index):
            expanded.append(BeamState(candidate, state.provenance + (name,)))

    # Keep structurally distinct states. Score only affects beam survival; no
    # conflicting candidates are blindly merged.
    unique: dict[tuple, BeamState] = {}
    for state in expanded:
        sig = _state_signature(state)
        prior = unique.get(sig)
        if prior is None or len(state.provenance) < len(prior.provenance):
            unique[sig] = state
    ranked = sorted(
        unique.values(),
        key=lambda state: (_score(state.event), -len(state.provenance)),
        reverse=True,
    )
    selected = ranked[:beam_width]
    improved = any(_state_signature(state) not in before_signatures for state in selected)
    return selected, improved


def run_funnel_event(
    raw: str,
    hypotheses: FunnelHypotheses,
    *,
    config: FunnelConfig = FunnelConfig(),
) -> FunnelResult:
    baseline = parse_security_multipass(raw)
    assert_source_accounting(baseline)
    if baseline.status == "SOURCE_PARSED":
        frozen = deepcopy(baseline)
        return FunnelResult(
            baseline=baseline,
            selected=frozen,
            beam=(BeamState(frozen, ("baseline:multipass",)),),
            passes_run=0,
            stopped_no_improvement=True,
        )
    beam = [BeamState(deepcopy(baseline), ("baseline:multipass",))]
    stopped = False
    passes = 0
    for pass_index in range(1, config.max_passes + 1):
        next_beam, improved = _beam_step(
            beam, hypotheses, pass_index, config.beam_width
        )
        passes = pass_index
        beam = next_beam
        if not improved:
            stopped = True
            break
    selected = beam[0].event
    if not _strict_no_loss(baseline, selected):
        selected = deepcopy(baseline)
    return FunnelResult(
        baseline=baseline,
        selected=selected,
        beam=tuple(beam),
        passes_run=passes,
        stopped_no_improvement=stopped,
    )


def replay_training(
    raws: list[str],
    *,
    config: FunnelConfig = FunnelConfig(),
) -> tuple[FunnelHypotheses, list[SourceEvent], int]:
    """Train/replay only on the training partition; evaluation never feeds back."""
    current = [parse_security_multipass(raw) for raw in raws]
    last_hypotheses = learn_funnel_hypotheses(raws, current)
    passes = 0
    for pass_index in range(1, config.max_passes + 1):
        passes = pass_index
        hypotheses = learn_funnel_hypotheses(raws, current)
        next_events: list[SourceEvent] = []
        improved = False
        for raw, prior in zip(raws, current):
            # Start each replay from the current train state to allow later
            # hypotheses to build on earlier exact additions.
            beam = [BeamState(deepcopy(prior), ("train-replay",))]
            next_beam, event_improved = _beam_step(
                beam, hypotheses, pass_index, config.beam_width
            )
            selected = next_beam[0].event
            next_events.append(selected)
            improved = improved or event_improved
        current = next_events
        last_hypotheses = hypotheses
        if not improved:
            break
    # Learn once more from the final training state; this frozen bundle is used
    # for evaluation and is never changed by evaluation results.
    last_hypotheses = learn_funnel_hypotheses(raws, current)
    return last_hypotheses, current, passes

@dataclass(frozen=True)
class FunnelBatchResult:
    baselines: tuple[SourceEvent, ...]
    selected: tuple[SourceEvent, ...]
    hypotheses: FunnelHypotheses
    passes_run: int


def run_funnel_batch(
    raws: Iterable[str],
    *,
    config: FunnelConfig = FunnelConfig(),
) -> FunnelBatchResult:
    """Learn and replay within one bounded Auto Parser sample batch.

    This is the product batch path: all events are first parsed by the qualified
    Multi-Pass engine, structural hypotheses are learned from that same local
    batch, and replay is bounded by config.max_passes. Every output fails
    closed to its baseline if raw/source accounting or no-loss checks fail.
    """
    items = list(raws)
    if not 1 <= len(items) <= MAX_BATCH_EVENTS:
        raise ValueError("FUNNEL_BATCH_BOUND")
    baselines = [parse_security_multipass(raw) for raw in items]
    for baseline in baselines:
        assert_source_accounting(baseline)

    hypotheses, replayed, passes = replay_training(items, config=config)
    selected: list[SourceEvent] = []
    for baseline, candidate in zip(baselines, replayed):
        try:
            assert_source_accounting(candidate)
        except (AssertionError, ValueError, TypeError):
            selected.append(deepcopy(baseline))
            continue
        if baseline.status == "SOURCE_PARSED":
            selected.append(deepcopy(baseline))
            continue
        if not _strict_no_loss(baseline, candidate):
            selected.append(deepcopy(baseline))
            continue
        selected.append(candidate)

    return FunnelBatchResult(
        baselines=tuple(baselines),
        selected=tuple(selected),
        hypotheses=hypotheses,
        passes_run=passes,
    )


def parse_security_funnel(
    raw: str,
    *,
    config: FunnelConfig = FunnelConfig(),
) -> SourceEvent:
    """Single-event Auto Parser entry point using the same bounded Funnel."""
    return run_funnel_batch([raw], config=config).selected[0]
