#!/usr/bin/env python3
"""Digest-only, offline field-level baseline and MDL-proxy shadow scoreboard.

Synthetic examples check harness correctness, NOT measured vendor accuracy.
An independent vendor oracle must be supplied separately before product gating.
No source text, field name/value pairs or private golden are emitted.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "multipass"))
from accuracy_shadow import choose_shadow
from bounded_funnel import FunnelConfig, FunnelHypotheses, run_funnel_batch, run_funnel_event
from multipass_contract import CandidateEvidence, candidate_from_event

FIXTURE = ROOT / "tests" / "fixtures" / "field-accuracy-synthetic-v1.json"
EVIDENCE = CandidateEvidence(
    parser_id="accuracy-research-observer",
    profile_id="field-accuracy-shadow",
    grammar_id=None,
    evidence_tier="HEURISTIC_RESIDUAL",
    independently_qualified=False,
    source_revision="20261022-shadow-only",
)
EMPTY_HYPOTHESES = FunnelHypotheses(None, {}, {}, {}, {}, {}, {})


def _value_id(value: object) -> str:
    return type(value).__name__ + ":" + json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _expected_claim(claim: dict) -> tuple:
    return (
        claim["path"], claim["occurrence"], _value_id(claim["value"]),
        claim["startByte"], claim["endByte"],
    )


def _actual_claim(occ: object) -> tuple:
    return (
        occ.display_path, occ.occurrence, _value_id(occ.value),
        occ.start_byte, occ.end_byte,
    )


def validate_fixture(path: Path) -> tuple[dict, str]:
    source = path.read_bytes()
    document = json.loads(source.decode("utf8", "strict"))
    if document.get("schema") != "parser-studio.field-accuracy-oracle.v0.1":
        raise ValueError("INVALID_ORACLE_SCHEMA")
    if not document.get("provenance"):
        raise ValueError("MISSING_ORACLE_PROVENANCE")
    if not isinstance(document.get("cases"), list) or not document["cases"]:
        raise ValueError("EMPTY_ORACLE")
    seen: set[str] = set()
    for entry in document["cases"]:
        name = entry["id"]
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError("DUPLICATE_OR_INVALID_CASE")
        seen.add(name)
        if entry.get("oracleScope") not in ("COMPLETE", "UNSCORABLE"):
            raise ValueError("INVALID_ORACLE_SCOPE")
        if not isinstance(entry.get("family"), str) or not entry["family"]:
            raise ValueError("ORACLE_FAMILY_MISSING")
        raw = entry["raw"].encode("utf8", "strict")
        if len(raw) > 65536:
            raise ValueError("ORACLE_SOURCE_TOO_LARGE")
        fields = entry.get("fields")
        if not isinstance(fields, list):
            raise ValueError("ORACLE_FIELDS_INVALID")
        if entry["oracleScope"] == "UNSCORABLE" and fields:
            raise ValueError("UNSCORABLE_CANNOT_PROVIDE_PARTIAL_PRECISION_GOLDEN")
        claims = Counter()
        for claim in fields:
            a, b = claim["startByte"], claim["endByte"]
            if not 0 <= a <= b <= len(raw):
                raise ValueError("ORACLE_FIELD_BOUNDARY_INVALID")
            try:
                source_lexeme = raw[a:b].decode("utf8", "strict")
                raw[:a].decode("utf8", "strict")
                raw[:b].decode("utf8", "strict")
            except UnicodeError as exc:
                raise ValueError("ORACLE_FIELD_UTF8_SPLIT") from exc
            if source_lexeme != claim["rawLexeme"]:
                raise ValueError("ORACLE_LEXEME_MISMATCH")
            if not isinstance(claim["path"], str) or not claim["path"]:
                raise ValueError("ORACLE_FIELD_NAME_MISSING")
            if not isinstance(claim["occurrence"], int) or claim["occurrence"] < 0:
                raise ValueError("ORACLE_OCCURRENCE_INVALID")
            claims[_expected_claim(claim)] += 1
        if any(count != 1 for count in claims.values()):
            raise ValueError("DUPLICATE_ORACLE_CLAIM")
    return document, sha256(source).hexdigest()


def compare_candidate(candidate: object, entry: dict) -> dict:
    expected = Counter(_expected_claim(item) for item in entry["fields"])
    actual = Counter(_actual_claim(item) for item in candidate.occurrences)
    matched = sum((expected & actual).values())
    fp = sum((actual - expected).values())
    fn = sum((expected - actual).values())
    false_complete = candidate.completeness == "SOURCE_PARSED" and bool(fp or fn)
    return {"tp": matched, "fp": fp, "fn": fn, "false_complete": false_complete}


def summarize(rows: list[dict]) -> dict:
    tp = sum(row["tp"] for row in rows)
    fp = sum(row["fp"] for row in rows)
    fn = sum(row["fn"] for row in rows)
    # A family with no positives or false claims has undefined field F1:
    # do not inflate macro averages with a vacuous perfect score.
    if tp + fp + fn == 0:
        precision = recall = f1 = None
    else:
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 6) if precision is not None else None,
        "recall": round(recall, 6) if recall is not None else None,
        "f1": round(f1, 6) if f1 is not None else None,
        "false_complete": sum(row["false_complete"] for row in rows),
    }


def run(path: Path) -> dict:
    doc, digest = validate_fixture(path)
    scored_product: list[dict] = []
    scored_pool_first: list[dict] = []
    scored_shadow: list[dict] = []
    families: dict[str, dict[str, list[dict]]] = defaultdict(
        lambda: {"product": [], "pool_first": [], "shadow": []}
    )
    reviewed: list[dict] = []
    changes = 0
    audits_rejected = 0
    missing_snapshots = 0
    total_candidates = 0

    for entry in doc["cases"]:
        raw = entry["raw"]
        family = entry["family"]
        product_event = run_funnel_batch([raw]).selected[0]
        observed = run_funnel_event(
            raw, EMPTY_HYPOTHESES, config=FunnelConfig(beam_width=4)
        )
        try:
            product = candidate_from_event(product_event, EVIDENCE)
            frozen = candidate_from_event(observed.baseline, EVIDENCE)
            pool = [candidate_from_event(state.event, EVIDENCE)
                    for state in observed.beam]
            if not pool:
                pool = [frozen]
            # Include the immutable baseline for an explicit abstention choice.
            if all(candidate.occurrences != frozen.occurrences for candidate in pool):
                pool.append(frozen)
            choice = choose_shadow(raw, pool, frozen)
            total_candidates += len(pool)
            audits_rejected += sum(not item.valid for item in choice.scores)
            if choice.selected_index is None:
                if entry["oracleScope"] == "COMPLETE":
                    raise RuntimeError("COMPLETE_ORACLE_WITHOUT_VALID_SHADOW")
                missing_snapshots += 1
                reviewed.append({"case_id_digest": sha256(entry["id"].encode()).hexdigest()[:12], "reason": "NO_VALID_SHADOW_CANDIDATE"})
                continue
            shadow = pool[choice.selected_index]
            first = pool[0]
            if choice.selected_index != 0:
                changes += 1
            if entry["oracleScope"] == "COMPLETE":
                p = compare_candidate(product, entry)
                b = compare_candidate(first, entry)
                s = compare_candidate(shadow, entry)
                scored_product.append(p)
                scored_pool_first.append(b)
                scored_shadow.append(s)
                families[family]["product"].append(p)
                families[family]["pool_first"].append(b)
                families[family]["shadow"].append(s)
            else:
                reviewed.append({"case_id_digest": sha256(entry["id"].encode()).hexdigest()[:12], "reason": "UNSCORABLE_ORACLE"})
        except (ValueError, IndexError, KeyError, TypeError, AssertionError):
            # Never shrink the scorable denominator because a candidate
            # crashed or its extracted occurrences could not be resolved.
            if entry["oracleScope"] == "COMPLETE":
                raise RuntimeError("COMPLETE_ORACLE_CANDIDATE_UNSCORABLE") from None
            missing_snapshots += 1
            reviewed.append({"case_id_digest": sha256(entry["id"].encode()).hexdigest()[:12], "reason": "CANDIDATE_SNAPSHOT_UNSCORABLE"})

    family_report = {
        name: {
            key: summarize(group[key])
            for key in ("product", "pool_first", "shadow")
        } for name, group in sorted(families.items())
    }
    return {
        "contract": "parser-studio.field-accuracy-mdl-shadow.v0.1",
        "provenance": doc["provenance"],
        "oracle_sha256": digest,
        "cases": len(doc["cases"]),
        "scorable_cases": len(scored_product),
        "unscorable_or_error_cases": len(reviewed),
        "errors_or_review": reviewed,
        "candidate_count": total_candidates,
        "hard_audit_rejections": audits_rejected,
        "shadow_changed_selected_candidate": changes,
        "product_single_event_baseline": summarize(scored_product),
        "fixed_pool_first_candidate": summarize(scored_pool_first),
        "same_pool_mdl_proxy_shadow": summarize(scored_shadow),
        "per_family": family_report,
        "holdout_independent_vendor_oracle": False,
        "manufacturer_wide_accuracy_claim": False,
        "runtime_or_export_modified": False,
        "confidence_calibration": "NOT_EVALUATED",
        "latency_p99": "INSUFFICIENT_SAMPLE",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline field accuracy shadow research; digest-only stdout")
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    args = parser.parse_args()
    print(json.dumps(run(args.fixture), sort_keys=True, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
