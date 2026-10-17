#!/usr/bin/env python3
"""Freeze blind source-grounded JSON truth and all unscorable originals.

The scorer and product parser are never imported here. The blind test group
is withheld from candidate-driven inspection until candidate code is frozen.
"""
import hashlib
import json
import os
from pathlib import Path

from generalizationJsonOracle import OracleInvalid, json_file_records, parse_json_event

STATE = Path.home() / ".local/state/parserstudio-generalization-blind-20261017"
PINS = Path(__file__).with_name("generalizationSources.pinned.json")
PUBLIC = Path(__file__).with_name("generalizationOracle.pinned.json")
SEALED = {"suricata_pcap", "log_zoo"}
JSON_EXTS = (".json", ".ndjson")
MAX_RECORDS = 2500


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def freeze_private(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError("Frozen oracle changed: " + path.name)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)


def records_for_file(file: dict, raw: bytes) -> list[tuple[bytes, str]]:
    source_path = file["source_path"]
    if source_path.endswith(JSON_EXTS):
        return json_file_records(raw)
    if source_path.endswith("sample.zeek.log"):
        return [(raw, "unscorable")]
    return [(line, "unscorable") for line in raw.splitlines() if line.strip()]


def main() -> None:
    pins_bytes = PINS.read_bytes()
    pins = json.loads(pins_bytes)
    if pins["stage"] != "PINNED_BEFORE_ANY_CANDIDATE_SCORING":
        raise RuntimeError("Source selection is not sealed")
    if pins["source_files"] != json.loads((STATE / "sources.pinned.json").read_bytes())["source_files"]:
        raise RuntimeError("Public/private source manifest mismatch")
    result = []
    per_family: dict[str, dict] = {}
    for file in pins["source_files"]:
        data = (STATE / "raw" / (file["id"] + ".bin")).read_bytes()
        if sha(data) != file["raw_sha256"] or len(data) != file["bytes"]:
            raise RuntimeError("Original source SHA/size changed: " + file["id"])
        originals = records_for_file(file, data)
        cursor = 0
        for ordinal, (raw, kind) in enumerate(originals):
            if len(result) >= MAX_RECORDS:
                raise RuntimeError("Bounded cohort size exhausted")
            pos = data.find(raw, cursor)
            if pos < cursor:
                raise RuntimeError("Source range could not be tied to original")
            cursor = pos + len(raw)
            try:
                decoded = raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                decoded = None
            fields = []
            reason = None
            if kind == "json" and decoded is not None:
                try:
                    fields = parse_json_event(raw)
                except (OracleInvalid, ValueError, UnicodeError):
                    reason = "JSON_INDEPENDENT_TRUTH_UNAVAILABLE"
            else:
                reason = "NO_INDEPENDENT_COMPLETE_FIELD_ORACLE" if decoded is not None else "UNDECODABLE_UTF8"
            record = {
                "id": f"{file['id']}-{ordinal:05d}",
                "family": file["family"],
                "split": "sealed_holdout" if file["family"] in SEALED else "development",
                "raw_event_sha256": sha(raw),
                "parent_file_sha256": file["raw_sha256"],
                "parent_byte_start": pos,
                "parent_byte_end": pos + len(raw),
                "format_hint": "json" if kind == "json" else "unqualified",
                "raw": decoded,
                "fields": fields,
                "oracle_status": "INDEPENDENT_JSON_BYTE_TRUTH" if fields else "UNSCORABLE",
                "exclusion": reason,
            }
            result.append(record)
            bucket = per_family.setdefault(file["family"], {
                "all_events": 0, "scorable_events": 0, "source_leaf_fields": 0, "unscorable_events": 0,
                "holdout": file["family"] in SEALED,
            })
            bucket["all_events"] += 1
            if fields:
                bucket["scorable_events"] += 1
                bucket["source_leaf_fields"] += len(fields)
            else:
                bucket["unscorable_events"] += 1
    normalized = (json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    freeze_private(STATE / "frozen-records-and-oracle.json", normalized)
    summary = {
        "schema": "blind-generalization-oracle-v1",
        "status": "FROZEN_BEFORE_BASELINE_OR_CANDIDATE_SCORING",
        "independent_semantics": "python_json_standard_decoder_crosschecked_with_independent_raw_byte_tokenizer",
        "source_manifest_sha256": sha(pins_bytes),
        "private_oracle_sha256": sha(normalized),
        "source_files": len(pins["source_files"]),
        "all_events": len(result),
        "scorable_events": sum(x["scorable_events"] for x in per_family.values()),
        "leaf_fields": sum(x["source_leaf_fields"] for x in per_family.values()),
        "unscorable_events": sum(x["unscorable_events"] for x in per_family.values()),
        "groups": per_family,
        "split_policy": "suricata_pcap_and_log_zoo_sealed_all_others_development",
        "candidate_access_to_sealed_truth": "prohibited_until_candidate_frozen",
        "nonjson_status": "UNSCORABLE_UNTIL_INDEPENDENT_FIELD_ORACLE",
        "claim_limit": "JSON_structural_source_fidelity_not_vendor_native_semantics",
    }
    frozen = (json.dumps(summary, indent=2) + "\n").encode()
    freeze_private(STATE / "oracle-summary.pinned.json", frozen)
    if PUBLIC.exists() and PUBLIC.read_bytes() != frozen:
        raise RuntimeError("Pinned public summary changed")
    PUBLIC.write_bytes(frozen)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
