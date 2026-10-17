#!/usr/bin/env python3
"""Freeze candidate source before one-time scoring on separately sealed holdouts."""
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
CANDIDATE = HERE / "src/poc/boundedStructuralSourceSpans.ts"
STATE = Path.home() / ".local/state/parserstudio-generalization-blind-20261017"
TARGET = STATE / "candidate-frozen.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    pinned = json.loads((STATE / "oracle-summary.pinned.json").read_text())
    development = json.loads((STATE / "bounded-candidate-development.json").read_text())
    baseline = json.loads((STATE / "baseline-v3-development.json").read_text())
    cand_sha = sha(CANDIDATE)
    assert development["candidate_sha256"] == cand_sha
    assert pinned["private_oracle_sha256"] == development["reference_sha256"]
    assert baseline["reference_manifest_sha"] == development["reference_sha256"]
    assert development["total"]["scorable"] == baseline["total"]["scorable"] == 40
    assert development["total"]["tp"] == baseline["total"]["baselineValueTP"] == 1302
    assert development["total"]["fp"] == development["total"]["fn"] == 0
    assert development["total"]["autoPromotions"] == 0
    seal = {"candidate_source_sha256": cand_sha,
            "independent_oracle_sha256": pinned["private_oracle_sha256"],
            "source_pins_sha256": pinned["source_manifest_sha256"],
            "status": "CANDIDATE_FROZEN_BEFORE_SEALED_HOLDOUT_SCORING",
            "qualification": "isolated_source_span_review_only"}
    content = (json.dumps(seal, indent=2) + "\n").encode()
    if TARGET.exists():
        if TARGET.read_bytes() != content:
            raise RuntimeError("Previously frozen candidate changed")
    else:
        fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
    print(json.dumps({"frozen": True,
                      "candidate_sha256": cand_sha,
                      "oracle_sha256": pinned["private_oracle_sha256"]}))


if __name__ == "__main__":
    main()
