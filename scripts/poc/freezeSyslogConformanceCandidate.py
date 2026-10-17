#!/usr/bin/env python3
"""Seal the accuracy candidate after development, before a distinct source holdout."""
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
STATE = Path.home() / ".local/state/parserstudio-syslog-conformance-20261017"
SOURCE = HERE / "src/poc/generalSyslogEnvelopeSpans.ts"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    oracle = json.loads((STATE / "oracle-summary.v3.pinned.json").read_text())
    baseline = json.loads((STATE / "baseline-development.json").read_text())
    candidate_sha = sha(SOURCE)
    candidate = json.loads(
        (STATE / f"candidate-development-{candidate_sha[:12]}.json").read_text()
    )
    if (candidate["candidate_source_sha"] != candidate_sha or
        candidate["reference_sha"] != oracle["private_oracle_sha256"] or
        baseline["reference_sha"] != oracle["private_oracle_sha256"]):
        raise RuntimeError("Candidate or independent reference was not pinned")
    now, before = candidate["total"], baseline["total"]
    if not (now["scorable"] == before["scorable"] == 39 and
            now["fields"] == before["sourceFields"] == 261 and
            now["tp"] == 261 and now["fp"] == now["fn"] == 0 and
            now["exactEvents"] == 39 and
            now["reviewedKnownInvalid"] == 0 and
            now["negative"] == before["negative"] == 79 and
            now["autoPromotions"] == 0 and now["rawPreserved"] == 121):
        raise RuntimeError("New generic grammar is not qualified even for development")
    record = {
        "state": "FROZEN_AFTER_DEV_BEFORE_SEALED_HOLDOUT",
        "candidate_sha256": candidate_sha,
        "reference_sha256": oracle["private_oracle_sha256"],
        "source_manifest_sha256": oracle["source_manifest_sha256"],
        "baseline_dev_tp": before["tp"],
        "candidate_dev_tp": now["tp"],
        "baseline_dev_fn": before["fn"],
        "candidate_dev_fn": now["fn"],
        "candidate_invalid_reviews": now["reviewedKnownInvalid"],
        "no_vendor_specific_repair": True,
        "not_authorized_for_product": True,
    }
    content = (json.dumps(record, indent=2) + "\n").encode()
    target = STATE / "candidate-frozen.json"
    if target.exists():
        if target.read_bytes() != content:
            raise RuntimeError("Previously sealed candidate must not change")
    else:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(content)
    print(json.dumps({"sealed": True, "candidate_sha256": candidate_sha,
                      "private_oracle_sha256": oracle["private_oracle_sha256"]}))


if __name__ == "__main__":
    main()
