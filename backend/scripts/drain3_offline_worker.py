#!/usr/bin/env python3
"""P1-AP5: bounded one-shot Drain3 training/holdout process.

MIT-licensed Drain3 0.9.11 is a separately installed and pinned dependency.
The trusted Python code is fixed. Log records are untrusted. No user-provided
Python, Regex, masking rules, imports, file paths or persistence are accepted.
Only fixed status/counts and aggressively sanitized token classes are returned.
"""
import json
import os
import re
import resource
import sys

# Apply process budgets before importing optional third-party code.
resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))

# Prevent accidental egress even if an optional library changes behavior.
import socket

def network_denied(*args, **kwargs):
    raise RuntimeError("NETWORK_DISABLED")

socket.socket = network_denied
socket.create_connection = network_denied

ALLOWED = frozenset({
    "ERROR", "WARN", "WARNING", "DEBUG", "INFO", "TRACE", "FATAL",
    "LOGIN", "LOGOUT", "ALLOW", "DENY", "FAILED", "SUCCESS", "GET",
    "POST", "PUT", "PATCH", "DELETE", "HTTP", "HTTPS", "TCP", "UDP",
    "SRC", "DST", "IP", "PORT", "USER", "STATUS", "TIME", "ID",
})
HEX_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
NUMERIC = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
PUNCTUATION = re.compile(r"^[|=,:;{}()[\]<>*]+$")
UUID = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9-]{27,}$")

def fail(reason):
    sys.stdout.write(json.dumps({"ok": False, "error": reason},
                                separators=(",", ":")) + "\n")
    return None

def strict(value, maximum):
    return (
        isinstance(value, list) and 0 <= len(value) <= maximum
        and all(
            isinstance(x, str) and 0 < len(x.encode("utf-8")) <= 2048
            and "\x00" not in x and "\r" not in x and "\n" not in x
            for x in value
        )
    )

def sanitized_word(token):
    if token == "<*>":
        return "<VAR>"
    if token.upper() in ALLOWED and token.isascii():
        return token.upper()
    if HEX_IP.fullmatch(token):
        return "<IP>"
    if NUMERIC.fullmatch(token):
        return "<NUM>"
    if UUID.fullmatch(token):
        return "<UUID>"
    if PUNCTUATION.fullmatch(token) and len(token) <= 5:
        return "<PUNCT>"
    return "<WORD>"

def sanitize_template(template):
    parts = str(template).split()
    if not parts or len(parts) > 48:
        return None
    return " ".join(sanitized_word(token) for token in parts)

def run():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            return fail("INPUT_TOO_LARGE")
        input_data = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(input_data, dict) or set(input_data) != {
            "contract", "training", "holdout",
        } or input_data["contract"] != "parser-studio.drain3-input.v0.1":
            return fail("UNTRUSTED_INPUT")
        train = input_data["training"]
        holdout = input_data["holdout"]
        if not strict(train, 500) or not strict(holdout, 500) or not train:
            return fail("UNTRUSTED_INPUT")
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
        config = TemplateMinerConfig()
        config.drain_max_clusters = 32
        config.drain_max_children = 32
        config.drain_depth = 4
        config.drain_sim_th = 0.6
        config.profiling_enabled = False
        config.snapshot_interval_minutes = 1000000
        # No persistence prevents source snapshots or output files.
        miner = TemplateMiner(persistence_handler=None, config=config)
        training_lines = {}
        for index, event in enumerate(train):
            result = miner.add_log_message(event)
            key = result["cluster_id"]
            training_lines.setdefault(key, []).append(index + 1)
        holdout_matches = {}
        matched_total = 0
        for event in holdout:
            cluster = miner.match(event)
            if cluster is not None:
                matched_total += 1
                holdout_matches[cluster.cluster_id] = (
                    holdout_matches.get(cluster.cluster_id, 0) + 1
                )
        groups = []
        for cluster in miner.drain.clusters:
            shape = sanitize_template(cluster.get_template())
            if shape is None:
                continue
            groups.append({
                "clusterId": "cluster-" + str(cluster.cluster_id),
                "shape": shape,
                "trainingCount": len(training_lines.get(cluster.cluster_id, [])),
                "trainingLineNumbers": training_lines.get(cluster.cluster_id, []),
                "holdoutMatches": holdout_matches.get(cluster.cluster_id, 0),
                "reviewOnly": True,
            })
        groups.sort(key=lambda value: (
            -value["trainingCount"], value["clusterId"]))
        return {
            "ok": True,
            "contract": "parser-studio.drain3-reviewed-hints.v0.1",
            "engine": "Drain3 0.9.11",
            "sourceCount": len(train),
            "accounted": sum(len(v) for v in training_lines.values()),
            "holdoutCount": len(holdout),
            "holdoutMatched": matched_total,
            "groupCount": len(groups),
            "groups": groups,
            "persisted": False,
            "sourceValuesIncluded": False,
            "nativeParserVerified": False,
            "targetImportVerified": False,
        }
    except (ImportError, ModuleNotFoundError):
        return fail("DRAIN3_NOT_INSTALLED")
    except Exception:
        # No exception text: it could contain customer values or code paths.
        return fail("MINER_UNAVAILABLE")

if __name__ == "__main__":
    result = run()
    if result is not None:
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
