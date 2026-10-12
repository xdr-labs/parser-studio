"""Fail-closed structural and Ruby provenance gate for disposable POC writes.

Only a synthetic project from an explicitly pinned Parser Studio Ruby template
may be sent to the owner-approved POC. This is a structural guard, NOT a
general-purpose Ruby security sandbox or a vendor runtime attestation.
"""

import base64
import hashlib
import json
import re

# Exact canonical template bytes at the following backend Git revisions,
# NOT arbitrary "file hash" values from user-supplied manifests.
# Backend commit 687be44; backend commit 7457e29. A future compiler revision
# must be separately reviewed and explicitly added here.
REVIEWED_TEMPLATE_SHA256 = frozenset({
    "e56812e5efd75ddc255e0813ecbd02f675bfb7b85928b35ff0db6b472791044e",
    "e941f631da790103cc4c53a89e2eebca2b5df470300935690ebd3450d2e4e911",
})
B64_CALL = re.compile(
    r"Base64\.strict_decode64\('([A-Za-z0-9+/=]{8,35000})'\)"
)
CANONICAL_PLACEHOLDER = "__PARSER_PROJECT_B64__"
MAX_IR_BYTES = 24000


class UnsafeDisposablePair(ValueError):
    """Raised when a disposable synthetic pair is not fully attested."""


def parse_disposable_conf(conf_bytes: bytes, name: str, port: int) -> tuple[str, ...]:
    """Accept a tiny exact-line grammar, not loose regex matches in a document.

    Sources: one or two UDP/TCP loopback sources, same port, same name.
    Output: one exact-name null sink. No Fluentd filters/exec/labels/includes
    or any other block/directive can appear anywhere in this configuration.
    """
    try:
        text = conf_bytes.decode("utf-8")
    except (UnicodeError, AttributeError):
        raise UnsafeDisposablePair("Non-UTF8 or missing disposable configuration") from None
    if "\0" in text or "\r" in text or len(text) > 12000:
        raise UnsafeDisposablePair("Unsupported characters or size in disposable config")
    lines = []
    for original in text.split("\n"):
        item = original.strip()
        if not item or item.startswith("#"):
            continue
        if len(item) > 180 or not item.isascii():
            raise UnsafeDisposablePair("Unexpected config directive format")
        lines.append(item)
    pos = 0
    protocols = []
    while pos < len(lines) and lines[pos] == "<source>":
        if len(protocols) >= 2:
            raise UnsafeDisposablePair("Too many disposable listeners")
        if pos + 8 >= len(lines):
            raise UnsafeDisposablePair("Truncated source block")
        type_line = lines[pos + 1]
        if type_line not in ("@type udp", "@type tcp"):
            raise UnsafeDisposablePair("Only UDP/TCP disposable receivers are allowed")
        protocol = type_line.split(" ")[1]
        expected = (
            "<source>", type_line, "bind 127.0.0.1", f"port {port}",
            f"tag {name}", "<parse>", f"@type {name}", "</parse>", "</source>",
        )
        if tuple(lines[pos:pos + len(expected)]) != expected:
            raise UnsafeDisposablePair("Unexpected listener/parse directive in test config")
        if protocol in protocols:
            raise UnsafeDisposablePair("Duplicate disposable protocol")
        protocols.append(protocol)
        pos += len(expected)
    if not protocols:
        raise UnsafeDisposablePair("Missing disposable source")
    final_block = (f"<match {name}.**>", "@type null", "</match>")
    if tuple(lines[pos:]) != final_block:
        raise UnsafeDisposablePair("Unknown Fluentd content outside sources/null sink")
    return tuple(protocols)


def _reject_json_duplicates(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate embedded IR key")
        output[key] = value
    return output


def check_reviewed_synthetic_ruby(
    ruby_bytes: bytes,
    name: str,
    port: int,
    protocols: tuple[str, ...],
    reviewed_templates=REVIEWED_TEMPLATE_SHA256,
) -> str:
    """Pin the exact Ruby wrapper while validating the only variable: JSON IR.

    The base64-decoded project is still ordinary data; Ruby code can only
    originate from a known committed template fingerprint.
    """
    if not isinstance(ruby_bytes, bytes) or not 0 < len(ruby_bytes) <= 512_000:
        raise UnsafeDisposablePair("Unsupported synthetic Ruby payload")
    try:
        raw = ruby_bytes.decode("utf-8")
    except UnicodeError:
        raise UnsafeDisposablePair("Non-UTF8 synthetic Ruby payload") from None
    found = list(B64_CALL.finditer(raw))
    if len(found) != 1:
        raise UnsafeDisposablePair("Ruby source is not a single known compiler template")
    match = found[0]
    normalized = raw[:match.start(1)] + CANONICAL_PLACEHOLDER + raw[match.end(1):]
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if digest not in reviewed_templates:
        raise UnsafeDisposablePair("Ruby template fingerprint is not allowlisted")
    try:
        decoded = base64.b64decode(match.group(1), validate=True)
        if len(decoded) > MAX_IR_BYTES:
            raise ValueError("oversized embedded project")
        project = json.loads(decoded, object_pairs_hook=_reject_json_duplicates)
    except (ValueError, UnicodeError, TypeError):
        raise UnsafeDisposablePair("Malformed embedded synthetic parser project") from None
    if not isinstance(project, dict):
        raise UnsafeDisposablePair("Unexpected synthetic project format")
    receiver = project.get("receiver")
    if (
        project.get("projectId") != "synthetic-fixture"
        or project.get("schemaRevision") != "0.1"
        or project.get("vendor") != "Synthetic"
        or project.get("slug") != name.removeprefix("customized_")
        or not isinstance(receiver, dict)
        or receiver.get("port") != port
        or receiver.get("bindAddress") != "127.0.0.1"
        or not isinstance(receiver.get("protocols"), list)
        or tuple(receiver["protocols"]) != protocols
    ):
        raise UnsafeDisposablePair("Synthetic IR disagrees with disposable CONF/name/port")
    return digest


def validate_disposable_pair(plan, *, reviewed_templates=REVIEWED_TEMPLATE_SHA256) -> str:
    protocols = parse_disposable_conf(plan.conf_bytes, plan.name, plan.port)
    return check_reviewed_synthetic_ruby(
        plan.parser_bytes, plan.name, plan.port, protocols, reviewed_templates,
    )
