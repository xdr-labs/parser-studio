"""Deterministic read-only security field role suggestions with abstention.

No normalization, source event mutation, Stellar target adapter or runtime
integration. Only anchored, unambiguous literal network arrow evidence may
produce roles; ambiguous context yields ABSTAIN and retains vendor fields.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

_IPV4 = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
_PATTERN = re.compile(
    rf"^\s*(?P<src_ip>{_IPV4}):(?P<src_port>[0-9]{{1,5}})"
    rf"\s*(?P<arrow>->|=>)\s*"
    rf"(?P<dst_ip>{_IPV4}):(?P<dst_port>[0-9]{{1,5}})"
    rf"(?:\s+(?:TCP|UDP))?(?:\s+(?:allow|deny))?\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RoleSuggestion:
    role: str
    value: str
    start_byte: int
    end_byte: int
    evidence_id: str


@dataclass(frozen=True)
class RoleDecision:
    state: str
    suggestions: tuple[RoleSuggestion, ...]
    reason: str


def infer_directional_roles(raw: str) -> RoleDecision:
    """Only exact standalone IPv4:port -> IPv4:port with bounded ports."""
    if not isinstance(raw, str) or len(raw.encode("utf8")) > 65536:
        return RoleDecision("ABSTAIN", (), "SOURCE_UNSUPPORTED")
    match = _PATTERN.fullmatch(raw)
    if match is None:
        return RoleDecision("ABSTAIN", (), "NO_UNAMBIGUOUS_DIRECTION_EVIDENCE")
    try:
        for part in ("src_ip", "dst_ip"):
            ipaddress.IPv4Address(match.group(part))
        for part in ("src_port", "dst_port"):
            port = int(match.group(part))
            if not 0 <= port <= 65535:
                raise ValueError("INVALID_PORT")
    except ValueError:
        return RoleDecision("ABSTAIN", (), "INVALID_NETWORK_TYPE")
    suggestions = []
    for group, role in (("src_ip", "srcip"), ("src_port", "srcport"),
                        ("dst_ip", "dstip"), ("dst_port", "dstport")):
        a, b = match.span(group)
        suggestions.append(RoleSuggestion(
            role=role,
            value=match.group(group),
            start_byte=len(raw[:a].encode("utf8")),
            end_byte=len(raw[:b].encode("utf8")),
            evidence_id="EXACT_STANDALONE_IPV4_PORT_DIRECTION_ARROW_V1",
        ))
    return RoleDecision("EVIDENCED_SUGGESTION_REVIEW_ONLY", tuple(suggestions),
                        "DIRECTIONAL_ARROW_SOURCE_SPANS_VERIFIED")
