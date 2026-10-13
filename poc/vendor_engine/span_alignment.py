"""Bounded, source-accurate token-template capture proposal.

Extracts only positional residual variable spans from a frozen Drain3-style
<*>/<:IP:>/<:NUMBER:> template. Never infers security/Dictionary meanings,
never labels template matches as verified field parsing, and rejects ambiguous
anchor layouts instead of returning the first regex or substring match.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import re

TOKEN = re.compile(r"<(\*|:[A-Za-z][A-Za-z0-9_]{0,19}:)>")
MAX_VARIABLES = 16
MAX_BODY_BYTES = 8192
MAX_VARIABLE_CHARS = 256
MAX_TRIALS = 4096
ALLOWED_MASKS = {"*", "IP", "NUMBER", "NUM", "UUID"}
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")
NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?\Z")


@dataclass(frozen=True)
class Capture:
    path: str
    mask: str
    value: str
    start_byte: int
    end_byte: int


@dataclass(frozen=True)
class Alignment:
    status: str
    captures: tuple[Capture, ...] = ()


def _parse_template(template: str) -> tuple[list[str], list[str]] | None:
    literals: list[str] = []
    masks: list[str] = []
    last = 0
    for matched in TOKEN.finditer(template):
        literal = template[last:matched.start()]
        # Unknown templating meta-syntax must never turn into an unsafe
        # partial pattern match with silently treated-as-literal syntax.
        if "<" in literal or ">" in literal:
            return None
        literals.append(literal)
        mask = matched[1].strip(":")
        if mask not in ALLOWED_MASKS:
            return None
        masks.append(mask)
        last = matched.end()
    suffix = template[last:]
    if "<" in suffix or ">" in suffix:
        return None
    literals.append(suffix)
    return literals, masks


def _typed_match(mask: str, value: str, *, allow_empty: bool = False) -> bool:
    if not value:
        return allow_empty and mask == "*"
    if len(value) > MAX_VARIABLE_CHARS or not value.strip() or "\x00" in value:
        return False
    if mask == "IP":
        try:
            ip_address(value)
            return True
        except ValueError:
            return False
    if mask in ("NUM", "NUMBER"):
        return NUMBER_RE.fullmatch(value) is not None
    if mask == "UUID":
        return UUID_RE.fullmatch(value) is not None
    return True


def align_template(
    template: str,
    body: str,
    *,
    raw: str | None = None,
    body_start_char: int = 0,
    cluster_support: int = 2,
    trusted_profile: bool = False,
) -> Alignment:
    """Propose exact byte-offset captures; reject non-unique alignments.

    The body must be an unchanged slice of raw beginning at body_start_char.
    Source offsets are UTF-8 bytes even for multibyte text. The template is
    frozen train-only; neither fitting nor substring generation occurs here.
    """
    if not isinstance(template, str) or not isinstance(body, str):
        raise TypeError("TEMPLATE_AND_BODY_MUST_BE_TEXT")
    if len(body.encode("utf8")) > MAX_BODY_BYTES or cluster_support < 2:
        return Alignment("ABSTAIN_UNQUALIFIED_CLUSTER")
    if raw is not None and (body_start_char < 0 or raw[body_start_char:body_start_char + len(body)] != body):
        return Alignment("SOURCE_SLICE_MISMATCH")
    parsed = _parse_template(template)
    if parsed is None:
        return Alignment("UNSUPPORTED_TEMPLATE_SYNTAX")
    literals, masks = parsed
    max_variables = 24 if trusted_profile else MAX_VARIABLES
    if not masks or len(masks) > max_variables:
        return Alignment("ABSTAIN_NO_BOUNDED_VARIABLES")
    if any(not literal for literal in literals[1:-1]):
        return Alignment("ABSTAIN_ADJACENT_VARIABLES")
    stable_anchors = sum(bool(s.strip()) for s in literals)
    static_chars = sum(len(s.strip()) for s in literals)
    # A train-labeled, source-verified template may use one sufficiently
    # distinctive anchored literal if seen in >= 2 independent train rows.
    # This relaxation is NEVER used for raw unsupervised Drain3 clusters.
    if trusted_profile:
        if stable_anchors < 1 or static_chars < 12:
            return Alignment("ABSTAIN_WEAK_ANCHORS")
    elif stable_anchors < 2 or static_chars < 8:
        return Alignment("ABSTAIN_WEAK_ANCHORS")
    if not body.startswith(literals[0]):
        return Alignment("NO_EXACT_ANCHORED_MATCH")

    found: list[list[tuple[int, int, str]]] = []
    trials = 0
    # Count distinct positional alignments. Never memoize only the current
    # offset: different earlier captures could converge to the same offset,
    # and memoization would hide ambiguity. Bounded trial count prevents DoS.

    def recurse(i: int, start: int, spans: list[tuple[int, int, str]]) -> None:
        nonlocal trials
        if len(found) > 1 or trials >= MAX_TRIALS:
            return
        target_literal = literals[i + 1]
        if not target_literal:
            # Empty final literal: the last variable extends to EOL.
            if i + 1 != len(masks):
                return
            end = len(body)
            if _typed_match(masks[i], body[start:end], allow_empty=trusted_profile):
                found.append(spans + [(start, end, masks[i])])
            return
        cursor = start
        # A variable cannot extend more than MAX_VARIABLE_CHARS to the next
        # literal. Never iterate through an unbounded regex search space.
        maximum = min(len(body), start + MAX_VARIABLE_CHARS + len(target_literal))
        while cursor < maximum:
            next_start = body.find(target_literal, cursor, maximum + 1)
            if next_start < 0:
                break
            trials += 1
            value = body[start:next_start]
            if _typed_match(masks[i], value, allow_empty=trusted_profile):
                next_offset = next_start + len(target_literal)
                record = spans + [(start, next_start, masks[i])]
                if i + 1 == len(masks):
                    if next_offset == len(body):
                        found.append(record)
                else:
                    recurse(i + 1, next_offset, record)
            if len(found) > 1 or trials >= MAX_TRIALS:
                break
            cursor = next_start + 1

    recurse(0, len(literals[0]), [])
    if trials >= MAX_TRIALS:
        return Alignment("ABSTAIN_SEARCH_BOUND")
    if len(found) > 1:
        return Alignment("AMBIGUOUS_ANCHOR_LAYOUT")
    if not found:
        return Alignment("NO_EXACT_ANCHORED_MATCH")
    offsets = found[0]
    original = raw if raw is not None else body
    base = body_start_char if raw is not None else 0
    source_bytes = original.encode("utf8")
    captures: list[Capture] = []
    for i, (start, end, mask) in enumerate(offsets):
        pos_a = len(original[:base + start].encode("utf8"))
        pos_b = len(original[:base + end].encode("utf8"))
        value = body[start:end]
        if source_bytes[pos_a:pos_b].decode("utf8") != value:
            return Alignment("SOURCE_BYTE_MISMATCH")
        if pos_a != pos_b:
            captures.append(Capture(f"residual.variable_{i}", mask, value, pos_a, pos_b))
    return Alignment("SOURCE_SPAN_CANDIDATE_ONLY", tuple(captures))
