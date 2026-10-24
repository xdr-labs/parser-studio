"""Strict, documented, yearless text-log envelopes; no invented timestamp or body semantics.

Recognizes Android logcat threadtime and bracketed application/target activity
messages when their full headers match. These are *source extraction* only:
message remains unchanged, no event year/timezone/action is inferred.
"""
from __future__ import annotations

from datetime import datetime
import re

from engine import MAX_RAW_BYTES
from source_parse import SourceEvent, ValueSpan, _span, _close


# Android's logcat -v threadtime producer fields:
# MM-DD HH:MM:SS.mmm  PID  TID P Tag: message
LOGCAT = re.compile(
    r"(?P<month_day>[0-9]{2}-[0-9]{2}) "
    r"(?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3})[ \t]+"
    r"(?P<pid>[0-9]{1,7})[ \t]+(?P<tid>[0-9]{1,7}) "
    r"(?P<priority>[VDIWEFS]) "
    r"(?P<tag>[A-Za-z0-9_.$/\-]{1,96}): "
    r"(?P<message>[^\r\n]{1,4096})"
)
# Bracketed month.day clock + application - hostname:port message. This is a
# general, delimited source format used by Proxifier; user-facing action is
# strictly retained as opaque message, never guessed as a security verdict.
ACTIVITY = re.compile(
    r"\[(?P<month_day>[0-9]{2}\.[0-9]{2}) (?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2})\] "
    r"(?P<application>[A-Za-z0-9_.+\-]{1,96}(?: \*64)?) - "
    r"(?P<target_host>[A-Za-z0-9_][A-Za-z0-9_.\-]{0,254}):"
    r"(?P<target_port>[0-9]{1,5}) "
    r"(?P<message>[^\r\n]{1,4096})"
)


def _clock_valid(month_day:str, clock:str, separator:str)->bool:
    try:
        month,day=(int(v) for v in month_day.split(separator))
        # 2000 permits leap-day without inferring which event year was used.
        datetime(2000,month,day)
        h,m,s=(int(v) for v in clock.split('.')[0].split(':'))
        return 0<=h<24 and 0<=m<60 and 0<=s<60
    except (ValueError,OverflowError):
        return False


def parse_yearless_documented_envelope(raw:str)->SourceEvent|None:
    """Return a strict complete source envelope, or None for prior safe parsers."""
    if not isinstance(raw,str) or not raw or '\x00' in raw or len(raw.encode('utf8'))>MAX_RAW_BYTES:
        return None
    match=LOGCAT.fullmatch(raw)
    if match is not None:
        if not _clock_valid(match['month_day'],match['clock'],'-'):
            return None
        fields=match.groupdict()
        # PIDs and TIDs are numeric producer identifiers, not inferred actors.
        fields['pid']=int(fields['pid'])
        fields['tid']=int(fields['tid'])
        syntax='ANDROID_LOGCAT_THREADTIME'
    else:
        match=ACTIVITY.fullmatch(raw)
        if match is None or not _clock_valid(match['month_day'],match['clock'],'.'):
            return None
        port=int(match['target_port'])
        if port<1 or port>65535:return None
        fields=match.groupdict()
        fields['target_port']=port
        syntax='BRACKETED_MONTH_DAY_APPLICATION_TARGET'

    # Header fields are definite, but free-text message roles are not. Even
    # with full byte accounting this must remain PARTIAL for human/AI review.
    out=SourceEvent(raw,syntax=syntax,vendor_fields=fields,primitive_fields=len(fields),
                    issues=['FREE_TEXT_FIELD_ROLES_NEED_REVIEW'])
    out.covered.append((0,len(raw)))
    for key in fields:
        first,last=match.span(key)
        span=_span(raw,key,first,last)
        out.value_spans.append(ValueSpan(span.path,span.start_byte,span.end_byte,(key,)))
    return _close(out)
