"""Direct source extraction for three explicitly bounded Java log layouts.

Independent implementation from Apache PatternLayout syntax and published
Spark/ZooKeeper configuration examples. Not a universal Log4j decoder: only
these exact envelope layouts are admitted. The message remains a separate
source-parsing stage; no Drain/template/default-policy change is made here.
"""
from __future__ import annotations
from datetime import date
import re
from structured_source import Fragment

PREFIX=re.compile(
    r"^(?P<date>(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{2}/[0-9]{2}/[0-9]{2})) "
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[,.][0-9]{3})?)[ \t]+"
    r"(?:\[myid:(?P<node_id>[0-9]{0,12})\] - )?"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)[ \t]+"
)
LOGGER=r"[A-Za-z_$][A-Za-z0-9_.$]{0,255}"
SUFFIXES=(
    re.compile(r"\[(?P<context>[^\]\r\n]{1,512})\] - "),
    re.compile(r"\[(?P<thread>[^\]\r\n]{1,256})\][ \t]+(?P<logger>"+LOGGER+r"): "),
    re.compile(r"(?P<logger>"+LOGGER+r"): "),
)


def extract_java_envelope(raw:str)->tuple[Fragment,int]|None:
    if len(raw.encode("utf8"))>131072 or "\x00" in raw:
        return None
    prefix=PREFIX.match(raw)
    if prefix is None:return None
    stamp=prefix.group("date")
    try:
        if "-" in stamp:
            date.fromisoformat(stamp)
        else:
            # A two-digit year is preserved, never expanded/normalized.
            # Validate only possible month/day bounds; Feb 29 is allowed.
            _,month,day=(int(x) for x in stamp.split("/"))
            date(2000,month,day)
        hour,minute,second=(int(x) for x in prefix.group("time")[:8].split(":"))
        if hour>23 or minute>59 or second>59:return None
    except ValueError:
        return None
    suffix=None
    for pattern in SUFFIXES:
        suffix=pattern.match(raw,prefix.end())
        if suffix is not None:break
    if suffix is None:return None
    values={k:v for k,v in prefix.groupdict().items() if v is not None}
    values.update(suffix.groupdict())
    spans=[("java."+k,*prefix.span(k)) for k,v in prefix.groupdict().items() if v is not None]
    spans.extend(("java."+k,*suffix.span(k)) for k in suffix.groupdict())
    return Fragment(
        fields={"java":values},spans=spans,
        covered=[(0,suffix.end())],primitive_fields=len(values),
    ),suffix.end()
