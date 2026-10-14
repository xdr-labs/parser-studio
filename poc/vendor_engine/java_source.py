"""Direct source extraction for explicitly bounded Java log envelopes.

The extra timestamp/level separator is admitted only for bracketed-context
layouts. Source-backed context atoms supplement, never replace, the exact
visible context. Unrecognized bodies remain a separate partial parsing stage.
"""
from __future__ import annotations
from datetime import date
import re
from structured_source import Fragment

PREFIX=re.compile(
    r"^(?P<date>(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{2}/[0-9]{2}/[0-9]{2})) "
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[,.][0-9]{3})?)[ \t]+"
    r"(?P<dash>- )?(?:\[myid:(?P<node_id>[0-9]{0,12})\] - )?"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)[ \t]+"
)
LOGGER=r"[A-Za-z_$][A-Za-z0-9_.$]{0,255}"
CONTEXT_ATOMS=re.compile(
    r"(?P<thread>.{1,256}):(?P<logger>"+LOGGER+r")@(?P<line_number>[0-9]{1,9})\Z"
)
SUFFIXES=(
    re.compile(r"\[(?P<thread>[^\]\r\n]{1,256})\][ \t]+(?P<logger>"+LOGGER+r"): "),
    re.compile(r"(?P<logger>"+LOGGER+r"): "),
)


def _context(raw:str,start:int):
    """Balanced outer context, bounded nesting; never scan into a message."""
    if raw[start:start+1]!='[':return None
    depth=1;cursor=start+1
    while cursor<len(raw) and cursor-start<=513:
        char=raw[cursor]
        if ord(char)<32 or ord(char)==127:return None
        if char=='[':
            depth+=1
            if depth>8:return None
        elif char==']':
            depth-=1
            if depth==0:
                if cursor==start+1 or raw[cursor+1:cursor+4]!=' - ':return None
                text=raw[start+1:cursor]
                values={'context':text}
                spans=[('java.context',start+1,cursor)]
                atoms=CONTEXT_ATOMS.fullmatch(text)
                if atoms is not None:
                    # Multiple colon boundaries admit competing thread/logger
                    # interpretations. Keep the whole exact context and only
                    # the anchored numeric suffix; never infer semantic atoms.
                    names=('thread','logger','line_number') if text.count(':')==1 else ('line_number',)
                    values.update((key,atoms.group(key)) for key in names)
                    spans.extend(('java.'+key,start+1+atoms.start(key),start+1+atoms.end(key))
                                 for key in names)
                return values,spans,cursor+4
        cursor+=1
    return None


def extract_java_envelope(raw:str)->tuple[Fragment,int]|None:
    if len(raw.encode('utf8'))>131072 or '\x00' in raw:return None
    prefix=PREFIX.match(raw)
    if prefix is None:return None
    stamp=prefix.group('date')
    try:
        if '-' in stamp:date.fromisoformat(stamp)
        else:
            # Preserve a two-digit year without inventing its century.
            _,month,day=(int(x) for x in stamp.split('/'))
            date(2000,month,day)
        hour,minute,second=(int(x) for x in prefix.group('time')[:8].split(':'))
        if hour>23 or minute>59 or second>59:return None
    except ValueError:return None
    suffix=_context(raw,prefix.end())
    if suffix is None:
        if prefix.group('dash') is not None:return None
        for pattern in SUFFIXES:
            match=pattern.match(raw,prefix.end())
            if match is not None:
                suffix=(match.groupdict(),[('java.'+key,*match.span(key)) for key in match.groupdict()],match.end())
                break
    if suffix is None:return None
    values={key:prefix.group(key) for key in ('date','time','node_id','level') if prefix.group(key) is not None}
    spans=[('java.'+key,*prefix.span(key)) for key in values]
    values.update(suffix[0]);spans.extend(suffix[1]);end=suffix[2]
    return Fragment(fields={'java':values},spans=spans,
                    covered=[(0,end)],primitive_fields=len(values)),end
