"""Bounded Palo Alto PAN-OS TRAFFIC positional CSV promotion.

The generic source parser first proves comma-delimited column boundaries and
preserves every original value/span. This module only assigns the documented
TRAFFIC column names when the complete 53/54-column shape and several
independent type invariants agree. Unknown/other CSV remains positional.
"""
from __future__ import annotations
import re
from source_parse import SourceEvent,ValueSpan

PANOS_TRAFFIC_53=(
    'domain','receive_time','serial','type','subtype','config_version','time_generated',
    'src','dst','natsrc','natdst','rule','srcuser','dstuser','app','vsys','from','to',
    'inbound_if','outbound_if','logset','time_received','sessionid','repeatcnt','sport',
    'dport','natsport','natdport','flags','protocol','action','bytes','bytes_sent',
    'bytes_received','packets','start_time','elapsed','category','seqno','actionflags',
    'srcloc','dstloc','cpadding','pkts_sent','pkts_received','session_end_reason',
    'dg_hier_level_1','dg_hier_level_2','dg_hier_level_3','dg_hier_level_4',
    'vsys_name','device_name','action_source',
)
PANOS_TRAFFIC_54=PANOS_TRAFFIC_53[:38]+('padding',)+PANOS_TRAFFIC_53[38:]
DATE_TIME=re.compile(r'^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}$')
IPV4=re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
SAFE_PROTOCOL=re.compile(r'^[A-Za-z0-9_.-]{1,24}$')
SAFE_ACTION=re.compile(r'^[A-Za-z0-9_. -]{1,64}$')


def _ip(value:str)->bool:
    return bool(IPV4.fullmatch(value)) and all(0<=int(part)<=255 for part in value.split('.'))


def promote_panos_traffic_csv(event:SourceEvent)->SourceEvent|None:
    """Rename only a fully bounded positional PAN-OS TRAFFIC record."""
    if (
        'CSV' not in event.syntax or event.residual_bytes or
        any(issue!='UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION' for issue in event.issues)
    ):
        return None
    values=event.vendor_fields
    count=len(values)
    if count not in (53,54) or values.get('column_3')!='TRAFFIC':
        return None
    ordered=[str(values.get(f'column_{i}','')) for i in range(count)]
    if not all(DATE_TIME.fullmatch(ordered[i]) for i in (1,6,21,35)):
        return None
    if not all(_ip(ordered[i]) for i in (7,8,9,10)):
        return None
    for i in (24,25,26,27):
        value=ordered[i]
        if not value.isdigit() or not 0<=int(value)<=65535:
            return None
    if not SAFE_PROTOCOL.fullmatch(ordered[29]) or not SAFE_ACTION.fullmatch(ordered[30]):
        return None

    names=PANOS_TRAFFIC_54 if count==54 else PANOS_TRAFFIC_53
    promoted=SourceEvent(event.raw,syntax='PANOS_TRAFFIC_CSV')
    promoted.vendor_fields={'fields':dict(zip(names,ordered))}
    renamed=[]
    by_column={span.path:span for span in event.value_spans}
    for index,name in enumerate(names):
        span=by_column.get(f'column_{index}')
        if span is None:
            return None
        renamed.append(ValueSpan(
            'fields.'+name,span.start_byte,span.end_byte,('fields',name),
        ))
    promoted.value_spans=renamed
    promoted.covered=list(event.covered)
    promoted.primitive_fields=len(renamed)
    promoted.issues=[]
    promoted.unparsed=list(event.unparsed)
    return promoted
