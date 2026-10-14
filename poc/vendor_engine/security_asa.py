"""Conservative Cisco ASA/FTD message-id source extraction; never claim full prose parse."""
from __future__ import annotations
import re
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

ASA_ID=re.compile(r'%(ASA|FTD)-(\d)-(\d{6}):[ \t]*')
ASA_CONNECTION=re.compile(r'\b(?P<action>Built|Teardown) (?P<direction>inbound|outbound) (?P<protocol>TCP|UDP|ICMP) connection\b')

def parse_asa_message(raw:str)->SourceEvent|None:
    if not isinstance(raw,str):return None
    found=list(ASA_ID.finditer(raw))
    if len(found)!=1:return None
    match=found[0]
    # Only a complete, bounded, line-delimited event may own an ASA message ID.
    if '\n' in raw or '\r' in raw or len(raw.encode('utf8'))>131072:return None
    event=SourceEvent(raw,syntax='CISCO_ASA_FTD_MESSAGE_ID')
    tree={};spans=[]
    for name,index in [('product',1),('severity',2),('message_id',3)]:
        value=match.group(index);a,b=match.span(index)
        tree[name]=value
        spans.append(ValueSpan('asa.'+name,len(raw[:a].encode()),len(raw[:b].encode()),('asa',name)))
    # Independently visible ASA connection grammar; message text remains residual.
    body=raw[match.end():]
    conn=ASA_CONNECTION.match(body)
    if conn is not None:
        for name in ('action','direction','protocol'):
            value=conn.group(name)
            a,b=conn.span(name);a+=match.end();b+=match.end()
            tree[name]=value
            spans.append(ValueSpan('asa.'+name,len(raw[:a].encode()),len(raw[:b].encode()),('asa',name)))
    event.vendor_fields={'asa':tree}
    event.value_spans=spans
    event.primitive_fields=len(spans)
    event.covered=[(match.start(),match.end())]
    event.issues=['ASA_MESSAGE_BODY_UNPARSED']
    event=_close(event)
    assert_source_accounting(event)
    return event
