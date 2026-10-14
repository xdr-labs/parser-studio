"""Conservative Cisco ASA/FTD message-id source extraction; never claim full prose parse."""
from __future__ import annotations
import re
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

ASA_ID=re.compile(r'%(ASA|FTD)-(\d)-(\d{6}):[ \t]*')
ASA_CONNECTION=re.compile(r'\b(?P<action>Built|Teardown) (?P<direction>inbound|outbound) (?P<protocol>TCP|UDP|ICMP) connection\b')
ASA_DENY=re.compile(r'(?P<action>Deny) (?P<protocol>tcp|udp|icmp) src\b')
ASA_CONNECTION_ID=re.compile(r'[ \t]+(?P<connection_id>[0-9]{1,20})(?=[ \t]|$)')
ASA_ADDRESS=r'[0-9A-Fa-f:.]{2,64}'
ASA_PORT=r'[0-9]{1,5}'
ASA_BUILT_FULL=re.compile(
    rf'\A(?P<action>Built) (?P<direction>inbound|outbound) (?P<protocol>TCP|UDP) connection '
    rf'(?P<connection_id>[0-9]{{1,20}}) for (?P<src_interface>[A-Za-z0-9_.:-]{{1,64}}):'
    rf'(?P<src_ip>{ASA_ADDRESS})/(?P<src_port>{ASA_PORT}) '
    rf'\((?P<mapped_src_ip>{ASA_ADDRESS})/(?P<mapped_src_port>{ASA_PORT})\) to '
    rf'(?P<dst_interface>[A-Za-z0-9_.:-]{{1,64}}):(?P<dst_ip>{ASA_ADDRESS})/(?P<dst_port>{ASA_PORT}) '
    rf'\((?P<mapped_dst_ip>{ASA_ADDRESS})/(?P<mapped_dst_port>{ASA_PORT})\)\Z')
ASA_DENY_FULL=re.compile(
    rf'\A(?P<action>Deny) (?P<protocol>tcp|udp|icmp) src '
    rf'(?P<src_interface>[A-Za-z0-9_.:-]{{1,64}}):(?P<src_ip>{ASA_ADDRESS})/(?P<src_port>{ASA_PORT}) dst '
    rf'(?P<dst_interface>[A-Za-z0-9_.:-]{{1,64}}):(?P<dst_ip>{ASA_ADDRESS})/(?P<dst_port>{ASA_PORT})\Z')

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
    body=raw[match.end():]
    full=ASA_BUILT_FULL.match(body) or ASA_DENY_FULL.match(body)
    if full is not None:
        # These message-ID bodies are fully delimited by Cisco's published token
        # structure. Keep exact source strings; do not infer any absent value.
        for name,value in full.groupdict().items():
            if value is None:continue
            a,b=full.span(name);a+=match.end();b+=match.end()
            tree[name]=value
            spans.append(ValueSpan('asa.'+name,len(raw[:a].encode()),len(raw[:b].encode()),('asa',name)))
        for name in ('src_port','dst_port','mapped_src_port','mapped_dst_port'):
            if name in tree and not 0<=int(tree[name])<=65535:
                full=None;break
    if full is None:
        # Conservative fallback: message ID + only independently recognizable
        # action/protocol tokens. Unknown prose remains explicit residual.
        tree={k:v for k,v in tree.items() if k in ('product','severity','message_id')}
        spans=[s for s in spans if s.source_segments and s.source_segments[-1] in ('product','severity','message_id')]
        conn=ASA_CONNECTION.match(body)
        if conn is not None:
            for name in ('action','direction','protocol'):
                value=conn.group(name)
                a,b=conn.span(name);a+=match.end();b+=match.end()
                tree[name]=value
                spans.append(ValueSpan('asa.'+name,len(raw[:a].encode()),len(raw[:b].encode()),('asa',name)))
            identifier=ASA_CONNECTION_ID.match(body,conn.end())
            if identifier is not None:
                a,b=identifier.span('connection_id');a+=match.end();b+=match.end()
                tree['connection_id']=identifier['connection_id']
                spans.append(ValueSpan('asa.connection_id',len(raw[:a].encode()),len(raw[:b].encode()),('asa','connection_id')))
        deny=ASA_DENY.match(body) if conn is None else None
        if deny is not None:
            for name in ('action','protocol'):
                a,b=deny.span(name);a+=match.end();b+=match.end()
                tree[name]=deny.group(name)
                spans.append(ValueSpan('asa.'+name,len(raw[:a].encode()),len(raw[:b].encode()),('asa',name)))
    event.vendor_fields={'asa':tree}
    event.value_spans=spans
    event.primitive_fields=len(spans)
    event.covered=[(match.start(),len(raw) if full is not None else match.end())]
    event.issues=[] if full is not None else ['ASA_MESSAGE_BODY_UNPARSED']
    event.syntax='CISCO_ASA_FTD_MESSAGE_ID_FULL' if full is not None else event.syntax
    event=_close(event)
    assert_source_accounting(event)
    return event
