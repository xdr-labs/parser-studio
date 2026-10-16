export interface CiscoFirewallEnvelope{
  product:'ASA'|'FTD';
  severity:string;
  message_id:string;
  message:string;
  source_raw:string;
}

const STRICT_MESSAGE_IDS=new Set([
  '106023',
  '302013','302014','302015','302016',
]);

export function parseCiscoFirewallEnvelope(raw:string):CiscoFirewallEnvelope|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  const match=/^%?(ASA|FTD)-([0-7])-(\d{6}):[ \t]+(.+)$/.exec(raw);
  if(!match)return null;
  if(STRICT_MESSAGE_IDS.has(match[3]!))return null;
  const message=match[4]!;
  if(!message.trim()||new TextEncoder().encode(message).byteLength>4096)return null;
  if(/%?(?:ASA|FTD)-[0-7]-\d{6}:[ \t]+/.test(message))return null;
  return {
    product:match[1] as 'ASA'|'FTD',
    severity:match[2]!,
    message_id:match[3]!,
    message,
    source_raw:raw,
  };
}

export function extractCiscoFirewallEnvelope(raw:string):Record<string,unknown>|null{
  const envelope=parseCiscoFirewallEnvelope(raw);
  return envelope?{
    cisco_firewall:envelope,
    generic:{mode:'cisco_firewall_message_envelope',source_raw:raw},
  }:null;
}
