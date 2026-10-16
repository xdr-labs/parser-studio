export const VPC_FLOW_V2_FIELDS=[
  'version','account-id','interface-id','srcaddr','dstaddr','srcport','dstport',
  'protocol','packets','bytes','start','end','action','log-status',
] as const;

export type VpcFlowV2Field=typeof VPC_FLOW_V2_FIELDS[number];
export type VpcFlowV2Record=Record<VpcFlowV2Field,string>;

function ipv4(value:string):boolean{
  const parts=value.split('.');
  return parts.length===4&&parts.every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255);
}

function ipv6(value:string):boolean{
  if(!value.includes(':')||!/^[0-9A-Fa-f:]+$/.test(value)||value.indexOf('::')!==value.lastIndexOf('::'))return false;
  const sides=value.split('::');
  if(sides.length>2)return false;
  const groups=sides.flatMap(side=>side?side.split(':'):[]);
  if(groups.some(group=>!/^[0-9A-Fa-f]{1,4}$/.test(group)))return false;
  return sides.length===2?groups.length<8:groups.length===8;
}

function ip(value:string):boolean{return ipv4(value)||ipv6(value);}
function port(value:string):boolean{return value==='-'||(/^\d{1,5}$/.test(value)&&Number(value)<=65535);}
function uint(value:string):boolean{return value==='-'||/^\d+$/.test(value);}
function epoch(value:string):boolean{return value==='-'||/^\d{9,12}$/.test(value);}

export function parseVpcFlowLogV2(raw:string):VpcFlowV2Record|null{
  if(!raw||raw.includes('\0')||/[\r\n\t]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  const values=raw.trim().split(/ +/);
  if(values.length!==VPC_FLOW_V2_FIELDS.length||values[0]!=='2')return null;
  if(!(/^\d{12}$/.test(values[1]!)||values[1]==='unknown'))return null;
  if(!(/^eni-[0-9a-f]{8,32}$/i.test(values[2]!)||values[2]==='-'))return null;
  if(!(values[3]==='-'||ip(values[3]!))||!(values[4]==='-'||ip(values[4]!)))return null;
  if(!port(values[5]!)||!port(values[6]!))return null;
  if(!(values[7]==='-'||(/^\d{1,3}$/.test(values[7]!)&&Number(values[7])<=255)))return null;
  if(!uint(values[8]!)||!uint(values[9]!)||!epoch(values[10]!)||!epoch(values[11]!))return null;
  if(!/^(?:ACCEPT|REJECT|-)$/.test(values[12]!)||!/^(?:OK|NODATA|SKIPDATA)$/.test(values[13]!))return null;
  if(values[10]!=='-'&&values[11]!=='-'&&Number(values[11])<Number(values[10]))return null;
  if(values[13]==='OK'&&(values[3]==='-'||values[4]==='-'||values[7]==='-'||
    values[10]==='-'||values[11]==='-'||values[12]==='-'))return null;
  const record={} as VpcFlowV2Record;
  VPC_FLOW_V2_FIELDS.forEach((field,index)=>{record[field]=values[index]!;});
  return record;
}

export function extractVpcFlowStructural(raw:string):Record<string,unknown>|null{
  const flow=parseVpcFlowLogV2(raw);
  return flow?{
    aws_vpc_flow:flow,
    generic:{mode:'aws_vpc_flow_v2',source_raw:raw},
  }:null;
}
