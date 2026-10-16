export type VendorSchemaConfidence='HIGH';

export interface OrderedVendorSchemaMatch{
  vendor:string;
  product:string;
  family:string;
  profile:string;
  confidence:VendorSchemaConfidence;
  knownFieldCount:number;
  unknownTailCount:number;
  fields:Record<string,string>;
  evidence:string[];
}

export interface VendorSchemaDescriptor{
  id:string;
  vendor:string;
  product:string;
  family:string;
  layout:'ordered-csv';
  driftPolicy:'preserve-tail';
}

const PANOS_TRAFFIC_CORE_53=[
  'domain','receive_time','serial','type','subtype','config_version','time_generated',
  'src','dst','natsrc','natdst','rule','srcuser','dstuser','app','vsys','from','to',
  'inbound_if','outbound_if','logset','time_received','sessionid','repeatcnt','sport',
  'dport','natsport','natdport','flags','protocol','action','bytes','bytes_sent',
  'bytes_received','packets','start_time','elapsed','category','seqno','actionflags',
  'srcloc','dstloc','cpadding','pkts_sent','pkts_received','session_end_reason',
  'dg_hier_level_1','dg_hier_level_2','dg_hier_level_3','dg_hier_level_4',
  'vsys_name','device_name','action_source',
] as const;

const PANOS_TRAFFIC_PADDING_54=[
  ...PANOS_TRAFFIC_CORE_53.slice(0,38),'padding',...PANOS_TRAFFIC_CORE_53.slice(38),
] as const;

export const VENDOR_SCHEMA_CATALOG:readonly VendorSchemaDescriptor[]=[
  {
    id:'panos.traffic.core53',
    vendor:'Palo Alto Networks',
    product:'PAN-OS',
    family:'TRAFFIC',
    layout:'ordered-csv',
    driftPolicy:'preserve-tail',
  },
  {
    id:'panos.traffic.padding54',
    vendor:'Palo Alto Networks',
    product:'PAN-OS',
    family:'TRAFFIC',
    layout:'ordered-csv',
    driftPolicy:'preserve-tail',
  },
] as const;

function validIpv4(value:string):boolean{
  const parts=value.split('.');
  return parts.length===4&&parts.every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255);
}

function validDateTime(value:string):boolean{
  return /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,9})?$/.test(value);
}

function validPort(value:string):boolean{
  return /^\d{1,5}$/.test(value)&&Number(value)<=65535;
}

function looksSequence(value:string):boolean{
  return /^\d{1,20}$/.test(value);
}

function looksActionFlags(value:string):boolean{
  // PAN-OS actionflags is represented as a hexadecimal flag token. Requiring
  // the 0x prefix prevents a numeric padding column followed by a numeric
  // sequence number from being mistaken for the core layout.
  return /^0x[0-9a-f]+$/i.test(value);
}

function buildFields(values:string[],names:readonly string[]):Record<string,string>{
  const fields:Record<string,string>={};
  for(let index=0;index<values.length;index++){
    const name=names[index]??'vendor_extra_'+String(index-names.length+1).padStart(3,'0');
    fields[name]=values[index]!;
  }
  return fields;
}

/**
 * Match only evidence-backed ordered vendor layouts.
 *
 * The matcher deliberately separates schema recognition from the generic
 * Syslog/CSV parser. Known columns receive semantic names; later columns that
 * were not part of the reviewed layout are preserved as vendor_extra_### so a
 * vendor software upgrade cannot silently shift or discard source values.
 */
export function matchOrderedVendorSchema(values:readonly string[]):OrderedVendorSchemaMatch|null{
  if(values.length<53||values[3]!=='TRAFFIC')return null;
  if(!validDateTime(values[1]??'')||!validDateTime(values[6]??'')||
     !validDateTime(values[21]??'')||!validDateTime(values[35]??''))return null;
  for(const index of [7,8,9,10])if(!validIpv4(values[index]??''))return null;
  for(const index of [24,25,26,27])if(!validPort(values[index]??''))return null;
  if(!/^[A-Za-z0-9_.-]{1,24}$/.test(values[29]??'')||
     !/^[A-Za-z0-9_. -]{1,64}$/.test(values[30]??''))return null;

  let profile:string;
  let names:readonly string[];
  if(looksSequence(values[38]??'')&&looksActionFlags(values[39]??'')){
    profile='panos.traffic.core53';names=PANOS_TRAFFIC_CORE_53;
  }else if(values.length>=54&&(values[38]??'')===''&&
           looksSequence(values[39]??'')&&looksActionFlags(values[40]??'')){
    profile='panos.traffic.padding54';names=PANOS_TRAFFIC_PADDING_54;
  }else return null;

  return {
    vendor:'Palo Alto Networks',
    product:'PAN-OS',
    family:'TRAFFIC',
    profile,
    confidence:'HIGH',
    knownFieldCount:Math.min(values.length,names.length),
    unknownTailCount:Math.max(0,values.length-names.length),
    fields:buildFields([...values],names),
    evidence:[
      'TRAFFIC event-family anchor',
      'reviewed PAN-OS ordered timestamp/IP/port anchors',
      profile==='panos.traffic.padding54'?'padding-column signature':'core sequence/actionflags signature',
    ],
  };
}
