/** Browser-only, opt-in Zeek TSV preparation. No network, disk or data egress. */
import {MAX_DATASET_BYTES,MAX_EVENTS,tokenizeCSV} from '../parser';

export interface ZeekReviewProposal{
  columns:string;
  dataRows:string;
  metadataCount:number;
  recordCount:number;
}

const ALLOWED_HEADERS=/^#(?:separator|set_separator|empty_field|unset_field|path|open|fields|types|close)(?:\s|$)/;

export function inspectZeekReview(source:string):ZeekReviewProposal|null{
  if(!source||source.includes('\r')||new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES)
    return null;
  const lines=source.split('\n');
  if(lines.length<4)return null;
  const separator=lines.find(line=>line.startsWith('#separator '));
  if(separator!=='#separator \\x09')return null;
  const schema=lines.filter(line=>line.startsWith('#fields\t'));
  if(schema.length!==1)return null;
  const originalNames=schema[0]!.slice('#fields\t'.length).split('\t');
  if(originalNames.length<2||originalNames.length>100)return null;
  const names=originalNames.map(name=>name.replace(/[.-]/g,'_'));
  if(names.some(name=>!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(name)||
     ['__proto__','constructor','prototype'].includes(name))||
     new Set(names).size!==names.length)return null;
  const data:string[]=[];
  let metadataCount=0;
  let seenData=false;
  for(const line of lines){
    if(!line)continue;
    if(line.startsWith('#')){
      if(!ALLOWED_HEADERS.test(line))return null;
      if(seenData&&!line.startsWith('#close'))return null;
      metadataCount++;
      continue;
    }
    seenData=true;
    if(tokenizeCSV(line,'\t')?.length!==names.length)return null;
    data.push(line);
  }
  if(data.length===0||data.length>MAX_EVENTS||metadataCount<2)return null;
  return {columns:names.join(','),dataRows:data.join('\n'),
    metadataCount,recordCount:data.length};
}
