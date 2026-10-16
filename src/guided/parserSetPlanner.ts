import type {MultiPassSourcePreview} from './multipassPreviewClient';

export interface ParserSetFrame{
  startByte:number;
  endByte:number;
  preview:MultiPassSourcePreview;
}

export interface ParserSetFamilyGroup{
  id:string;
  label:string;
  family:string;
  syntax:string;
  eventIndexes:number[];
  count:number;
}

export interface ParserSetPlan{
  contract:'parser-studio.parser-set-plan.v0.1';
  status:'MULTI_FAMILY'|'SINGLE_FAMILY'|'INSUFFICIENT_EVIDENCE';
  eventCount:number;
  accounted:number;
  groups:ParserSetFamilyGroup[];
  nativeVerified:false;
  targetVerified:false;
}

function objectValue(value:unknown):Record<string,unknown>|null{
  return value&&typeof value==='object'&&!Array.isArray(value)
    ?value as Record<string,unknown>:null;
}

function atPath(root:Record<string,unknown>,path:string[]):unknown{
  let current:unknown=root;
  for(const part of path){
    const object=objectValue(current);
    if(!object)return undefined;
    current=object[part];
  }
  return current;
}

function safeFamilyToken(value:unknown):string|null{
  if(typeof value!=='string')return null;
  const token=value.trim().toUpperCase();
  return /^[A-Z][A-Z0-9_-]{1,31}$/.test(token)?token:null;
}

function explicitFamily(preview:MultiPassSourcePreview):string|null{
  const candidates=[
    ['generic','fields','type'],
    ['generic','columns','column_3'],
    ['body','type'],
    ['type'],
  ];
  for(const path of candidates){
    const token=safeFamilyToken(atPath(preview.fields,path));
    if(token)return token;
  }
  const asa=objectValue(preview.fields.asa);
  if(asa&&typeof asa.message_id==='string'&&/^\d{6}$/.test(asa.message_id))
    return 'ASA-'+asa.message_id;
  return null;
}

function syntaxFamily(preview:MultiPassSourcePreview):string|null{
  const syntax=preview.syntax.trim().toUpperCase();
  if(!syntax||syntax.length>160)return null;
  const pan=syntax.match(/PANOS_([A-Z0-9_-]+?)(?:_CSV|$|\+)/);
  if(pan?.[1])return pan[1];
  const asa=syntax.match(/(?:CISCO_)?ASA(?:_FTD)?_MESSAGE_ID_([0-9]{6})/);
  if(asa?.[1])return 'ASA-'+asa[1];
  return null;
}

function labelFor(family:string,syntax:string):string{
  if(syntax.includes('PANOS_'))return 'Palo Alto Networks · '+family.replaceAll('_',' ');
  if(family.startsWith('ASA-'))return 'Cisco ASA / FTD · '+family.slice(4);
  return family.replaceAll('_',' ')+' · '+syntax.replaceAll('_',' ');
}

export function planParserSet(frames:readonly ParserSetFrame[]):ParserSetPlan{
  const groups=new Map<string,ParserSetFamilyGroup>();
  let accounted=0;
  frames.forEach((frame,index)=>{
    if(frame.preview.status!=='SOURCE_PARSED')return;
    const family=explicitFamily(frame.preview)??syntaxFamily(frame.preview);
    if(!family)return;
    const syntax=frame.preview.syntax.trim().toUpperCase();
    const id=family+'\0'+syntax;
    const current=groups.get(id)??{
      id,family,syntax,label:labelFor(family,syntax),eventIndexes:[],count:0,
    };
    current.eventIndexes.push(index);
    current.count++;
    groups.set(id,current);
    accounted++;
  });
  const list=[...groups.values()].sort((a,b)=>a.eventIndexes[0]!-b.eventIndexes[0]!);
  const fullyAccounted=frames.length>0&&accounted===frames.length;
  const status:ParserSetPlan['status']=!fullyAccounted
    ?'INSUFFICIENT_EVIDENCE'
    :list.length>1?'MULTI_FAMILY':list.length===1?'SINGLE_FAMILY':'INSUFFICIENT_EVIDENCE';
  return {
    contract:'parser-studio.parser-set-plan.v0.1',
    status,eventCount:frames.length,accounted,groups:list,
    nativeVerified:false,targetVerified:false,
  };
}

export type ParserSetMaterialization=
 |{ok:true;source:string;count:number}
 |{ok:false;reason:'SOURCE_MISMATCH'|'SOURCE_LIMIT'};

export function materializeParserSetFamily(
  source:string,frames:readonly ParserSetFrame[],group:ParserSetFamilyGroup,
):ParserSetMaterialization{
  const bytes=new TextEncoder().encode(source);
  if(!bytes.length||bytes.length>64*1024)
    return {ok:false,reason:'SOURCE_LIMIT'};
  if(!group.eventIndexes.length||group.count!==group.eventIndexes.length||
     group.eventIndexes.some((index,position)=>!Number.isSafeInteger(index)||index<0||
       (position>0&&index<=group.eventIndexes[position-1]!)))
    return {ok:false,reason:'SOURCE_MISMATCH'};
  const decoder=new TextDecoder('utf-8',{fatal:true});
  const selected:string[]=[];
  let previousEnd=-1;
  try{
    for(const index of group.eventIndexes){
      const frame=frames[index];
      if(!frame||!Number.isSafeInteger(frame.startByte)||!Number.isSafeInteger(frame.endByte)||
         frame.startByte<0||frame.endByte>bytes.length||frame.startByte>=frame.endByte||
         frame.startByte<previousEnd)
        return {ok:false,reason:'SOURCE_MISMATCH'};
      selected.push(decoder.decode(bytes.slice(frame.startByte,frame.endByte)));
      previousEnd=frame.endByte;
    }
  }catch{return {ok:false,reason:'SOURCE_MISMATCH'};}
  const grouped=selected.join('\n');
  if(new TextEncoder().encode(grouped).byteLength>64*1024)
    return {ok:false,reason:'SOURCE_LIMIT'};
  return {ok:true,source:grouped,count:selected.length};
}
