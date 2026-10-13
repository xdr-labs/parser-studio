/** P1-AP5: explicit no-secret same-origin Drain3 availability → consent → POST.
 * Not an LLM, native parser compiler, credential path or implicit raw upload.
 */
export type Drain3Availability='AVAILABLE'|'DISABLED';
export interface Drain3Hint{
 clusterId:string;shape:string;
 trainingCount:number;trainingLineNumbers:number[];
 holdoutMatches:number;reviewOnly:true;
}
export interface Drain3Report{
 contract:'parser-studio.drain3-reviewed-hints.v0.1';
 engine:'Drain3 0.9.11';sourceCount:number;accounted:number;
 holdoutCount:number;holdoutMatched:number;groupCount:number;
 groups:Drain3Hint[];persisted:false;sourceValuesIncluded:false;
 nativeParserVerified:false;targetImportVerified:false;
}
const BASE='/api/v1/parser-pairs/patterns/drain3';
const MAX_BYTES=64*1024;
const SHAPE=new Set([
 'ERROR','WARN','WARNING','DEBUG','INFO','TRACE','FATAL','LOGIN',
 'LOGOUT','ALLOW','DENY','FAILED','SUCCESS','GET','POST','PUT',
 'PATCH','DELETE','HTTP','HTTPS','TCP','UDP','SRC','DST','IP',
 'PORT','USER','STATUS','TIME','ID','<VAR>','<IP>','<NUM>',
 '<UUID>','<PUNCT>','<WORD>',
]);
function exact(value:unknown,keys:readonly string[]):value is Record<string,unknown>{
 return value!==null&&typeof value==='object'&&!Array.isArray(value)&&
  Object.keys(value).length===keys.length&&
  Object.keys(value).every(k=>keys.includes(k));
}
const denial=():never=>{throw new Error('Private offline Drain3 capability or report was not verified.');};
export async function checkPrivateDrain3Availability(
 requester:typeof fetch=fetch,
):Promise<Drain3Availability>{
 const response=await requester(BASE+'/capabilities',{
  method:'GET',cache:'no-store',credentials:'same-origin',
  headers:{Accept:'application/json'},
 });
 if(response.status===403||response.status===404)return 'DISABLED';
 if(response.status!==200)denial();
 let data:unknown;
 try{data=await response.json();}catch{denial();}
 if(!exact(data,[
  'contract','available','requiresExplicitConfirmation','engine',
  'sameOriginRawSourceTransfer','noPersistence','maxTrainingEvents',
  'maxHoldoutEvents','nativeParserVerified','targetImportVerified',
  'noExternalLlmCalls',
 ])||
 data.contract!=='parser-studio.drain3-capabilities.v0.1'||
 data.available!==true||data.requiresExplicitConfirmation!==true||
 data.engine!=='Drain3 0.9.11'||data.sameOriginRawSourceTransfer!==true||
 data.noPersistence!==true||data.maxTrainingEvents!==500||
 data.maxHoldoutEvents!==500||data.nativeParserVerified!==false||
 data.targetImportVerified!==false||data.noExternalLlmCalls!==true)denial();
 return 'AVAILABLE';
}
function validSource(records:unknown,allowEmpty:boolean):records is string[]{
 return Array.isArray(records)&&records.length<=500&&
  (allowEmpty||records.length>0)&&records.every(x=>
   typeof x==='string'&&x.length>0&&x.length<=2048&&
   new TextEncoder().encode(x).byteLength<=2048&&
   !/[\u0000\r\n]/.test(x));
}
function checkReport(raw:unknown,train:string[],holdout:string[]):Drain3Report{
 if(!exact(raw,['contract','engine','sourceCount','accounted',
  'holdoutCount','holdoutMatched','groupCount','groups','persisted',
  'sourceValuesIncluded','nativeParserVerified','targetImportVerified'])||
  raw.contract!=='parser-studio.drain3-reviewed-hints.v0.1'||
  raw.engine!=='Drain3 0.9.11'||raw.sourceCount!==train.length||
  raw.accounted!==train.length||raw.holdoutCount!==holdout.length||
  !Number.isSafeInteger(raw.holdoutMatched)||
  Number(raw.holdoutMatched)<0||Number(raw.holdoutMatched)>holdout.length||
  !Array.isArray(raw.groups)||raw.groups.length>32||
  raw.groupCount!==raw.groups.length||raw.persisted!==false||
  raw.sourceValuesIncluded!==false||raw.nativeParserVerified!==false||
  raw.targetImportVerified!==false)denial();
 const data=raw as Record<string,unknown>;
 const seen=new Set<string>(),lineNums=new Set<number>();
 let verifiedHoldout=0;
 for(const group of data.groups as unknown[]){
  if(!exact(group,['clusterId','shape','trainingCount',
    'trainingLineNumbers','holdoutMatches','reviewOnly'])||
    typeof group.clusterId!=='string'||!/^cluster-[1-9][0-9]{0,3}$/.test(group.clusterId)||
    seen.has(group.clusterId)||typeof group.shape!=='string'||
    group.shape.length>512||!group.shape||
    !group.shape.split(' ').every(x=>SHAPE.has(x))||
    !Number.isSafeInteger(group.trainingCount)||Number(group.trainingCount)<1||
    !Array.isArray(group.trainingLineNumbers)||
    group.trainingLineNumbers.length!==group.trainingCount||
    !Number.isSafeInteger(group.holdoutMatches)||
    Number(group.holdoutMatches)<0||group.reviewOnly!==true)denial();
  const entry=group as Record<string,unknown>;
  seen.add(entry.clusterId as string);
  verifiedHoldout+=Number(entry.holdoutMatches);
  for(const line of entry.trainingLineNumbers as unknown[]){
   if(!Number.isSafeInteger(line)||Number(line)<1||
     Number(line)>train.length||lineNums.has(Number(line)))denial();
   lineNums.add(Number(line));
  }
 }
 if(lineNums.size!==train.length||verifiedHoldout!==data.holdoutMatched)denial();
 return raw as Drain3Report;
}
/** Call only after a separate successful availability GET and user consent. */
export async function runPrivateDrain3Review(
 training:string[],holdout:string[],approved:boolean,requester:typeof fetch=fetch,
):Promise<Drain3Report>{
 if(!approved)throw new Error('Explicit consent required before any log transfer.');
 if(!validSource(training,false)||!validSource(holdout,true))denial();
 const body=JSON.stringify({
  contract:'parser-studio.drain3-input.v0.1',training,holdout,confirmed:true,
 });
 if(new TextEncoder().encode(body).byteLength>MAX_BYTES)denial();
 const response=await requester(BASE,{
  method:'POST',cache:'no-store',credentials:'same-origin',
  headers:{'Content-Type':'application/json',Accept:'application/json'},
  body,
 });
 if(response.status!==200)throw new Error('Private Drain3 backend unavailable or unauthorized.');
 let data:unknown;
 try{data=await response.json();}catch{denial();}
 return checkReport(data,training,holdout);
}
