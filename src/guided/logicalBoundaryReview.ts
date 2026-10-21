import {hasDuplicateJsonObjectKeys} from '../jsonDuplicateKeys';
/**
 * P0-AP1 browser-local candidate logical event boundaries.
 * Never returns customer text, creates parser rules, persists source, or
 * claims a Fluentd event breaker / DP import / sensor receiver readiness.
 */
import {MAX_DATASET_BYTES,MAX_EVENTS,MAX_LINE_CHARS} from '../parser';

export type BoundaryKind='JSON_OBJECT'|'JAVA_STACK'|'UNRECOGNIZED';
export type BoundaryStatus='CANDIDATE'|'ALREADY_SINGLE_LINE'|'AMBIGUOUS';
export interface LogicalBoundaryGroup{
 kind:BoundaryKind;
 status:BoundaryStatus;
 firstLine:number;
 lastLine:number;
 physicalLines:number;
 nonEmptyLines:number;
}
export interface LogicalBoundaryReport{
 contract:'auto-parser.logical-boundary-review.v0.1';
 status:'NO_SAMPLES'|'NO_MULTILINE'|'REVIEWABLE_MULTILINE'|
   'REVIEW_REQUIRED'|'LIMIT_EXCEEDED';
 sourceLines:number;
 nonEmptyLines:number;
 accountedNonEmptyLines:number;
 multilineEventCount:number;
 ambiguousCount:number;
 groups:LogicalBoundaryGroup[];
 browserOnly:true;
 nativeVerified:false;
 targetVerified:false;
 sourceIncluded:false;
}

const MAX_PHYSICAL_LINES=2000;
const MAX_GROUP_BYTES=8192;
const MAX_DEPTH=8;
const FORBIDDEN_KEYS=new Set(['__proto__','prototype','constructor']);
const rootDate=/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d{1,6})?\s+(?:WARN|ERROR|FATAL|SEVERE)\b/;
const exceptionHeader=/^(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*(?:Exception|Error):/;
const stackLine=/^\s+at\s+(?:[\w.$]+\/)?[\w.$]+\([\w.$:/ -]+\)$/;
const causeLine=/^(?:Caused by:|Suppressed:)\s+(?:[\w.$]+)(?:Exception|Error):/;
const elidedLine=/^\s*\.\.\.\s+\d+\s+more$/;

function jsonShape(node:unknown,depth:number):boolean{
 if(depth>MAX_DEPTH)return false;
 if(node===null||typeof node!=='object')return true;
 if(Array.isArray(node))return node.length<=128&&
   node.every(value=>jsonShape(value,depth+1));
 const pairs=Object.entries(node);
 return pairs.length<=128&&pairs.every(([key,value])=>
   !FORBIDDEN_KEYS.has(key)&&key.length<=128&&jsonShape(value,depth+1));
}
function report(
 status:LogicalBoundaryReport['status'],sourceLines=0,nonEmptyLines=0,
 groups:LogicalBoundaryGroup[]=[],
):LogicalBoundaryReport{
 const accountedNonEmptyLines=groups.reduce((sum,g)=>sum+g.nonEmptyLines,0);
 return {contract:'auto-parser.logical-boundary-review.v0.1',status,
  sourceLines,nonEmptyLines,accountedNonEmptyLines,
  multilineEventCount:groups.filter(g=>g.status==='CANDIDATE'&&g.physicalLines>1).length,
  ambiguousCount:groups.filter(g=>g.status==='AMBIGUOUS').length,
  groups,browserOnly:true,nativeVerified:false,targetVerified:false,sourceIncluded:false};
}
function scanJson(lines:string[],index:number):{
 last:number;status:BoundaryStatus
}{
 let depth=0,quoted=false,escaped=false,invalid=false,complete=false;
 let content='';
 let bytes=0;
 let last=index;
 for(let i=index;i<lines.length;i++){
   const line=lines[i]!;
   bytes+=new TextEncoder().encode(line).byteLength+(i===index?0:1);
   if(bytes>MAX_GROUP_BYTES)
     return {last:i,status:'AMBIGUOUS'};
   content+=i===index?line:'\n'+line;
   for(const char of line){
     if(quoted){
       if(escaped){escaped=false;continue;}
       if(char==='\\'){escaped=true;continue;}
       if(char==='"')quoted=false;
       continue;
     }
     if(char==='"'){quoted=true;continue;}
     if(char==='{'||char==='['){depth++;if(depth>MAX_DEPTH)invalid=true;}
     else if(char==='}'||char===']'){
       depth--;
       if(depth<0)invalid=true;
       if(depth===0)complete=true;
     }else if(complete&&!/\s/.test(char))invalid=true;
   }
   last=i;
   if(invalid||complete)break;
 }
 if(invalid||!complete||quoted||escaped)return {last,status:'AMBIGUOUS'};
 try{
   const value:unknown=JSON.parse(content);
   if(!value||typeof value!=='object'||Array.isArray(value)||!jsonShape(value,0))
     return {last,status:'AMBIGUOUS'};
   // A multiline review candidate does not certify data loss through
   // JSON.parse's last-key-wins behavior. Keep complete source line accounting
   // while marking this group explicitly ambiguous for human review.
   if(hasDuplicateJsonObjectKeys(content))return {last,status:'AMBIGUOUS'};
 }catch{return {last,status:'AMBIGUOUS'};}
 return {last,status:last===index?'ALREADY_SINGLE_LINE':'CANDIDATE'};
}
/** Never emits any observed log value, user name, stack frame or JSON key. */
export function reviewLogicalBoundaries(source:string):LogicalBoundaryReport{
 if(typeof source!=='string'||new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES)
   return report('LIMIT_EXCEEDED');
 const lines=source.replace(/\r\n?/g,'\n').split('\n');
 const nonEmpty=lines.filter(l=>l.trim()!=='').length;
 if(!nonEmpty)return report('NO_SAMPLES',lines.length,0);
 if(lines.length>MAX_PHYSICAL_LINES||lines.some(x=>x.length>MAX_LINE_CHARS))
   return report('LIMIT_EXCEEDED',lines.length,nonEmpty);
 // With exactly one non-empty physical line there is no boundary ambiguity to
 // resolve: this tool answers only the multi-line grouping question, not
 // whether the parser grammar itself is valid.
 if(nonEmpty===1){
   const lineIndex=lines.findIndex(line=>line.trim()!=='');
   const only=lines[lineIndex]!.trim();
   // A JSON opener may be a truncated pretty-printed object, so keep the
   // bounded JSON scanner for that one case. Other one-line logs cannot have
   // a multi-line grouping ambiguity in the current sample.
   if(!only.startsWith('{')&&!only.startsWith('[')){
     return report('NO_MULTILINE',lines.length,1,[{
       kind:'UNRECOGNIZED',status:'ALREADY_SINGLE_LINE',
       firstLine:lineIndex+1,lastLine:lineIndex+1,physicalLines:1,nonEmptyLines:1,
     }]);
   }
 }
 const groups:LogicalBoundaryGroup[]=[];
 let index=0;
 const add=(kind:BoundaryKind,status:BoundaryStatus,first:number,last:number)=>{
   const used=lines.slice(first,last+1).filter(line=>line.trim()!=='').length;
   groups.push({kind,status,firstLine:first+1,lastLine:last+1,
     physicalLines:last-first+1,nonEmptyLines:used});
 };
 while(index<lines.length){
   if(!lines[index]!.trim()){index++;continue;}
   if(groups.length>=MAX_EVENTS)return report('LIMIT_EXCEEDED',lines.length,nonEmpty);
   const raw=lines[index]!.trim();
   if(raw.startsWith('{')){
     const result=scanJson(lines,index);
     add('JSON_OBJECT',result.status,index,result.last);
     index=result.last+1;continue;
   }
   if(rootDate.test(raw)||exceptionHeader.test(raw)){
     let last=index,frames=0;
     let bytes=new TextEncoder().encode(lines[index]!).byteLength;
     while(last+1<lines.length){
       const next=lines[last+1]!;
       const trimmed=next.trim();
       if(!trimmed)break;
       // Only a bounded fixed StackTrace grammar may append physical lines.
       if(stackLine.test(next))frames++;
       else if(exceptionHeader.test(trimmed)||causeLine.test(trimmed)||
               elidedLine.test(next)){}
       else break;
       bytes+=new TextEncoder().encode(next).byteLength+1;
       if(bytes>MAX_GROUP_BYTES)break;
       last++;
     }
     const status:BoundaryStatus=frames>0&&last>index?'CANDIDATE':
       last===index?'ALREADY_SINGLE_LINE':'AMBIGUOUS';
     add('JAVA_STACK',status,index,last);
     index=last+1;continue;
   }
   // Unknown and orphan frames are all accounted for, never discarded.
   add('UNRECOGNIZED','AMBIGUOUS',index,index);
   index++;
 }
 const result=report('NO_MULTILINE',lines.length,nonEmpty,groups);
 const status:LogicalBoundaryReport['status']=result.accountedNonEmptyLines!==nonEmpty||
   result.ambiguousCount>0?'REVIEW_REQUIRED':
   result.multilineEventCount>0?'REVIEWABLE_MULTILINE':'NO_MULTILINE';
 return {...result,status};
}
