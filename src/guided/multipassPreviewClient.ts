import {sha256Utf8Hex} from '../sha256';
import {isUtf8ByteBoundary} from './sourceByteSelection';
import semanticPolicy from '../../runtime/multipass/semantic-policy.v1.json';

const DICTIONARY_REVISION='stellar-standard-metadata-7.0.xs-2026-10-14';
const DICTIONARY_URLS=[
 'https://docs.stellarcyber.ai/prod-docs/6.5.xs/Common/Metadata-Dictionary.htm?TocPath=REFERENCE%7C_____8',
 'https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm',
 'https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf',
] as const;
const DICTIONARY_TYPES=new Set(['string','integer','ip']);
const SOURCE_PATH=/^[A-Za-z_][A-Za-z0-9_.@:\-[\]]{0,255}$/;
const TARGET_PATH=/^[A-Za-z_][A-Za-z0-9_.\-[\]]{0,255}$/;
const CEF_ALIASES:Record<string,string>={src:'srcip',dst:'dstip',spt:'srcport',dpt:'dstport',act:'action'};

export interface MultiPassRedactionProjection {
 contract:'parser-studio.visible-redaction-assessment.v0.1';
 assessment:'EXPLICIT_VISIBLE_MASKS'|'NOT_ASSESSED_NO_LITERAL_MARKER'|'EXCLUDED_NO_SOURCE_OCCURRENCES';
 sourceOccurrences:number;explicitMaskOccurrences:number;unassessedVisibleOccurrences:number;
 excludedEvent:boolean;
 occurrences:Array<{sourcePath:string;occurrence:number;
  markerClass:'REDACTED_KEYWORD'|'MASKED_KEYWORD'|'ASTERISK_RUN';
  startByte:number;endByte:number}>;
 sourceExtractionPreserved:true;hiddenValueReconstruction:false;
}

export interface MultiPassDictionaryProjection {
 contract:'parser-studio.stellar-dictionary-projection.v0.1';
 dictionaryRevision:string;
 sourceUrls:string[];
 mapped:Array<{sourcePath:string;targetField:string;documentedType:string;
  mappingClass:'EXACT_DICTIONARY_NAME'|'CEF_STANDARD_ALIAS'|'EXPLICIT_SOURCE_ALIAS';startByte:number;endByte:number}>;
 unmappedCount:number;issues:string[];
 automaticAliasInference:false;standardizedAliasMapping:true;sourceExtractionPreserved:true;
 nativeVerified:false;targetVerified:false;
}

/** Explicit opt-in local Multi-Pass source preview; no automatic source upload. */
export interface MultiPassSourcePreview {
 contract:'parser-studio.multipass-source-preview.v0.1';
 status:'SOURCE_PARSED'|'PARTIAL'|'RAW_ONLY'|'STRUCTURED_EMPTY';
 syntax:string;sourceSha256:string;sourceBytes:number;
 fields:Record<string,unknown>;
 spans:Array<{path:string;startByte:number;endByte:number}>;
 residuals:Array<{startByte:number;endByte:number}>;
 issues:string[];
 dictionary?:MultiPassDictionaryProjection;
 redaction?:MultiPassRedactionProjection;
 nativeVerified:false;targetVerified:false;
}

export interface MultiPassBatchPreview {
 contract:'parser-studio.multipass-source-batch-preview.v0.1';
 sourceSha256:string;sourceBytes:number;eventCount:number;
 events:Array<{index:number;startByte:number;endByte:number;preview:MultiPassSourcePreview}>;
 separators:Array<{startByte:number;endByte:number;kind:'WHITESPACE'|'UTF8_BOM'|'SOURCE_METADATA'|'SOURCE_FRAMING'}>;
 nativeVerified:false;targetVerified:false;
}
function mappingMatchesContract(sourcePath:string,targetField:string,mappingClass:string):boolean{
 if(mappingClass==='EXACT_DICTIONARY_NAME')
  return sourcePath===targetField||sourcePath===`body.${targetField}`;
 if(mappingClass==='EXPLICIT_SOURCE_ALIAS'){
  const parts=sourcePath.toLowerCase().split('.');
  const leaf=parts.at(-1);
  return !parts.some(part=>semanticPolicy.excludedPortSourceSegments.includes(part))&&
    leaf!==undefined&&semanticPolicy.explicitPortSourceAliases[
      leaf as keyof typeof semanticPolicy.explicitPortSourceAliases]===targetField;
 }
 if(mappingClass==='CEF_STANDARD_ALIAS'){
  for(const prefix of ['cef_extension.','body.cef_extension.']){
   if(sourcePath.startsWith(prefix))
    return CEF_ALIASES[sourcePath.slice(prefix.length)]===targetField;
  }
 }
 return false;
}
function verifyDictionary(raw:unknown,spans:MultiPassSourcePreview['spans'],size:number):
 MultiPassDictionaryProjection{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))
  throw new Error('Untrusted Stellar Dictionary projection.');
 const value=raw as Partial<MultiPassDictionaryProjection>;
 if(value.contract!=='parser-studio.stellar-dictionary-projection.v0.1'||
  value.dictionaryRevision!==DICTIONARY_REVISION||
  JSON.stringify(value.sourceUrls)!==JSON.stringify(DICTIONARY_URLS)||
  !Array.isArray(value.mapped)||!Array.isArray(value.issues)||
  !Number.isSafeInteger(value.unmappedCount)||value.unmappedCount!<0||
  value.automaticAliasInference!==false||value.standardizedAliasMapping!==true||
  value.sourceExtractionPreserved!==true||value.nativeVerified!==false||value.targetVerified!==false||
  value.mapped.length+(value.unmappedCount??-1)!==spans.length||
  value.mapped.length>1024||value.issues.length>32)
  throw new Error('Untrusted Stellar Dictionary projection.');
 const spanKeys=new Set(spans.map(x=>x.path+'\0'+x.startByte+'\0'+x.endByte));
 const targets=new Set<string>();
 for(const item of value.mapped){
  if(!item||typeof item!=='object'||Array.isArray(item)||
   Object.prototype.hasOwnProperty.call(item,'value')||
   typeof item.sourcePath!=='string'||!SOURCE_PATH.test(item.sourcePath)||
   typeof item.targetField!=='string'||!TARGET_PATH.test(item.targetField)||
   !DICTIONARY_TYPES.has(item.documentedType)||
   !['EXACT_DICTIONARY_NAME','CEF_STANDARD_ALIAS','EXPLICIT_SOURCE_ALIAS'].includes(item.mappingClass)||
   (item.mappingClass==='EXPLICIT_SOURCE_ALIAS'&&item.documentedType!=='integer')||
   !mappingMatchesContract(item.sourcePath,item.targetField,item.mappingClass)||
   !Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
   item.startByte<0||item.endByte>size||item.startByte>item.endByte||
   !spanKeys.has(item.sourcePath+'\0'+item.startByte+'\0'+item.endByte)||
   targets.has(item.targetField))
   throw new Error('Untrusted Stellar Dictionary projection.');
  targets.add(item.targetField);
 }
 if(value.issues.some(x=>typeof x!=='string'||x.length>160||
   !/^[A-Za-z0-9_.:-]+$/.test(x)))
  throw new Error('Untrusted Stellar Dictionary projection.');
 return value as MultiPassDictionaryProjection;
}
function visibleMarkerMatches(markerClass:string,token:string):boolean{
 const lower=token.toLocaleLowerCase('en-US');
 if(markerClass==='REDACTED_KEYWORD')
  return ['redacted','<redacted>','[redacted]'].includes(lower);
 if(markerClass==='MASKED_KEYWORD')
  return ['masked','<masked>','[masked]'].includes(lower);
 if(markerClass==='ASTERISK_RUN')return /^\*{3,64}$/.test(token);
 return false;
}
function verifyRedaction(raw:unknown,source:string,spans:MultiPassSourcePreview['spans'],size:number):
 MultiPassRedactionProjection{
 if(!raw||typeof raw!=='object'||Array.isArray(raw))
  throw new Error('Untrusted visible redaction projection.');
 const value=raw as Partial<MultiPassRedactionProjection>;
 const assessments=['EXPLICIT_VISIBLE_MASKS','NOT_ASSESSED_NO_LITERAL_MARKER','EXCLUDED_NO_SOURCE_OCCURRENCES'];
 if(value.contract!=='parser-studio.visible-redaction-assessment.v0.1'||
  !assessments.includes(value.assessment??'')||
  !Number.isSafeInteger(value.sourceOccurrences)||value.sourceOccurrences!<0||
  !Number.isSafeInteger(value.explicitMaskOccurrences)||value.explicitMaskOccurrences!<0||
  !Number.isSafeInteger(value.unassessedVisibleOccurrences)||value.unassessedVisibleOccurrences!<0||
  value.sourceOccurrences!==spans.length||
  (value.explicitMaskOccurrences!+value.unassessedVisibleOccurrences!)!==value.sourceOccurrences||
  !Array.isArray(value.occurrences)||value.occurrences.length!==value.explicitMaskOccurrences||
  value.sourceExtractionPreserved!==true||value.hiddenValueReconstruction!==false||
  typeof value.excludedEvent!=='boolean')
  throw new Error('Untrusted visible redaction projection.');
 const excluded=value.assessment==='EXCLUDED_NO_SOURCE_OCCURRENCES';
 if(value.excludedEvent!==excluded||
  (value.assessment==='EXPLICIT_VISIBLE_MASKS'&&value.explicitMaskOccurrences===0)||
  (value.assessment==='NOT_ASSESSED_NO_LITERAL_MARKER'&&
    (value.explicitMaskOccurrences!==0||value.sourceOccurrences===0))||
  (excluded&&(value.sourceOccurrences!==0||value.explicitMaskOccurrences!==0)))
  throw new Error('Untrusted visible redaction projection.');
 const grouped=new Map<string,Array<{path:string;startByte:number;endByte:number}>>();
 for(const span of spans){
  const items=grouped.get(span.path)??[];items.push(span);grouped.set(span.path,items);
 }
 const sourceBytes=new TextEncoder().encode(source);
 const decoder=new TextDecoder('utf-8',{fatal:true});
 const seen=new Set<string>();
 for(const item of value.occurrences){
  if(!item||typeof item!=='object'||Array.isArray(item)||
   Object.prototype.hasOwnProperty.call(item,'value')||
   typeof item.sourcePath!=='string'||!SOURCE_PATH.test(item.sourcePath)||
   !Number.isSafeInteger(item.occurrence)||item.occurrence!<0||
   !['REDACTED_KEYWORD','MASKED_KEYWORD','ASTERISK_RUN'].includes(item.markerClass)||
   !Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
   item.startByte<0||item.endByte>size||item.startByte>=item.endByte)
   throw new Error('Untrusted visible redaction projection.');
  const span=grouped.get(item.sourcePath)?.[item.occurrence!];
  const key=item.sourcePath+'\0'+item.occurrence;
  if(!span||item.startByte<span.startByte||item.endByte>span.endByte||seen.has(key))
   throw new Error('Untrusted visible redaction projection.');
  let token:string;
  try{token=decoder.decode(sourceBytes.slice(item.startByte,item.endByte));}
  catch{throw new Error('Untrusted visible redaction projection.');}
  if(!visibleMarkerMatches(item.markerClass!,token))
   throw new Error('Untrusted visible redaction projection.');
  seen.add(key);
 }
 return value as MultiPassRedactionProjection;
}
async function verifySourcePreview(raw:string,value:Partial<MultiPassSourcePreview>):Promise<MultiPassSourcePreview>{
 const originalBytes=new TextEncoder().encode(raw);
 const size=originalBytes.byteLength;
 if(value.contract!=='parser-studio.multipass-source-preview.v0.1'||
  !['SOURCE_PARSED','PARTIAL','RAW_ONLY','STRUCTURED_EMPTY'].includes(value.status??'')||
  value.nativeVerified!==false||value.targetVerified!==false||
  value.sourceBytes!==size||!value.fields||Array.isArray(value.fields)||
  !Array.isArray(value.spans)||!Array.isArray(value.residuals)||!Array.isArray(value.issues))
  throw new Error('Untrusted Multi-Pass response.');
 if(!/^[a-f0-9]{64}$/.test(value.sourceSha256??''))
  throw new Error('Unverified source identity.');
 const expected=await sha256Utf8Hex(raw);
 if(value.sourceSha256!==expected)throw new Error('Multi-Pass response source mismatch.');
 for(const item of value.spans){
  if(!Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
    item.startByte<0||item.endByte>size||item.startByte>item.endByte)
    throw new Error('Invalid Multi-Pass byte span.');
  if(!isUtf8ByteBoundary(originalBytes,item.startByte)||
     !isUtf8ByteBoundary(originalBytes,item.endByte))
    throw new Error('Invalid Multi-Pass UTF-8 byte boundary.');
 }
 for(const item of value.residuals){
  if(!Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
    item.startByte<0||item.endByte>size||item.startByte>=item.endByte)
    throw new Error('Invalid Multi-Pass residual span.');
  if(!isUtf8ByteBoundary(originalBytes,item.startByte)||
     !isUtf8ByteBoundary(originalBytes,item.endByte))
    throw new Error('Invalid Multi-Pass UTF-8 residual byte boundary.');
 }
 if(value.dictionary!==undefined)
  value.dictionary=verifyDictionary(value.dictionary,value.spans,size);
 if(value.redaction!==undefined)
  value.redaction=verifyRedaction(value.redaction,raw,value.spans,size);
 return value as MultiPassSourcePreview;
}
function utf8Slice(raw:string,startByte:number,endByte:number):string{
 const data=new TextEncoder().encode(raw);
 try{return new TextDecoder('utf-8',{fatal:true}).decode(data.slice(startByte,endByte));}
 catch{throw new Error('Invalid Multi-Pass event byte range.');}
}
export type MultiPassRequestPhase='analyzing'|'validating';
export interface MultiPassRequestOptions {
 signal?:AbortSignal;
 onPhase?:(phase:MultiPassRequestPhase)=>void;
}
function assertNotAborted(signal?:AbortSignal){
 if(signal?.aborted)throw new DOMException('Analysis canceled.','AbortError');
}
export async function requestMultiPassPreview(raw:string,requester:typeof fetch=fetch,
 options:MultiPassRequestOptions={}):Promise<MultiPassSourcePreview>{
 assertNotAborted(options.signal);
 const size=new TextEncoder().encode(raw).byteLength;
 if(!size||size>65536)throw new Error('Source must be between 1 and 65536 UTF-8 bytes.');
 options.onPhase?.('analyzing');
 const response=await requester('/api/v1/multipass/preview',{method:'POST',
  headers:{'Content-Type':'application/json'},cache:'no-store',credentials:'same-origin',
  body:JSON.stringify({raw}),signal:options.signal});
 assertNotAborted(options.signal);
 if(!response.ok)throw new Error('Multi-Pass preview is unavailable. No engine result was accepted.');
 const value=await response.json() as Partial<MultiPassSourcePreview>;
 assertNotAborted(options.signal);
 options.onPhase?.('validating');
 const result=await verifySourcePreview(raw,value);
 assertNotAborted(options.signal);
 return result;
}
export async function requestMultiPassBatchPreview(raw:string,requester:typeof fetch=fetch,
 options:MultiPassRequestOptions={}):Promise<MultiPassBatchPreview>{
 assertNotAborted(options.signal);
 const size=new TextEncoder().encode(raw).byteLength;
 if(!size||size>65536)throw new Error('Source must be between 1 and 65536 UTF-8 bytes.');
 options.onPhase?.('analyzing');
 const response=await requester('/api/v1/multipass/preview-batch',{method:'POST',
  headers:{'Content-Type':'application/json'},cache:'no-store',credentials:'same-origin',
  body:JSON.stringify({raw}),signal:options.signal});
 assertNotAborted(options.signal);
 if(!response.ok)throw new Error('Multi-Pass batch preview is unavailable. No engine result was accepted.');
 const value=await response.json() as Partial<MultiPassBatchPreview>;
 assertNotAborted(options.signal);
 options.onPhase?.('validating');
 if(value.contract!=='parser-studio.multipass-source-batch-preview.v0.1'||
  value.nativeVerified!==false||value.targetVerified!==false||
  value.sourceBytes!==size||!Number.isSafeInteger(value.eventCount)||value.eventCount!<1||
  value.eventCount!>500||!Array.isArray(value.events)||value.events.length!==value.eventCount||
  !Array.isArray(value.separators))
  throw new Error('Untrusted Multi-Pass batch response.');
 if(!/^[a-f0-9]{64}$/.test(value.sourceSha256??'')||
  value.sourceSha256!==await sha256Utf8Hex(raw))
  throw new Error('Multi-Pass batch response source mismatch.');
 assertNotAborted(options.signal);
 const partitions:Array<{startByte:number;endByte:number}>=[];
 const sourceBytes=new TextEncoder().encode(raw);
 for(const [position,item] of value.events.entries()){
  if(!item||typeof item!=='object'||Array.isArray(item)||
    item.index!==position||!Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
    item.startByte<0||item.endByte>size||item.startByte>=item.endByte||
    !item.preview||typeof item.preview!=='object'||Array.isArray(item.preview))
    throw new Error('Invalid Multi-Pass batch event.');
  const eventRaw=utf8Slice(raw,item.startByte,item.endByte);
  item.preview=await verifySourcePreview(eventRaw,item.preview);
  assertNotAborted(options.signal);
  partitions.push({startByte:item.startByte,endByte:item.endByte});
 }
 for(const item of value.separators){
  if(!item||typeof item!=='object'||Array.isArray(item)||
    !Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
    item.startByte<0||item.endByte>size||item.startByte>=item.endByte||
    !['WHITESPACE','UTF8_BOM','SOURCE_METADATA','SOURCE_FRAMING'].includes(item.kind))
    throw new Error('Invalid Multi-Pass batch separator.');
  const bytes=sourceBytes.slice(item.startByte,item.endByte);
  if(item.kind==='UTF8_BOM'){
   if(item.startByte!==0||bytes.length!==3||bytes[0]!==0xef||bytes[1]!==0xbb||bytes[2]!==0xbf)
    throw new Error('Invalid Multi-Pass batch separator.');
  }else{
   let text:string;
   try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}
   catch{throw new Error('Invalid Multi-Pass batch separator.');}
   if(item.kind==='SOURCE_FRAMING'){
    if(!(text==='\0'||text==='\x1e'||text==='\n\n'||text==='\r\n\r\n'||
      (/^[1-9][0-9]{0,5} $/.test(text)&&Number(text.trim())<=65536)))
      throw new Error('Invalid source transport framing.');
   }else if(item.kind==='SOURCE_METADATA'){
    if(!/^#[^\r\n]*(?:\r?\n)?$/.test(text)||bytes.length>8194)
     throw new Error('Invalid Multi-Pass schema metadata.');
   }else if(!/^[ \t\r\n]+$/.test(text))throw new Error('Invalid Multi-Pass batch separator.');
  }
  partitions.push({startByte:item.startByte,endByte:item.endByte});
 }
 let cursor=0;
 for(const item of partitions.sort((a,b)=>a.startByte-b.startByte)){
  if(item.startByte!==cursor)throw new Error('Multi-Pass batch source accounting mismatch.');
  cursor=item.endByte;
 }
 if(cursor!==size)throw new Error('Multi-Pass batch source accounting mismatch.');
 return value as MultiPassBatchPreview;
}
