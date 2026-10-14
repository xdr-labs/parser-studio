import {sha256Utf8Hex} from '../sha256';

const DICTIONARY_REVISION='stellar-standard-metadata-7.0.xs-2026-10-14';
const DICTIONARY_URLS=[
 'https://docs.stellarcyber.ai/prod-docs/6.5.xs/Common/Metadata-Dictionary.htm?TocPath=REFERENCE%7C_____8',
 'https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm',
 'https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf',
] as const;
const DICTIONARY_TYPES=new Set(['string','integer','ip']);
const SAFE_PATH=/^[A-Za-z_][A-Za-z0-9_.\-[\]]{0,255}$/;
const CEF_ALIASES:Record<string,string>={src:'srcip',dst:'dstip',spt:'srcport',dpt:'dstport',act:'action'};

export interface MultiPassDictionaryProjection {
 contract:'parser-studio.stellar-dictionary-projection.v0.1';
 dictionaryRevision:string;
 sourceUrls:string[];
 mapped:Array<{sourcePath:string;targetField:string;documentedType:string;
  mappingClass:'EXACT_DICTIONARY_NAME'|'CEF_STANDARD_ALIAS';startByte:number;endByte:number}>;
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
 nativeVerified:false;targetVerified:false;
}
function mappingMatchesContract(sourcePath:string,targetField:string,mappingClass:string):boolean{
 if(mappingClass==='EXACT_DICTIONARY_NAME')
  return sourcePath===targetField||sourcePath===`body.${targetField}`;
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
   typeof item.sourcePath!=='string'||!SAFE_PATH.test(item.sourcePath)||
   typeof item.targetField!=='string'||!SAFE_PATH.test(item.targetField)||
   !DICTIONARY_TYPES.has(item.documentedType)||
   !['EXACT_DICTIONARY_NAME','CEF_STANDARD_ALIAS'].includes(item.mappingClass)||
   !mappingMatchesContract(item.sourcePath,item.targetField,item.mappingClass)||
   !Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
   item.startByte<0||item.endByte>size||item.startByte>=item.endByte||
   !spanKeys.has(item.sourcePath+'\0'+item.startByte+'\0'+item.endByte)||
   targets.has(item.targetField))
   throw new Error('Untrusted Stellar Dictionary projection.');
  targets.add(item.targetField);
 }
 if(value.issues.some(x=>typeof x!=='string'||x.length>160||
   !/^[A-Z0-9_.:-]+$/.test(x)))
  throw new Error('Untrusted Stellar Dictionary projection.');
 return value as MultiPassDictionaryProjection;
}
export async function requestMultiPassPreview(raw:string,requester:typeof fetch=fetch):Promise<MultiPassSourcePreview>{
 const size=new TextEncoder().encode(raw).byteLength;
 if(!size||size>65536)throw new Error('Source must be between 1 and 65536 UTF-8 bytes.');
 const response=await requester('/api/v1/multipass/preview',{method:'POST',
  headers:{'Content-Type':'application/json'},cache:'no-store',credentials:'same-origin',
  body:JSON.stringify({raw})});
 if(!response.ok)throw new Error('Multi-Pass preview is unavailable. No engine result was accepted.');
 const value=await response.json() as Partial<MultiPassSourcePreview>;
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
 for(const item of [...value.spans,...value.residuals]){
  if(!Number.isSafeInteger(item.startByte)||!Number.isSafeInteger(item.endByte)||
    item.startByte<0||item.endByte>size||item.startByte>=item.endByte)
    throw new Error('Invalid Multi-Pass byte span.');
 }
 if(value.dictionary!==undefined)
  value.dictionary=verifyDictionary(value.dictionary,value.spans,size);
 return value as MultiPassSourcePreview;
}
