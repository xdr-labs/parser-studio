import type {LexicalCandidate,SourceField,SourceSpan} from './losslessLexer';
import {assessPinnedSourceCandidate,type SourceTrustOutcome} from './sourceTrustRegistry';
import {sourceValueSupportsMapping} from './sourceNormalizationBoundary';
import {findStellarMetadataField} from '../guided/stellarMetadataCatalog';

/**
 * A bounded, reusable composition grammar for an IPv4 address, numeric port,
 * interface label and optional resolved hostname. No vendor-specific regex
 * rescues, no IPv6 guesses and no direct Stellar native parser output.
 */
export interface CompositeEndpointPart {
  role:'ipv4'|'port'|'interface'|'resolvedHost';
  value:string;
  sourceSpan:SourceSpan;
}
export interface CompositeEndpoint {
  original:string;
  parts:CompositeEndpointPart[];
  grammar:'ipv4_port_interface';
  complete:true;
  sourceValuePreserved:true;
}
export interface CompositeEndpointReview {
  contract:'parser-studio.composite-endpoint-review.v0.1';
  disposition:'REVIEWABLE_COMPONENTS_UNAPPROVED'|'SOURCE_REFERENCE_UNVERIFIED'|
    'SOURCE_FIELD_MISSING'|'SOURCE_FIELD_REPEATED'|'UNSUPPORTED_COMPOSITE'|
    'TARGET_TYPE_UNSUPPORTED';
  sourceOracleStatus:SourceTrustOutcome;
  componentCount:number;
  byteRanges:SourceSpan[];
  suggestedTargets:string[];
  sourceGrammarApproved:false;
  endpointSemanticApproved:false;
  normalizationApproved:false;
  nativeRuntimeVerified:false;
  productPromotionAllowed:false;
  requiresHumanReview:true;
}
const MAX_COMPOSITE_LENGTH=512;
const encoder=new TextEncoder();
const interfaceName=/^[A-Za-z][A-Za-z0-9_.\/-]{0,31}$/;
const hostnameLabel=/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
function validHostname(value:string):boolean{
  if(value.length>253)return false;
  const labels=value.split('.');
  return labels.length<=64&&labels.every(label=>hostnameLabel.test(label));
}

function ipv4(value:string):boolean{
  const pieces=value.split('.');
  if(pieces.length!==4)return false;
  return pieces.every(piece=>(piece==='0'||/^[1-9][0-9]{0,2}$/.test(piece))&&
    Number(piece)<=255);
}
const span=(raw:string,start:number,end:number):SourceSpan=>({
  start,end,
  startByte:encoder.encode(raw.slice(0,start)).length,
  endByte:encoder.encode(raw.slice(0,end)).length,
});

/** Pure source-part recognition, no inferred target semantics. */
export function parseCompositeIpPortInterface(value:string):{
  parts:Array<{role:CompositeEndpointPart['role'];value:string;start:number;end:number}>;
}|null{
  if(!value||value.length>MAX_COMPOSITE_LENGTH||/[\x00-\x20\x7f]/.test(value))
    return null;
  const segments=value.split(':');
  if(segments.length!==3&&segments.length!==4)return null;
  const [ip,port,label,resolved]=segments;
  if(!ip||!port||!label||!ipv4(ip)||!interfaceName.test(label)||
     label.includes('..')||label.includes('//')||label.includes('/.')||
     label.endsWith('/'))return null;
  if(!/^(?:0|[1-9][0-9]{0,4})$/.test(port)||Number(port)>65535)return null;
  if(resolved!==undefined&&!validHostname(resolved))
    return null;
  const roles=['ipv4','port','interface','resolvedHost'] as const;
  let cursor=0;
  const parts=segments.map((segment,index)=>{
    const start=cursor;
    const end=start+segment.length;
    cursor=end+1;
    return {role:roles[index]!,value:segment,start,end};
  });
  return {parts};
}

/** Retains exact source UTF-8 byte offsets for every split component. */
export function extractCompositeFromSource(
  raw:string,field:SourceField,
):CompositeEndpoint|null{
  if(!raw||field.valueSpan.start<0||field.valueSpan.end>raw.length||
    raw.slice(field.valueSpan.start,field.valueSpan.end)!==field.value)
    return null;
  const parsed=parseCompositeIpPortInterface(field.value);
  if(!parsed)return null;
  const parts=parsed.parts.map(part=>({
    role:part.role,value:part.value,
    sourceSpan:span(raw,field.valueSpan.start+part.start,field.valueSpan.start+part.end),
  }));
  if(parts.some(part=>raw.slice(part.sourceSpan.start,part.sourceSpan.end)!==part.value))
    return null;
  return {original:field.value,parts,grammar:'ipv4_port_interface',
    complete:true,sourceValuePreserved:true};
}

const no=(status:CompositeEndpointReview['disposition'],source:SourceTrustOutcome):
  CompositeEndpointReview=>({
  contract:'parser-studio.composite-endpoint-review.v0.1',
  disposition:status,sourceOracleStatus:source,componentCount:0,
  byteRanges:[],suggestedTargets:[],
  sourceGrammarApproved:false,endpointSemanticApproved:false,
  normalizationApproved:false,nativeRuntimeVerified:false,
  productPromotionAllowed:false,requiresHumanReview:true,
});

/**
 * Exact source field identity is necessary but not a semantic authorization.
 * Source/destination mapping role is supplied explicitly for human review.
 */
export async function reviewPinnedCompositeEndpoint(
  fixtureId:string,candidate:LexicalCandidate,sourceKey:string,
  proposedRole:'source'|'destination',
):Promise<CompositeEndpointReview>{
  const trust=await assessPinnedSourceCandidate(fixtureId,candidate);
  if(trust.outcome!=='PINNED_LEXICAL_MATCH_UNREVIEWED')
    return no('SOURCE_REFERENCE_UNVERIFIED',trust.outcome);
  const fields=candidate.fields.filter(f=>f.key===sourceKey);
  if(fields.length===0)return no('SOURCE_FIELD_MISSING',trust.outcome);
  if(fields.length!==1)return no('SOURCE_FIELD_REPEATED',trust.outcome);
  const parsed=extractCompositeFromSource(candidate.sourceRaw,fields[0]!);
  if(!parsed)return no('UNSUPPORTED_COMPOSITE',trust.outcome);
  const ip=parsed.parts.find(item=>item.role==='ipv4')!.value;
  const port=parsed.parts.find(item=>item.role==='port')!.value;
  const targets=proposedRole==='source'?['srcip','srcport']:['dstip','dstport'];
  const matching=targets.every((target,index)=>{
    const catalog=findStellarMetadataField(target);
    if(!catalog?.mappable||!catalog.mappingType)return false;
    return sourceValueSupportsMapping(target,catalog.mappingType,index===0?ip:port);
  });
  if(!matching)return no('TARGET_TYPE_UNSUPPORTED',trust.outcome);
  return {
    contract:'parser-studio.composite-endpoint-review.v0.1',
    disposition:'REVIEWABLE_COMPONENTS_UNAPPROVED',
    sourceOracleStatus:trust.outcome,
    componentCount:parsed.parts.length,
    byteRanges:parsed.parts.map(part=>part.sourceSpan),
    suggestedTargets:targets,
    sourceGrammarApproved:false,endpointSemanticApproved:false,
    normalizationApproved:false,nativeRuntimeVerified:false,
    productPromotionAllowed:false,requiresHumanReview:true,
  };
}
