/** Review-only format boundary; no vendor decoder, field promotion or native claim.
 * Authoritative documentation confirms only the *scope* of an escape contract.
 * Source identity, actual device version and wire-mode require independent proof.
 */
export type DeclaredWireFormat='FORTIOS_RAW_KV'|'FORTIOS_CEF'|'RFC5424_SD'|
  'SONICOS_DEFAULT'|'SONICOS_ENHANCED'|'SONICOS_ARCSIGHT_CEF'|
  'SOPHOS_STANDARD'|'SOPHOS_LEGACY'|'UNKNOWN';
export type ObservedShape='KV_LEXICAL'|'CEF_HEADER'|'RFC5424_HEADER'|'OTHER';
export type EscapeEvidence='FORTIOS_7_2_CEF_EXTENSION_DOCUMENTED'|
  'RFC5424_STRUCTURED_DATA_DOCUMENTED'|'VENDOR_FORMAT_OPTIONS_ONLY'|
  'UNDEFINED_FOR_VERSION_OR_WIRE';
export type EscapeDisposition='REFERENCE_ONLY_REVIEW'|'FORMAT_CONFLICT_UNSCORABLE'|
  'VERSION_OR_WIRE_UNSCORABLE';
export type EscapeContractResult={
  disposition:EscapeDisposition;
  observedShape:ObservedShape;
  evidence:EscapeEvidence;
  manufacturerEscapeSemantics:'NOT_CERTIFIED';
  canDecodeVendorEscapes:false;
  canAutoPromote:false;
};

/** Detect structural signatures only; cannot prove sending device or version. */
export function observedWireShape(raw:string):ObservedShape{
  if(/^<[0-9]{1,3}>1 /.test(raw))return 'RFC5424_HEADER';
  if(/^(?:<[0-9]{1,3}>[ \t]*)?(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[^\s]+\s+)?CEF:[0-9]+\|/.test(raw))
    return 'CEF_HEADER';
  if(/^(?:<[0-9]{1,3}>[ \t]*)?[A-Za-z_][A-Za-z0-9_.-]*=/.test(raw)||
     /^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[^\s]+\s+[A-Za-z_][A-Za-z0-9_.-]*=/.test(raw))
    return 'KV_LEXICAL';
  return 'OTHER';
}

export function reviewEscapeContract(input:{
  raw:string;declared:DeclaredWireFormat;deviceVersion:string|null;
}):EscapeContractResult{
  const observed=observedWireShape(input.raw);
  const make=(disposition:EscapeDisposition,evidence:EscapeEvidence):EscapeContractResult=>({
    disposition,observedShape:observed,evidence,
    manufacturerEscapeSemantics:'NOT_CERTIFIED',
    canDecodeVendorEscapes:false,canAutoPromote:false,
  });
  const required:ObservedShape[]|null=(()=>{
    switch(input.declared){
      case 'FORTIOS_RAW_KV':
      case 'SONICOS_DEFAULT':
      case 'SONICOS_ENHANCED':
      case 'SOPHOS_STANDARD':
      case 'SOPHOS_LEGACY':return ['KV_LEXICAL'];
      case 'FORTIOS_CEF':
      case 'SONICOS_ARCSIGHT_CEF':return ['CEF_HEADER'];
      case 'RFC5424_SD':return ['RFC5424_HEADER'];
      default:return null;
    }
  })();
  if(!required||observed==='OTHER')
    return make('VERSION_OR_WIRE_UNSCORABLE','UNDEFINED_FOR_VERSION_OR_WIRE');
  if(!required.includes(observed))
    return make('FORMAT_CONFLICT_UNSCORABLE','UNDEFINED_FOR_VERSION_OR_WIRE');
  const version=input.deviceVersion;
  if(!version)
    return make('VERSION_OR_WIRE_UNSCORABLE','UNDEFINED_FOR_VERSION_OR_WIRE');
  if(input.declared==='FORTIOS_CEF'&&/^7\.2\.[0-9]+$/.test(version))
    return make('REFERENCE_ONLY_REVIEW','FORTIOS_7_2_CEF_EXTENSION_DOCUMENTED');
  if(input.declared==='RFC5424_SD')
    return make('REFERENCE_ONLY_REVIEW','RFC5424_STRUCTURED_DATA_DOCUMENTED');
  if((input.declared==='SONICOS_DEFAULT'||input.declared==='SONICOS_ENHANCED'||
      input.declared==='SONICOS_ARCSIGHT_CEF')&&/^7\.1(?:\.|$)/.test(version))
    return make('REFERENCE_ONLY_REVIEW','VENDOR_FORMAT_OPTIONS_ONLY');
  if((input.declared==='SOPHOS_STANDARD'||input.declared==='SOPHOS_LEGACY')&&
     /^20\.0(?:\.|$)/.test(version))
    return make('REFERENCE_ONLY_REVIEW','VENDOR_FORMAT_OPTIONS_ONLY');
  return make('VERSION_OR_WIRE_UNSCORABLE','UNDEFINED_FOR_VERSION_OR_WIRE');
}
