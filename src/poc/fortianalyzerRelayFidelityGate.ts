/** Documentation-backed relay-stage source fidelity review; isolated PoC only.
 *
 * FortiAnalyzer 7.6.6 log-forward documents transparent forward, encapsulation,
 * enrichment, masking, exclusions, base64 decoding and CVE enrichment separately.
 * A matched collector message is never proof of an identical upstream device event.
 */
export type RelayServerType='syslog'|'cef'|'other';
export type RelayWireFormat='fgt'|'rfc-5424'|null;
export type TransparentMode='enable'|'disable'|'faz-enrich'|null;
export type Toggle='enable'|'disable'|null;
export type SourceIpMode='original_ip'|'local_ip'|null;
export type RelayOrigin='DEVICE_CONFIGURATION_EXPORT_CLAIM'|'USER_DECLARED'|
  'VENDOR_DOCUMENTATION'|'REPOSITORY_FIXTURE';
export type RelayEffect=
  'REENCODED_CEF'|'FORTIANALYZER_SYSLOG_WRAPPER'|'FORTIANALYZER_FIELDS_ENRICHED'|
  'FIELDS_MASKED'|'FIELDS_EXCLUDED'|'ATTACKCONTEXT_BASE64_DECODED'|
  'CVE_FIELD_ENRICHED'|'ORIGIN_IP_REWRITTEN'|'TRANSPARENCY_NOT_ATTESTED';
export type RelayDisposition=
  'VERSION_NOT_DOCUMENTED'|'UNVERIFIED_CONFIGURATION_ORIGIN'|
  'FORWARDING_STATE_UNSCORABLE'|'INCOMPLETE_OR_CONFLICTING_CONFIGURATION'|
  'UNSUPPORTED_DESTINATION'|'PAYLOAD_TRANSFORMED_REVIEW_ONLY'|
  'TRANSPARENT_CLAIM_UNATTESTED';
export type FortiAnalyzerRelayConfig={
  producer:'FORTIANALYZER';
  deviceVersion:string|null;
  configOrigin:RelayOrigin;
  forwarding:'forwarding'|'aggregation'|'disable'|null;
  serverType:RelayServerType|null;
  wireFormat:RelayWireFormat;
  transparent:TransparentMode;
  masking:Toggle;
  fieldExclusion:Toggle;
  decodeBase64:Toggle;
  enrichCve:Toggle;
  sourceIp:SourceIpMode;
};
export type RelayReview={
  disposition:RelayDisposition;
  documentedForVersion:'FORTIANALYZER_7_6_6_CLI_ONLY'|'NOT_DOCUMENTED';
  effects:RelayEffect[];
  payloadFidelity:'UNKNOWN'|'POTENTIALLY_TRANSFORMED'|'TRANSPARENT_CONFIG_UNATTESTED';
  originalDeviceByteEquivalence:'NOT_PROVEN';
  collectorInputOnly:true;
  vendorEscapeSemantics:'NOT_CERTIFIED';
  nativeTarget:'NOT_VERIFIED';
  canAutoPromote:false;
};
const version='7.6.6';
const isToggle=(value:Toggle):value is Exclude<Toggle,null>=>
  value==='enable'||value==='disable';
export function reviewFortiAnalyzerRelayFidelity(config:FortiAnalyzerRelayConfig):RelayReview{
  const effects:RelayEffect[]=[];
  const result=(disposition:RelayDisposition):RelayReview=>({
    disposition,documentedForVersion:config.deviceVersion===version?
      'FORTIANALYZER_7_6_6_CLI_ONLY':'NOT_DOCUMENTED',
    effects,payloadFidelity:disposition==='PAYLOAD_TRANSFORMED_REVIEW_ONLY'?
      'POTENTIALLY_TRANSFORMED':disposition==='TRANSPARENT_CLAIM_UNATTESTED'?
      'TRANSPARENT_CONFIG_UNATTESTED':'UNKNOWN',
    originalDeviceByteEquivalence:'NOT_PROVEN',
    collectorInputOnly:true,
    vendorEscapeSemantics:'NOT_CERTIFIED',nativeTarget:'NOT_VERIFIED',
    canAutoPromote:false,
  });
  // Only exact version with an independently pinned public CLI reference is scoped.
  if(config.deviceVersion!==version)return result('VERSION_NOT_DOCUMENTED');
  if(config.configOrigin!=='DEVICE_CONFIGURATION_EXPORT_CLAIM')
    return result('UNVERIFIED_CONFIGURATION_ORIGIN');
  if(config.forwarding!=='forwarding')return result('FORWARDING_STATE_UNSCORABLE');
  if(!config.serverType||config.serverType==='other')
    return result('UNSUPPORTED_DESTINATION');
  if(!isToggle(config.masking)||!isToggle(config.fieldExclusion)||
     config.sourceIp===null)
    return result('INCOMPLETE_OR_CONFLICTING_CONFIGURATION');
  // CEF is not the syslog-format selector: it has its own output encoding.
  if(config.serverType==='cef'){
    if(config.wireFormat!==null||config.transparent!==null||
      config.decodeBase64!==null||config.enrichCve!==null)
      return result('INCOMPLETE_OR_CONFLICTING_CONFIGURATION');
    effects.push('REENCODED_CEF');
  }else{
    if(!config.wireFormat||!config.transparent||
      !isToggle(config.decodeBase64)||!isToggle(config.enrichCve))
      return result('INCOMPLETE_OR_CONFLICTING_CONFIGURATION');
    if(config.transparent==='disable')
      effects.push('FORTIANALYZER_SYSLOG_WRAPPER');
    if(config.transparent==='faz-enrich')
      effects.push('FORTIANALYZER_FIELDS_ENRICHED');
    if(config.decodeBase64==='enable')
      effects.push('ATTACKCONTEXT_BASE64_DECODED');
    if(config.enrichCve==='enable')
      effects.push('CVE_FIELD_ENRICHED');
  }
  if(config.masking==='enable')effects.push('FIELDS_MASKED');
  if(config.fieldExclusion==='enable')effects.push('FIELDS_EXCLUDED');
  // Changing the packet source IP does not prove payload bytes changed.
  if(config.sourceIp==='local_ip')effects.push('ORIGIN_IP_REWRITTEN');
  if(!effects.some(x=>x!=='ORIGIN_IP_REWRITTEN')){
    effects.push('TRANSPARENCY_NOT_ATTESTED');
    return result('TRANSPARENT_CLAIM_UNATTESTED');
  }
  return result('PAYLOAD_TRANSFORMED_REVIEW_ONLY');
}
