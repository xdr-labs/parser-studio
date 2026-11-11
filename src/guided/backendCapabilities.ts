import {analyzeRuby24RegexCost,RUBY24_REGEX_REJECTION_TEXT} from '../../backend/src/ruby24-regex-cost';
import type { BackendParserProject } from './backendAdapter';
import {validatePreviewRegexPattern} from '../regexSafety';
import {GENERIC_STRUCTURAL_SINGLE_PROFILES,GENERIC_STRUCTURAL_MIXED_PROFILE_V1,
  isGenericStructuralProfile,isGenericStructuralSingleProfile,type GenericStructuralSingleProfile} from '../genericStructuralProfiles';

/** A private loopback API advertises supported authoring features, not deployment approval. */
export interface BackendCapabilities {
  contract: 'host-customized-pair.v0.1';
  projectSchemaRevision: '0.1';
  authoring: {
    receiverProtocols: Array<'udp' | 'tcp'>;
    extractionFormats: Array<'json' | 'kv' | 'csv' | 'syslog_rfc3164' | 'syslog_rfc5424' | 'cef' | 'leef' | 'mixed' | 'java_stacktrace' | 'regex' | 'generic_structural'>;
    genericStructuralGrammar?: 'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15';
    genericStructuralProfiles?: Array<GenericStructuralSingleProfile>;
    /** The explicit two-grammar combination is separate from the original profile list. */
    genericStructuralMixedProfileV1?: boolean;
    genericStructuralOmitSourceRaw?: boolean;
    formatCoverage: 'reviewed-bounded-subset';
    /** Mixed routing must be explicit; arbitrary vendor regex is never selected. */
    strictMixedSingleLineFamilies?: Array<'json'|'kv'|'cef'|'leef'|'rfc5424_cef'|'rfc5424_leef'|'rfc3164_kv'|'rfc5424_json'|'rfc5424_kv'|'rfc3164_cef'|'rfc3164_leef'|'csv'>;
    strictMixedRequiresExplicitAllowlist?: true;
    /** Per-family mapping is conditional within one generated parser artifact. */
    conditionalEventProfiles?: true;
    conditionalEventProfilesUnknownPolicy?: 'reject';
    declaredForwarderEnvelopeUnwrap?: true;
    declaredForwarderMaximumHops?: 3;
    declaredForwarderFormats?: readonly ['rfc3164','rfc5424'];
    jsonBlankLineTcpFraming?: true;
    jsonBlankLineOtherTransports?: false;
    jsonBlankLineDelimiter?: 'LF_LF';
    javaBlankLineTcpFraming?: true;
    javaBlankLineOtherTransports?: false;
    javaBlankLineDelimiter?: 'LF_LF';
    javaStackTraceGrammar?: 'EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1';
    boundedRegexNamedCaptureSubset?: true;
    boundedRegexMaxPatternChars?: 256;
    boundedRegexRuntimeTimeoutMs?: 50;
    rfc3164StrictTaggedMessageSubset?: true;
    rfc3164TaglessStructuredSecuritySubset?: true;
    rfc3164TimePolicy?: 'YEAR_AND_ZONE_UNKNOWN';
    rfc3164NativeTimeReconstruction?: false;
    rfc3164BodyFormats?: Array<'raw'|'json'|'kv'|'cef'|'leef'|'regex'>;
    /** Only advertised by backend revisions implementing bounded nested bodies/SD. */
    rfc5424BodyFormats?: Array<'raw' | 'json' | 'kv' | 'cef' | 'leef' | 'regex'>;
    rfc5424AdjacentStructuredDataSubset?: true;
    rfc5424StructuredDataMaxBytes?: 1024;
    leefHexSeparatorSubset?: true;
    httpReceiver: false;
    multipleDistinctReceiverPorts: false;
    multiline: false;
    arbitraryRuby: false;
  };
  /** Optional gated synthetic-only backend preview capabilities. Not sensor readiness. */
  testLab?: {
    offlineJsonPreview?: boolean;
    requiresBackendPreviewAuthorization?: boolean;
    liveSensorSenderEnabled?: boolean;
    trustedSinkSessionControlAvailable?: boolean;
    sessionControlRequiresBackendAuthorization?: boolean;
    sessionMaxRatePerSecond?: number;
    sessionMaxLeaseMs?: number;
    sessionMaxAdditionalEventsPerRenewal?: number;
    sessionMaxCumulativeEvents?: number;
    sessionRenewalRequiresSeparateApproval?: boolean;
    sessionDurableAcrossRestart?: boolean;
    serverInjectedUdpTcpSinkAvailable?: boolean;
    sinkRequiresIpLiteralAllowlist?: boolean;
    sinkRequiresPerDeliveryPolicyAndAudit?: boolean;
    /** Advertised query code is NOT a grant to read tenant event data. */
    /** Read-only bounded scenario preview; never implies sender readiness. */
    scenarioOfflinePreviewAvailable?: boolean;
    multiSampleReplayAvailable?: boolean;
    constantRateScenarioAvailable?: boolean;
    boundedOriginalGapsScenarioAvailable?: boolean;
    scenarioMaxSamples?: number;
    scenarioRunMarkerRequired?: boolean;
    interflowReadClientAvailable?: boolean;
    interflowBoundedPollingAvailable?: boolean;
    interflowMaxPollAttempts?: number;
    interflowMaxPollWindowMs?: number;
    interflowCursorVerified?: boolean;
    interflowSearchPermissionsVerified?: boolean;
    interflowRealTargetVerified?: boolean;
    sensorIngestVerified?: boolean;
    runtimeParsingVerified?: boolean;
  };
  downloads?: {
    individualGeneratedFiles: true;
    zipWithManifest: true;
    requiresDpConnection: false;
    requiresApiKey: false;
    autoDeploys: false;
    exactArtifactRevision: true;
    /** Target adapter capability, not a property of the portable project. */
    targetRuntimeProfile?:{
      profile:'stellar70-observed-ruby24';
      ruby:'2.4.9';
      fluentd:'1.7.4';
      regexPreviewSupported:true;
      regexExportSupported:true;
      regexExportMode:'ruby24-static-cost-proof';
      targetImportVerified:false;
    };
    /** Optional server-gated metadata, not owner authorization. */
    ownedOfflineRevisionHistoryOptIn?: true;
    ownedOfflineRevisionHttpAvailableWhenInjected?: true;
    revisionRestorePreviewNeverWritesTarget?: true;
    revisionHistoryDurableAcrossRestart?: boolean;
  };
  import: {
    exactInternalPairsEditable: true;
    unknownLegacyRubyEditable: false;
    structuralInspectionOnly: true;
    redactedImportLossReportHttpAvailable?: true;
    opaqueImportRemainsReadOnly?: true;
  };
  verification: {
    engineVerified: false;
    targetImportVerified: false;
    liveListenerVerified: false;
    proprietaryLoaderVerified: false;
    /** Applies to fixed synthetic corpus only, NEVER a generated user parser. */
    nativeSyntheticProfile?: 'ruby3.2.x-fluentd1.17.1';
    nativeCapabilityManifestHttpOptInAvailable?: true;
    nativeCapabilityManifestEnabledByDefault?: false;
  };
  limits: { maxProjectBodyBytes: number; maxInspectBodyBytes: number };
}

const BASE = '/api/v1/parser-pairs';
const KNOWN_FORMATS = new Set(['json', 'kv', 'csv', 'syslog_rfc3164', 'syslog_rfc5424', 'cef', 'leef', 'mixed', 'java_stacktrace','regex','generic_structural']);
const KNOWN_PROTOCOLS = new Set(['udp', 'tcp']);
const KNOWN_RFC_BODIES = new Set(['raw','json','kv','cef','leef','regex']);

export async function fetchBackendCapabilities(
  requester: typeof fetch = fetch,
): Promise<BackendCapabilities> {
  const response = await requester(BASE + '/capabilities', {
    method: 'GET',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });
  if (response.status !== 200) throw new Error('Backend capabilities request failed (HTTP ' + response.status + ').');
  let value: unknown;
  try { value = await response.json(); } catch {
    throw new Error('The capabilities API returned invalid JSON.');
  }
  if (!value || typeof value !== 'object') throw new Error('Backend capability contract is missing.');
  const cap = value as Partial<BackendCapabilities>;
  const a = cap.authoring;
  const im = cap.import;
  const v = cap.verification;
  const l = cap.limits;
  if (cap.contract !== 'host-customized-pair.v0.1' ||
      cap.projectSchemaRevision !== '0.1' ||
      !a || !Array.isArray(a.extractionFormats) || a.extractionFormats.length === 0 ||
      new Set(a.extractionFormats).size !== a.extractionFormats.length ||
      !a.extractionFormats.every((format) => KNOWN_FORMATS.has(format)) ||
      !Array.isArray(a.receiverProtocols) || a.receiverProtocols.length === 0 ||
      new Set(a.receiverProtocols).size !== a.receiverProtocols.length ||
      !a.receiverProtocols.every((p) => KNOWN_PROTOCOLS.has(p)) ||
      a.formatCoverage !== 'reviewed-bounded-subset' ||
      a.httpReceiver !== false || a.multipleDistinctReceiverPorts !== false ||
      a.multiline !== false || a.arbitraryRuby !== false ||
      im?.exactInternalPairsEditable !== true ||
      im.unknownLegacyRubyEditable !== false || im.structuralInspectionOnly !== true ||
      v?.engineVerified !== false || v.targetImportVerified !== false ||
      v.liveListenerVerified !== false || v.proprietaryLoaderVerified !== false ||
      !Number.isInteger(l?.maxProjectBodyBytes) || !Number.isInteger(l?.maxInspectBodyBytes) ||
      (l?.maxProjectBodyBytes ?? 0) < 1024 || (l?.maxInspectBodyBytes ?? 0) < 1024) {
    throw new Error('DRAFT generation blocked due to untrusted backend capabilities or verification flags.');
  }
  const conditionalClaims=[a.conditionalEventProfiles,
    a.conditionalEventProfilesUnknownPolicy,a.declaredForwarderEnvelopeUnwrap,
    a.declaredForwarderMaximumHops,a.declaredForwarderFormats];
  if(conditionalClaims.some(value=>value!==undefined)&&(
    a.conditionalEventProfiles!==true||
    a.conditionalEventProfilesUnknownPolicy!=='reject'||
    a.declaredForwarderEnvelopeUnwrap!==true||
    a.declaredForwarderMaximumHops!==3||
    JSON.stringify(a.declaredForwarderFormats)!=='["rfc3164","rfc5424"]'
  ))throw new Error('Untrusted conditional-family or declared-forwarder compiler claims.');
  const mixedAdvertised=a.extractionFormats.includes('mixed');
  const mixed=a.strictMixedSingleLineFamilies;
  const reviewedMixed=['json','kv','cef','leef'];
  const wrapped=['rfc5424_cef','rfc5424_leef'];
  const nested=['rfc5424_json','rfc5424_kv'];
  if(mixedAdvertised){
    if(a.strictMixedRequiresExplicitAllowlist!==true||
      !Array.isArray(mixed)||![4,6,7,9,11,12].includes(mixed.length)||
      new Set(mixed).size!==mixed.length||
      !reviewedMixed.every(f=>mixed.includes(f as 'json'))||
      (mixed.length>=6&&!wrapped.every(f=>mixed.includes(f as 'rfc5424_cef')))||
      (mixed.length>=7&&!mixed.includes('rfc3164_kv'))||
      (mixed.length>=9&&!nested.every(f=>mixed.includes(f as 'rfc5424_json')))||
      (mixed.length>=11&&!['rfc3164_cef','rfc3164_leef'].every(f=>
        mixed.includes(f as 'rfc3164_cef')))||
      (mixed.length===12&&!mixed.includes('csv')))
      throw new Error('Backend mixed routing requires one of the exact reviewed family allowlists.');
  }else if(mixed!==undefined||a.strictMixedRequiresExplicitAllowlist!==undefined)
    throw new Error('Unsupported mixed routing capability was advertised.');
  if((a.jsonBlankLineTcpFraming!==undefined||
      a.jsonBlankLineOtherTransports!==undefined||
      a.jsonBlankLineDelimiter!==undefined)&&
    (a.jsonBlankLineTcpFraming!==true||
     a.jsonBlankLineOtherTransports!==false||
     a.jsonBlankLineDelimiter!=='LF_LF'))
    throw new Error('Untrusted explicit TCP blank-line JSON framing contract.');
  const javaAdvertised=a.extractionFormats.includes('java_stacktrace');
  const javaClaims=[
    a.javaBlankLineTcpFraming,a.javaBlankLineOtherTransports,
    a.javaBlankLineDelimiter,a.javaStackTraceGrammar,
  ];
  if(javaAdvertised&&(
    a.javaBlankLineTcpFraming!==true||
    a.javaBlankLineOtherTransports!==false||
    a.javaBlankLineDelimiter!=='LF_LF'||
    a.javaStackTraceGrammar!=='EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1'))
    throw new Error('Java Stack Trace requires the exact bounded TCP LF LF native framing contract.');
  if(!javaAdvertised&&javaClaims.some(x=>x!==undefined))
    throw new Error('Untrusted Java frame capability without parser support.');
  const genericStructuralAdvertised=a.extractionFormats.includes('generic_structural');
  if(genericStructuralAdvertised&&a.genericStructuralGrammar!=='GENERIC_STRUCTURAL_ULTRA_COMPILER_V15')
    throw new Error('Generic Structural authoring requires the exact bounded compiler grammar.');
  if(!genericStructuralAdvertised&&a.genericStructuralGrammar!==undefined)
    throw new Error('Untrusted Generic Structural capability without parser support.');
  if(a.genericStructuralProfiles!==undefined&&(
    !genericStructuralAdvertised||!Array.isArray(a.genericStructuralProfiles)||
    a.genericStructuralProfiles.length<1||a.genericStructuralProfiles.length>GENERIC_STRUCTURAL_SINGLE_PROFILES.length||
    new Set(a.genericStructuralProfiles).size!==a.genericStructuralProfiles.length||
    !a.genericStructuralProfiles.every(isGenericStructuralSingleProfile)))
    throw new Error('Untrusted additional Generic Structural profile capability.');
  if(a.genericStructuralMixedProfileV1!==undefined&&(
    !genericStructuralAdvertised||typeof a.genericStructuralMixedProfileV1!=='boolean'))
    throw new Error('Untrusted combined Generic Structural profile capability.');
  if(a.genericStructuralOmitSourceRaw!==undefined&&(
    !genericStructuralAdvertised||typeof a.genericStructuralOmitSourceRaw!=='boolean'))
    throw new Error('Untrusted Generic Structural raw-line option capability.');
  const regexAdvertised=a.extractionFormats.includes('regex');
  const regexClaims=[a.boundedRegexNamedCaptureSubset,a.boundedRegexMaxPatternChars,
    a.boundedRegexRuntimeTimeoutMs];
  if(regexAdvertised&&(
    a.boundedRegexNamedCaptureSubset!==true||
    a.boundedRegexMaxPatternChars!==256||
    a.boundedRegexRuntimeTimeoutMs!==50))
    throw new Error('Regex authoring requires the exact bounded named-capture contract.');
  if(!regexAdvertised&&regexClaims.some(x=>x!==undefined))
    throw new Error('Untrusted Regex capability without parser support.');
  const rfc3164Advertised=a.extractionFormats.includes('syslog_rfc3164');
  if(rfc3164Advertised&&(
      a.rfc3164StrictTaggedMessageSubset!==true||
      a.rfc3164TimePolicy!=='YEAR_AND_ZONE_UNKNOWN'||
      a.rfc3164NativeTimeReconstruction!==false||
      !Array.isArray(a.rfc3164BodyFormats)||
      a.rfc3164BodyFormats.length!==KNOWN_RFC_BODIES.size||
      new Set(a.rfc3164BodyFormats).size!==KNOWN_RFC_BODIES.size||
      !a.rfc3164BodyFormats.every(mode=>KNOWN_RFC_BODIES.has(mode))
  ))throw new Error('Untrusted RFC3164 authoring capability and timestamp policy.');
  if(!rfc3164Advertised&&(a.rfc3164StrictTaggedMessageSubset!==undefined||
     a.rfc3164BodyFormats!==undefined||a.rfc3164TimePolicy!==undefined||
     a.rfc3164NativeTimeReconstruction!==undefined))
    throw new Error('RFC3164 claims are inconsistent with the available formats.');
  const extended = a.rfc5424BodyFormats !== undefined ||
    a.rfc5424AdjacentStructuredDataSubset !== undefined ||
    a.rfc5424StructuredDataMaxBytes !== undefined ||
    a.leefHexSeparatorSubset !== undefined;
  if (extended && (
    !Array.isArray(a.rfc5424BodyFormats) ||
    a.rfc5424BodyFormats.length < 3 ||
    a.rfc5424BodyFormats.length > KNOWN_RFC_BODIES.size ||
    new Set(a.rfc5424BodyFormats).size !== a.rfc5424BodyFormats.length ||
    !a.rfc5424BodyFormats.every((mode) => KNOWN_RFC_BODIES.has(mode)) ||
    a.rfc5424AdjacentStructuredDataSubset !== true ||
    a.rfc5424StructuredDataMaxBytes !== 1024 ||
    a.leefHexSeparatorSubset !== true
  )) throw new Error('Extended RFC5424/LEEF capability declarations do not match the reviewed contract.');
  if (cap.downloads !== undefined) {
    const dl = cap.downloads;
    const coreKeys='autoDeploys,exactArtifactRevision,individualGeneratedFiles,requiresApiKey,requiresDpConnection,zipWithManifest';
    const extendedKeys='autoDeploys,exactArtifactRevision,individualGeneratedFiles,ownedOfflineRevisionHistoryOptIn,ownedOfflineRevisionHttpAvailableWhenInjected,requiresApiKey,requiresDpConnection,revisionHistoryDurableAcrossRestart,revisionRestorePreviewNeverWritesTarget,zipWithManifest';
    const actualKeys=Object.keys(dl).filter(key=>key!=='targetRuntimeProfile').sort().join(',');
    const runtime=dl.targetRuntimeProfile;
    if(runtime!==undefined&&(
      Object.keys(runtime).sort().join(',')!=='fluentd,profile,regexExportMode,regexExportSupported,regexPreviewSupported,ruby,targetImportVerified'||
      runtime.profile!=='stellar70-observed-ruby24'||
      runtime.ruby!=='2.4.9'||runtime.fluentd!=='1.7.4'||
      runtime.regexPreviewSupported!==true||
      runtime.regexExportSupported!==true||
      runtime.regexExportMode!=='ruby24-static-cost-proof'||
      runtime.targetImportVerified!==false))
      throw new Error('Untrusted or unverified target Regex export capability.');
    if (!dl || typeof dl !== 'object' ||
        (actualKeys !== coreKeys && actualKeys !== extendedKeys) ||
        dl.individualGeneratedFiles !== true || dl.zipWithManifest !== true ||
        dl.requiresDpConnection !== false || dl.requiresApiKey !== false ||
        dl.autoDeploys !== false || dl.exactArtifactRevision !== true ||
        (actualKeys === extendedKeys &&
          (dl.ownedOfflineRevisionHistoryOptIn !== true ||
           dl.ownedOfflineRevisionHttpAvailableWhenInjected !== true ||
           dl.revisionRestorePreviewNeverWritesTarget !== true ||
           typeof dl.revisionHistoryDurableAcrossRestart !== 'boolean'))) {
      throw new Error('Backend ZIP/revision capabilities do not match the reviewed contract.');
    }
  }
  // Native capability evidence is an opt-in fixed synthetic manifest, not
  // per-project compiler/native execution or a proof of vendor installation.
  const nativeKeys=['nativeSyntheticProfile','nativeCapabilityManifestHttpOptInAvailable',
    'nativeCapabilityManifestEnabledByDefault'] as const;
  if (nativeKeys.some(k=>v[k]!==undefined) &&
    (v.nativeSyntheticProfile!=='ruby3.2.x-fluentd1.17.1' ||
     v.nativeCapabilityManifestHttpOptInAvailable!==true ||
     v.nativeCapabilityManifestEnabledByDefault!==false)) {
    throw new Error('Native manifest capability must remain synthetic-only and disabled by default.');
  }
  const importKeys=['redactedImportLossReportHttpAvailable','opaqueImportRemainsReadOnly'] as const;
  if(importKeys.some(k=>im[k]!==undefined) &&
    (im.redactedImportLossReportHttpAvailable!==true || im.opaqueImportRemainsReadOnly!==true)) {
    throw new Error('Backend import capability cannot widen opaque legacy write access.');
  }
  return cap as BackendCapabilities;
}

export function assertBackendProjectSupported(project: BackendParserProject, cap: BackendCapabilities): void {
  if(project.normalization.eventProfiles&&(
    cap.authoring.conditionalEventProfiles!==true||
    cap.authoring.conditionalEventProfilesUnknownPolicy!=='reject'))
    throw new Error('Event-family routing requires reviewed backend compiler capability.');
  if(project.extraction.forwarder&&(
    cap.authoring.declaredForwarderEnvelopeUnwrap!==true||
    cap.authoring.declaredForwarderMaximumHops!==3||
    JSON.stringify(cap.authoring.declaredForwarderFormats)!=='["rfc3164","rfc5424"]'))
    throw new Error('Forwarder relay parsing requires exact backed Ruby compiler capability.');
  if(project.normalization.eventProfiles&&(
    cap.authoring.conditionalEventProfiles!==true||
    cap.authoring.conditionalEventProfilesUnknownPolicy!=='reject'))
    throw new Error('Event-family conditional output requires an explicit reviewed native compiler capability.');
  if(project.extraction.forwarder&&(
    cap.authoring.declaredForwarderEnvelopeUnwrap!==true||
    cap.authoring.declaredForwarderMaximumHops!==3))
    throw new Error('Declared relay prefixes need exact backend compiler capability.');

  if(project.receiver.tcpFraming==='blank_line_json'&&(
    cap.authoring.jsonBlankLineTcpFraming!==true||
    cap.authoring.jsonBlankLineOtherTransports!==false||
    cap.authoring.jsonBlankLineDelimiter!=='LF_LF'||
    project.extraction.format!=='json'||
    project.receiver.protocols.length!==1||
    project.receiver.protocols[0]!=='tcp'))
    throw new Error('Backend did not explicitly verify TCP-only blank-line JSON framing.');
  let regexPattern:string|undefined;
  const extraction=project.extraction;
  if(extraction.format==='regex')regexPattern=extraction.pattern;
  else if('syslogBodyFormat' in extraction&&
    (extraction.format==='syslog_rfc3164'||extraction.format==='syslog_rfc5424')&&
    extraction.syslogBodyFormat==='regex'&&'pattern' in extraction)
    regexPattern=extraction.pattern;
  if(regexPattern!==undefined&&cap.downloads?.targetRuntimeProfile?.regexExportSupported!==true)
    throw Object.assign(new Error(
      'Regex samples may be reviewed in the browser, but this backend does not advertise Regex export for the Stellar Cyber 7.0 Ruby 2.4.9 target. Parser files and ZIP export are blocked; use a supported non-Regex grammar.'),
      {code:'TARGET_RUNTIME_REGEX_UNSUPPORTED'});
  if(regexPattern!==undefined){
    const cost=analyzeRuby24RegexCost(regexPattern);
    if(!cost.ok)
      throw Object.assign(new Error(
        'This Regex can be reviewed in the browser but cannot be exported for Stellar Cyber 7.0 (Ruby 2.4.9 has no Regexp timeout, so only anchored patterns with statically bounded backtracking are allowed): '+
        RUBY24_REGEX_REJECTION_TEXT[cost.reason]+'.'),
        {code:'TARGET_RUNTIME_REGEX_UNSUPPORTED'});
  }
  if(regexPattern!==undefined&&(
    cap.authoring.boundedRegexNamedCaptureSubset!==true||
    cap.authoring.boundedRegexMaxPatternChars!==256||
    cap.authoring.boundedRegexRuntimeTimeoutMs!==50||
    validatePreviewRegexPattern(regexPattern)!==null))
    throw new Error('Regex DRAFT requires the exact bounded named-capture safety contract.');
  if(project.extraction.format==='generic_structural'&&(
    project.receiver.port<6800||
    cap.authoring.genericStructuralGrammar!=='GENERIC_STRUCTURAL_ULTRA_COMPILER_V15'))
    throw new Error('Generic Structural DRAFT requires the exact bounded grammar and listener port >=6800.');
  if(project.extraction.genericStructuralProfile!==undefined){
    const profile=project.extraction.genericStructuralProfile;
    if(project.extraction.format!=='generic_structural'||
      !isGenericStructuralProfile(profile))
      throw new Error('The backend does not advertise the selected Generic Structural profile.');
    const supported=profile===GENERIC_STRUCTURAL_MIXED_PROFILE_V1
      ?cap.authoring.genericStructuralMixedProfileV1===true
      :cap.authoring.genericStructuralProfiles?.includes(profile);
    if(!supported)
      throw Object.assign(new Error('The backend does not advertise the selected Generic Structural profile.'),
        {code:'BACKEND_PROFILE_UNSUPPORTED'});
  }
  if(project.extraction.omitSourceRaw!==undefined&&(
    project.extraction.format!=='generic_structural'||project.extraction.omitSourceRaw!==true||
    cap.authoring.genericStructuralOmitSourceRaw!==true))
    throw Object.assign(new Error('The backend does not support leaving the raw line out of the Generic Structural output.'),
      {code:'BACKEND_PROFILE_UNSUPPORTED'});
  if(project.extraction.format==='java_stacktrace'&&(
    project.receiver.tcpFraming!=='blank_line_java'||
    project.receiver.protocols.length!==1||
    project.receiver.protocols[0]!=='tcp'||
    cap.authoring.javaBlankLineTcpFraming!==true||
    cap.authoring.javaBlankLineOtherTransports!==false||
    cap.authoring.javaBlankLineDelimiter!=='LF_LF'||
    cap.authoring.javaStackTraceGrammar!=='EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1'))
    throw new Error('Java DRAFT requires explicit bounded TCP-only LF LF framing.');
  if (project.extraction.format === 'syslog_rfc5424') {
    const mode = project.extraction.syslogBodyFormat ?? 'raw';
    if (!cap.authoring.rfc5424BodyFormats?.includes(mode)) {
      throw new Error('Backend does not explicitly support RFC5424-embedded ' + mode.toUpperCase() + ' extraction.');
    }
  }
  if(project.extraction.format==='syslog_rfc3164'){
    const mode=project.extraction.syslogBodyFormat??'raw';
    if(cap.authoring.rfc3164StrictTaggedMessageSubset!==true||
      cap.authoring.rfc3164TimePolicy!=='YEAR_AND_ZONE_UNKNOWN'||
      cap.authoring.rfc3164NativeTimeReconstruction!==false||
      !cap.authoring.rfc3164BodyFormats?.includes(mode))
      throw new Error('Backend does not explicitly support reviewed RFC3164 '+mode.toUpperCase()+' extraction.');
  }
  if(project.extraction.format==='mixed'){
    const formats=project.extraction.mixedFormats;
    if(formats.includes('csv')&&(
      !Array.isArray(project.extraction.csvColumns)||
      project.extraction.csvColumns.length<2||
      ![',',';','\t'].includes(project.extraction.csvDelimiter??'INVALID')))
      throw new Error('Mixed CSV requires explicit reviewed column names and delimiter.');
    if(formats.some(f=>['rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef'].includes(f))&&
       project.receiver.port<6800)
      throw new Error('Syslog-wrapped mixed parser sensor/CONF listener port must be >=6800.');
    if(formats.some(f=>f.startsWith('rfc3164_'))&&(
      cap.authoring.rfc3164StrictTaggedMessageSubset!==true||
      cap.authoring.rfc3164TimePolicy!=='YEAR_AND_ZONE_UNKNOWN'||
      cap.authoring.rfc3164NativeTimeReconstruction!==false||
      !formats.filter(f=>f.startsWith('rfc3164_')).every(f=>
        cap.authoring.rfc3164BodyFormats?.includes(f.slice(8) as 'kv'|'cef'|'leef'))))
      throw new Error('Backend must explicitly support yearless RFC3164 mixed TAG KV.');
    if(cap.authoring.strictMixedRequiresExplicitAllowlist!==true||
      !Array.isArray(formats)||formats.length<2||formats.length>4||
      new Set(formats).size!==formats.length||
      !formats.every(f=>cap.authoring.strictMixedSingleLineFamilies?.includes(f)))
      throw new Error('Backend does not support the explicitly reviewed mixed-format allowlist.');
  }
  if (!cap.authoring.extractionFormats.includes(project.extraction.format)) {
    throw new Error('Backend did not confirm support for ' + project.extraction.format.toUpperCase() + ' format.');
  }
  if (!project.receiver.protocols.every((protocol) => cap.authoring.receiverProtocols.includes(protocol))) {
    throw new Error('Backend does not support the selected UDP/TCP receiver protocol.');
  }
  if (new TextEncoder().encode(JSON.stringify(project)).length > cap.limits.maxProjectBodyBytes) {
    throw new Error('Backend project size limit exceeded.');
  }
}
