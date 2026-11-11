import { describe, expect, it, vi } from 'vitest';
import { createDraft } from '../model';
import { toBackendProject } from './backendAdapter';
import { fetchBackendCapabilities, assertBackendProjectSupported } from './backendCapabilities';

const capabilities = {
  contract: 'host-customized-pair.v0.1',
  projectSchemaRevision: '0.1',
  authoring: {
    receiverProtocols: ['udp', 'tcp'],
    extractionFormats: ['json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef'],
    httpReceiver: false, multipleDistinctReceiverPorts: false, formatCoverage: 'reviewed-bounded-subset',
    multiline: false, arbitraryRuby: false,
  },
  import: { exactInternalPairsEditable: true, unknownLegacyRubyEditable: false, structuralInspectionOnly: true },
  verification: { engineVerified: false, targetImportVerified: false, liveListenerVerified: false, proprietaryLoaderVerified: false },
  limits: { maxProjectBodyBytes: 262144, maxInspectBodyBytes: 2097152 },
};
function csvProject() {
  const draft = createDraft(); draft.format = 'csv'; draft.csvColumns = 'action,src_ip,dst_port';
  const result = toBackendProject(draft);
  if (!result.ok) throw new Error('CSV adapter failed');
  return result.project;
}
function response(status: number, payload: unknown): Response {
  return { status, json: async () => payload } as Response;
}
describe('read-only backend capabilities (never native target approval)', () => {
  it('GETs same-origin metadata only and approves advertised CSV', async () => {
    const request = vi.fn(async () => response(200, capabilities)) as unknown as typeof fetch;
    const result = await fetchBackendCapabilities(request);
    expect(() => assertBackendProjectSupported(csvProject(), result)).not.toThrow();
    const [url, init] = (request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/parser-pairs/capabilities');
    expect(init.method).toBe('GET');
    expect(init.credentials).toBe('same-origin');
    expect(init.cache).toBe('no-store');
    expect(init.body).toBeUndefined();
  });
  it('keeps CSV locked if backend advertises only JSON/KV', async () => {
    const request = vi.fn(async () => response(200, {
      ...capabilities, authoring: { ...capabilities.authoring, extractionFormats: ['json', 'kv'] },
    })) as unknown as typeof fetch;
    const result = await fetchBackendCapabilities(request);
    expect(() => assertBackendProjectSupported(csvProject(), result)).toThrow(/CSV|csv/);
  });
  it.each([
    { ...capabilities, projectSchemaRevision: '0.2' },
    { ...capabilities, authoring: { ...capabilities.authoring, extractionFormats: ['json', 'unknown'] } },
    { ...capabilities, authoring: { ...capabilities.authoring, multiline: true } },
    { ...capabilities, verification: { ...capabilities.verification, targetImportVerified: true } },
    { ...capabilities, import: { ...capabilities.import, unknownLegacyRubyEditable: true } },
  ])('rejects unreviewed or upgraded capability claims', async (broken) => {
    const request = vi.fn(async () => response(200, broken)) as unknown as typeof fetch;
    await expect(fetchBackendCapabilities(request)).rejects.toThrow();
  });
  it('accepts exact latest backend offline revision and public-synthetic manifest extensions',async()=>{
    const current={...capabilities,
      downloads:{individualGeneratedFiles:true,zipWithManifest:true,
        requiresDpConnection:false,requiresApiKey:false,autoDeploys:false,
        exactArtifactRevision:true,ownedOfflineRevisionHistoryOptIn:true,
        ownedOfflineRevisionHttpAvailableWhenInjected:true,
        revisionRestorePreviewNeverWritesTarget:true,
        revisionHistoryDurableAcrossRestart:false},
      import:{...capabilities.import,redactedImportLossReportHttpAvailable:true,
        opaqueImportRemainsReadOnly:true},
      verification:{...capabilities.verification,
        nativeSyntheticProfile:'ruby3.2.x-fluentd1.17.1',
        nativeCapabilityManifestHttpOptInAvailable:true,
        nativeCapabilityManifestEnabledByDefault:false},
    };
    const fetcher=vi.fn(async()=>response(200,current)) as unknown as typeof fetch;
    const safe=await fetchBackendCapabilities(fetcher);
    expect(safe.downloads?.revisionHistoryDurableAcrossRestart).toBe(false);
    expect(safe.verification.targetImportVerified).toBe(false);
    expect(safe.verification.engineVerified).toBe(false);
    expect(safe.verification.nativeCapabilityManifestEnabledByDefault).toBe(false);
    expect(() => assertBackendProjectSupported(csvProject(),safe)).not.toThrow();
  });
  it.each([
    {ownedOfflineRevisionHttpAvailableWhenInjected:false},
    {revisionRestorePreviewNeverWritesTarget:false},
    {ownedOfflineRevisionHistoryOptIn:'true'},
    {revisionHistoryDurableAcrossRestart:'true'},
    {arbitraryUnknownFlag:true},
  ])('fails closed for forged or incomplete revision history extensions',async delta=>{
    const caps={...capabilities,downloads:{
      individualGeneratedFiles:true,zipWithManifest:true,
      requiresDpConnection:false,requiresApiKey:false,autoDeploys:false,
      exactArtifactRevision:true,ownedOfflineRevisionHistoryOptIn:true,
      ownedOfflineRevisionHttpAvailableWhenInjected:true,
      revisionRestorePreviewNeverWritesTarget:true,
      revisionHistoryDurableAcrossRestart:false,...delta},
    };
    await expect(fetchBackendCapabilities(vi.fn(async()=>response(200,caps)) as unknown as typeof fetch)).rejects.toThrow();
  });
  it('rejects forged verified public-synthetic native manifest flags',async()=>{
    const forged={...capabilities,verification:{...capabilities.verification,
      nativeSyntheticProfile:'ruby3.2.x-fluentd1.17.1',
      nativeCapabilityManifestHttpOptInAvailable:true,
      nativeCapabilityManifestEnabledByDefault:true}};
    await expect(fetchBackendCapabilities(vi.fn(async()=>response(200,forged)) as unknown as typeof fetch)).rejects.toThrow();
  });
  it('rejects unavailable and non-json capability API', async () => {
    await expect(fetchBackendCapabilities(vi.fn(async () => response(404, {})) as unknown as typeof fetch)).rejects.toThrow();
    await expect(fetchBackendCapabilities(vi.fn(async () => ({ status:200, json:async () => { throw Error('bad'); } })) as unknown as typeof fetch)).rejects.toThrow();
  });
});


describe('Stellar 7 Ruby2.4 native Regex export boundary',()=>{
  const regexCapability={
    ...capabilities,
    authoring:{
      ...capabilities.authoring,
      extractionFormats:['json','kv','csv','regex'],
      boundedRegexNamedCaptureSubset:true,
      boundedRegexMaxPatternChars:256,
      boundedRegexRuntimeTimeoutMs:50,
    },
    downloads:{
      individualGeneratedFiles:true,zipWithManifest:true,
      requiresDpConnection:false,requiresApiKey:false,autoDeploys:false,
      exactArtifactRevision:true,
      targetRuntimeProfile:{
        profile:'stellar70-observed-ruby24',
        ruby:'2.4.9',fluentd:'1.7.4',
        regexPreviewSupported:true,regexExportSupported:true,
        regexExportMode:'ruby24-static-cost-proof',
        targetImportVerified:false,
      },
    },
  };
  const supported=async (source:unknown)=>{
    return fetchBackendCapabilities(vi.fn(async()=>response(200,source)) as unknown as typeof fetch);
  };
  it('keeps normal JSON export, allows statically bounded Regex, refuses unbounded Regex with a reason',async()=>{
    const cap=await supported(regexCapability);
    const parser=csvProject();
    expect(()=>assertBackendProjectSupported(parser,cap)).not.toThrow();
    parser.extraction={format:'regex',pattern:'^(?<action>ALLOW)$'};
    expect(()=>assertBackendProjectSupported(parser,cap)).not.toThrow();
    parser.extraction={format:'regex',pattern:'(?<value>\\d+)'};
    expect(()=>assertBackendProjectSupported(parser,cap)).toThrow(/no Regexp timeout.*quadratically/);
    parser.extraction={format:'syslog_rfc5424',syslogBodyFormat:'regex',
      pattern:'(?<value>\\d+)'};
    expect(()=>assertBackendProjectSupported(parser,cap)).toThrow(/cannot be exported/);
  });
  it('refuses Regex export when an older backend omits target profile',async()=>{
    const old={...regexCapability,
      downloads:Object.fromEntries(Object.entries(regexCapability.downloads)
        .filter(([key])=>key!=='targetRuntimeProfile'))};
    const cap=await supported(old);
    const parser=csvProject();
    parser.extraction={format:'regex',pattern:'^(?<action>ALLOW)$'};
    expect(()=>assertBackendProjectSupported(parser,cap)).toThrow(/Regex samples may be reviewed/);
  });
  it('rejects forged Regex support or target-verification claims',async()=>{
    const forged={
      ...regexCapability,downloads:{
        ...regexCapability.downloads,
        targetRuntimeProfile:{
          ...regexCapability.downloads.targetRuntimeProfile,
          regexExportSupported:false,
        },
      },
    };
    await expect(supported(forged)).rejects.toThrow(/target Regex export capability/);
  });
});
