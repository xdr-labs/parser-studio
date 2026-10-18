import { describe, expect, it, vi } from 'vitest';
import { createDraft } from '../model';
import { toBackendProject } from './backendAdapter';
import { fetchBackendCapabilities, assertBackendProjectSupported } from './backendCapabilities';

const old = {
  contract: 'host-customized-pair.v0.1', projectSchemaRevision: '0.1',
  authoring: { receiverProtocols: ['udp','tcp'], extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    httpReceiver:false, multipleDistinctReceiverPorts:false, formatCoverage:'reviewed-bounded-subset', multiline:false, arbitraryRuby:false },
  import: {exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification: {engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const updated = { ...old, authoring:{...old.authoring,
  rfc5424AdjacentStructuredDataSubset:true,rfc5424StructuredDataMaxBytes:1024,
  rfc5424BodyFormats:['raw','json','kv','cef','leef'],leefHexSeparatorSubset:true,
} };
const fake = (body: unknown) => vi.fn(async () => ({status:200,json:async()=>body})) as unknown as typeof fetch;
function nested(mode:'cef'|'leef') {
  const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat=mode;
  const converted=toBackendProject(draft);
  if (!converted.ok) throw Error(JSON.stringify(converted.issues));
  return converted.project;
}

describe('capability reconciliation with optional reviewed RFC5424 parser subsets', () => {
  it('accepts newest backend RFC5424 envelope modes and no target compatibility claims', async () => {
    const cap=await fetchBackendCapabilities(fake(updated));
    expect(cap.authoring.rfc5424BodyFormats).toContain('cef');
    expect(() => assertBackendProjectSupported(nested('cef'),cap)).not.toThrow();
    expect(() => assertBackendProjectSupported(nested('leef'),cap)).not.toThrow();
  });
  it('fails closed if an older server does not explicitly advertise nested mode', async () => {
    const cap=await fetchBackendCapabilities(fake(old));
    expect(() => assertBackendProjectSupported(nested('cef'),cap)).toThrow(/CEF|cef/i);
    expect(() => assertBackendProjectSupported(nested('leef'),cap)).toThrow(/LEEF|leef/i);
  });
  it('fails closed if the newer server lists only a subset of body modes', async () => {
    const cap=await fetchBackendCapabilities(fake({...updated, authoring:{
      ...updated.authoring,rfc5424BodyFormats:['raw','json','kv'],
    }}));
    expect(() => assertBackendProjectSupported(nested('cef'),cap)).toThrow();
  });
  it.each([
    { ...updated, authoring:{...updated.authoring,rfc5424BodyFormats:['raw','json','kv','eval']} },
    { ...updated, authoring:{...updated.authoring,rfc5424StructuredDataMaxBytes:10240000} },
    { ...updated, authoring:{...updated.authoring,rfc5424AdjacentStructuredDataSubset:true,rfc5424StructuredDataMaxBytes:0} },
    { ...updated, authoring:{...updated.authoring,rfc5424AdjacentStructuredDataSubset:false} },
    { ...updated, authoring:{...updated.authoring,leefHexSeparatorSubset:'true'} },
  ])('rejects unsupported or contradictory advertised authoring limits',async invalid=>{
    await expect(fetchBackendCapabilities(fake(invalid))).rejects.toThrow();
  });
  it.each(['cef','leef'] as const)('projects declare the exact nested %s schema mode and nothing executable', mode=>{
    expect(nested(mode).extraction).toEqual({format:'syslog_rfc5424',syslogBodyFormat:mode});
  });
});
