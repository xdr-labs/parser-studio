import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {suggestEventProfiles,validateEventProfiles} from './multiEventRouting';
import {inspectDeclaredForwarders,validForwarderConfig} from './declaredForwarder';
import {toBackendProject} from './backendAdapter';
import {assertBackendProjectSupported,type BackendCapabilities} from './backendCapabilities';

describe('Reviewed event type mappings in one offline parser',()=>{
  const source=[
    '{"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}',
    '{"event_type":"user","username":"김민수","action":"login"}',
    '{"event_type":"asset","hostname":"fw01","action":"found"}',
  ].join('\n');

  it('keeps event type variant maps in one strict backend project',()=>{
    const base=createDraft();
    const draft={...base,format:'json' as const,
      guided:{...base.guided!,classification:{defaultIndex:'Syslog' as const,rules:[]}},
      mappings:[{id:'common-event',source:'event_type',target:'event_type',
        type:'string' as const}]};
    const suite=preview(source,draft);
    const result=suggestEventProfiles(suite,draft,'event_type');
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.config.variants.map(x=>x.name)).toEqual(['threat','user','asset']);
    expect(result.config.variants.map(x=>x.equals)).toEqual(['threat','user','asset']);
    expect(validateEventProfiles(result.config)).toBe(null);
    const reviewed={...draft,mappings:result.common,eventProfiles:result.config};
    const portable=toBackendProject(reviewed);
    expect(portable.ok,JSON.stringify(portable)).toBe(true);
    if(!portable.ok)return;
    expect(portable.project.normalization.eventProfiles?.variants).toHaveLength(3);
    expect(portable.project.normalization.eventProfiles?.unknown).toBe('reject');
    expect(portable.project.normalization.eventProfiles?.variants[1]?.name).toBe('user');
    const legacy={authoring:{}} as BackendCapabilities;
    expect(()=>assertBackendProjectSupported(portable.project,legacy))
      .toThrow(/Event-family routing requires reviewed backend compiler capability/);
    expect(suite.events.map(x=>x.raw)).toEqual(source.split('\n'));
  });
  it('rejects unsafe/missing/ambiguous event type selectors without fabricating a family',()=>{
    const draft={...createDraft(),format:'json' as const};
    const suite=preview(source,draft);
    expect(suggestEventProfiles(suite,draft,'constructor').ok).toBe(false);
    expect(suggestEventProfiles(suite,draft,'no_such_field').ok).toBe(false);
    const partial=preview('{"event_type":"threat"}\n{"action":"allow"}',draft);
    expect(suggestEventProfiles(partial,draft,'event_type').ok).toBe(false);
  });
  it('extracts only expressly declared relay hosts, retaining received UTF-8 source',()=>{
    const raw='<134>Jan 16 15:19:05 relay01 fw: {"event_type":"user","username":"山田"}';
    const profile={maxHops:1 as const,relayHosts:['relay01']};
    expect(validForwarderConfig(profile)).toBe(true);
    const wrapped=inspectDeclaredForwarders(raw,profile);
    expect(wrapped.status).toBe('UNWRAPPED');
    expect(wrapped.payload).toContain('山田');
    expect(new TextDecoder('utf-8',{fatal:true}).decode(
      new TextEncoder().encode(raw).slice(wrapped.payloadStartByte)))
      .toBe(wrapped.payload);
    expect(inspectDeclaredForwarders(raw,{maxHops:1,relayHosts:['unknown']}).status)
      .toBe('DIRECT');
    expect(inspectDeclaredForwarders(raw,{maxHops:1,relayHosts:['relay01','relay01']}).status)
      .toBe('ABSTAIN_UNSAFE');
  });
});
