import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {compareLocalVersions,sameLocalWorking,validLocalDraft} from './localWorkspaceHistory';

describe('browser-only parser experiment version contract',()=>{
  it('distinguishes source, parser grammar and field-mapping experiments without changing source objects',()=>{
    const base=createDraft();
    const changed=structuredClone(base);
    changed.format='kv';
    changed.csvColumns='action,source,destination';
    changed.mappings[0]={...changed.mappings[0],target:'srcip'};
    changed.mappings.push({id:'hostname',source:'syslog.hostname',target:'hostname',type:'string'});
    const left={source:'action=allow src=192.0.2.10',datasetName:'Draft one',draft:base};
    const right={source:'action=deny src=192.0.2.11',datasetName:'Draft two',draft:changed};
    const result=compareLocalVersions(left,right);
    expect(result).toMatchObject({
      sourceChanged:true,changedLines:1,draftChanged:true,
      addedMappings:['hostname'],removedMappings:[],editedMappings:['source-ip'],
    });
    expect(result.changes).toEqual(expect.arrayContaining([
      'Dataset name','Parser format','CSV schema / delimiter','Field mappings',
    ]));
    expect(sameLocalWorking(left,right)).toBe(false);
    expect(base.format).toBe('auto');
    expect(base.mappings).toHaveLength(3);
  });

  it('preserves exact event source, mapping order and JSON-safe draft settings',()=>{
    const draft=createDraft();
    const a={source:'allowed 😀,allow,\n"quoted,cell"',datasetName:'UTF-8 source',draft};
    const copied=structuredClone(a);
    expect(validLocalDraft(copied.draft)).toBe(true);
    expect(sameLocalWorking(a,copied)).toBe(true);
    expect(compareLocalVersions(a,copied)).toMatchObject({
      sourceChanged:false,changedLines:0,draftChanged:false,
      addedMappings:[],removedMappings:[],editedMappings:[],changes:[],
    });
  });

  it('compares declared relays and reviewed multi-event mappings without exposing or altering raw values',()=>{
    const draft=createDraft();
    const original={
      source:'{"event_type":"threat","username":"김민수"}',
      datasetName:'UTF-8 event review',draft,
    };
    const staged=structuredClone(draft);
    staged.forwarder={maxHops:1,relayHosts:['relay01']};
    staged.eventProfiles={
      discriminator:'event_type',unknown:'reject',variants:[
        {name:'threat',equals:'threat',mappings:[{
          id:'event-threat',source:'username',target:'custom.user_name',type:'string',
        }]},
        {name:'user',equals:'user',mappings:[{
          id:'event-user',source:'username',target:'custom.user_name',type:'string',
        }]},
      ],
    };
    const selected={...original,draft:staged};
    expect(validLocalDraft(staged)).toBe(true);
    expect(compareLocalVersions(original,selected)).toMatchObject({
      sourceChanged:false,draftChanged:true,
      addedMappings:[],removedMappings:[],editedMappings:[],
    });
    expect(compareLocalVersions(original,selected).changes).toEqual([
      'Declared relay profile','Event-type routing / conditional mappings',
    ]);
    const changed=structuredClone(staged);
    changed.eventProfiles!.variants[0]!.mappings[0]!.target='custom.actor';
    const compared=compareLocalVersions(selected,{...original,draft:changed});
    expect(compared.changes).toContain('Event-type routing / conditional mappings');
    expect(compared.changes).not.toContain('Field mappings');
    expect(draft.forwarder).toBeUndefined();
    expect(draft.eventProfiles).toBeUndefined();
    expect(original.source).toContain('김민수');
  });

  it('fails closed on malformed saved multi-event rules and relay settings before restore',()=>{
    const draft=createDraft();
    const valid=structuredClone(draft);
    valid.eventProfiles={
      discriminator:'event_type',unknown:'reject',variants:[
        {name:'threat',equals:'threat',mappings:[{
          id:'threat-user',source:'username',target:'custom.user_name',type:'string',
        }]},
        {name:'user',equals:'user',mappings:[{
          id:'user-name',source:'username',target:'custom.user_name',type:'string',
        }]},
      ],
    };
    valid.forwarder={maxHops:1,relayHosts:['relay01']};
    expect(validLocalDraft(valid)).toBe(true);
    expect(validLocalDraft({...valid,eventProfiles:{unknown:'reject'}})).toBe(false);
    expect(validLocalDraft({...valid,eventProfiles:{...valid.eventProfiles,variants:[]}}))
      .toBe(false);
    expect(validLocalDraft({...valid,eventProfiles:{...valid.eventProfiles,unknown:'fallback'}}))
      .toBe(false);
    expect(validLocalDraft({...valid,eventProfiles:{...valid.eventProfiles,
      variants:[{...valid.eventProfiles.variants[0]!,mappings:[
        {id:'foo',source:'name',target:'target',type:'run_code'},
      ]},valid.eventProfiles.variants[1]]}})).toBe(false);
    expect(validLocalDraft({...valid,eventProfiles:{...valid.eventProfiles,
      variants:[{...valid.eventProfiles.variants[0]!,mappings:[
        valid.eventProfiles.variants[0]!.mappings[0],
        valid.eventProfiles.variants[0]!.mappings[0],
      ]},valid.eventProfiles.variants[1]]}})).toBe(false);
    for(const forwarder of [
      null,{}, {maxHops:4,relayHosts:['relay01']},
      {maxHops:1,relayHosts:'relay01'},
      {maxHops:1,relayHosts:['relay01','relay01']},
      {maxHops:1,relayHosts:['bad hostname']}
    ])expect(validLocalDraft({...valid,forwarder})).toBe(false);
    expect(valid.eventProfiles.variants[0]!.mappings[0]!.target).toBe('custom.user_name');
    expect(valid.forwarder.relayHosts).toEqual(['relay01']);
  });

  it('rejects duplicate, malformed and unsafe persisted parser settings',()=>{
    const draft=createDraft();
    const conditional={...draft,mappings:[{...draft.mappings[0]!,
      when:{sourcePath:'protocol-id',operator:'in' as const,values:['6','17']}}]};
    expect(validLocalDraft(conditional)).toBe(true);
    expect(validLocalDraft({...conditional,mappings:[{...conditional.mappings[0]!,
      when:{sourcePath:'__proto__.x',operator:'in',values:['6']}}]})).toBe(false);
    expect(validLocalDraft({...conditional,mappings:[{...conditional.mappings[0]!,
      when:{sourcePath:'proto',operator:'execute',values:['6']}}]})).toBe(false);
    expect(validLocalDraft({...draft,format:'forged'})).toBe(false);
    expect(validLocalDraft({...draft,mappings:[...draft.mappings,draft.mappings[0]]})).toBe(false);
    expect(validLocalDraft({...draft,mappings:[{id:'a',source:'src',target:'dst',type:'run_code'}]})).toBe(false);
    expect(validLocalDraft({...draft,guided:JSON.parse('{"__proto__":{"isAdmin":true}}')})).toBe(false);
    expect(validLocalDraft({...draft,mappings:Array.from({length:101},(_,i)=>({
      id:String(i),source:'src',target:'custom.foo',type:'string'}))})).toBe(false);
  });
});
