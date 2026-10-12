import {describe,expect,it} from 'vitest';
import {preview} from '../parser';
import {createDraft} from '../model';
import {traceBrowserMappingRules} from './browserRuleTrace';

const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"username":"PRIVATE_USER"}',
  '{"action":"deny","src_ip":"not-an-ip","dst_port":22,"url":"https://secret.invalid/a"}',
  '{"action":"allow","dst_port":80,"username":"HIDDEN"}',
].join('\n');
const draft=()=>({...createDraft(),format:'json' as const});
describe('per-event, value-free browser rule trace',()=>{
  it('lists every mapping in order for a selected event without raw or normalized values',()=>{
    const current=draft(),suite=preview(sample,current);
    const first=traceBrowserMappingRules(suite,current.mappings,'event-1');
    expect(first).toMatchObject({
      eventId:'event-1',line:1,totalRules:3,nativeVerified:false,
      mappings:[{ruleIndex:1,status:'MAPPED'},{ruleIndex:2,status:'MAPPED'},
        {ruleIndex:3,status:'MAPPED'}],
    });
    const serialized=JSON.stringify(first);
    for(const privateValue of ['198.51.100.10','PRIVATE_USER','CUSTOMER_SECRET','443'])
      expect(serialized).not.toContain(privateValue);
    expect(serialized).not.toContain('custom.source_ip');
  });
  it('distinguishes per-event type errors and absent fields for the same rule',()=>{
    const current=draft(),suite=preview(sample,current);
    const type=traceBrowserMappingRules(suite,current.mappings,'event-2');
    const absent=traceBrowserMappingRules(suite,current.mappings,'event-3');
    expect(type?.mappings[0]).toEqual({ruleIndex:1,status:'TYPE_FAILED'});
    expect(absent?.mappings[0]).toEqual({ruleIndex:1,status:'SOURCE_MISSING'});
    expect(type?.mappings[1].status).toBe('MAPPED');
    expect(type?.mappings[2].status).toBe('MAPPED');
    expect(JSON.stringify(type)).not.toContain('not-an-ip');
    expect(JSON.stringify(type)).not.toContain('https://secret.invalid');
  });
  it('flags duplicate targets without asserting which rule emitted a value',()=>{
    const current=draft();
    current.mappings[2]={...current.mappings[2],target:current.mappings[0].target};
    const suite=preview(sample,current);
    const trace=traceBrowserMappingRules(suite,current.mappings,'event-1');
    expect(trace?.mappings[0].status).toBe('TARGET_AMBIGUOUS');
    expect(trace?.mappings[2].status).toBe('TARGET_AMBIGUOUS');
  });
  it('rejects unsafe paths as rules without echoing names',()=>{
    const current=draft();
    current.mappings[0]={...current.mappings[0],source:'__proto__.password',target:'PRIVATE_SOURCE'};
    const suite=preview(sample,current);
    const trace=traceBrowserMappingRules(suite,current.mappings,'event-1');
    expect(trace?.mappings[0]).toEqual({ruleIndex:1,status:'RULE_INVALID'});
    expect(JSON.stringify(trace)).not.toContain('password');
    expect(JSON.stringify(trace)).not.toContain('PRIVATE_SOURCE');
  });
  it('does not interpret a worker-supplied free-text diagnostic or a forged verification claim',()=>{
    const current=draft(),suite=preview(sample,current);
    suite.events[0]!.diagnostics.push({stage:'normalize',severity:'error',
      code:'PRIVATE_198_51_100_10',message:'CUSTOMER_SECRET',field:'src_ip'});
    const trace=traceBrowserMappingRules(suite,current.mappings,'event-1');
    expect(trace?.mappings[0].status).toBe('MAPPED');
    expect(JSON.stringify(trace)).not.toContain('CUSTOMER_SECRET');
    expect(JSON.stringify(trace)).not.toContain('PRIVATE_');
    expect(trace?.nativeVerified).toBe(false);
    const fake={...suite,nativeFluentdVerified:true};
    expect(traceBrowserMappingRules(fake as typeof suite,current.mappings,'event-1')).toBeNull();
  });
  it('fails closed for stale selections, zero events, malformed event indices and bad mapping bounds',()=>{
    const current=draft(),suite=preview(sample,current);
    expect(traceBrowserMappingRules(suite,current.mappings,'event-99')).toBeNull();
    expect(traceBrowserMappingRules({...suite,events:[]},current.mappings,'event-1')).toBeNull();
    expect(traceBrowserMappingRules({...suite,events:[{...suite.events[0]!,line:-1}]},current.mappings,'event-1')).toBeNull();
    expect(traceBrowserMappingRules(suite,Array.from({length:101},(_,i)=>({...current.mappings[0]!,id:String(i)})),'event-1')).toBeNull();
  });
});
