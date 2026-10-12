import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {recommendLocalFormat} from './localFormatAdvisor';

const json=[
  '{"action":"allow","src_ip":"198.51.100.10","username":"PRIVATE_USER"}',
  '{"action":"deny","src_ip":"203.0.113.5","username":"SECRET_ACCOUNT"}',
].join('\n');
const kv='action=allow src_ip=198.51.100.10\naction=deny src_ip=203.0.113.5';
function candidate(text:string,format:'auto'|'json'|'kv'|'csv'|'regex'='auto',boundary:'single-line'|'blank-line'='single-line'){
  const draft=createDraft();
  draft.format=format;
  if(draft.guided)draft.guided={...draft.guided,eventBoundary:boundary};
  return recommendLocalFormat(text,preview(text,draft),boundary);
}

describe('offline beginner format recommendation',()=>{
  it('recommends JSON only when every physical event is accounted for and detected',()=>{
    const result=candidate(json);
    expect(result).toMatchObject({status:'RECOMMENDED',format:'json',
      totalEvents:2,reviewedEvents:2,nativeVerified:false});
    expect(result.confidencePercent).toBeGreaterThanOrEqual(90);
    for(const value of ['198.51.100.10','203.0.113.5','PRIVATE_USER','SECRET_ACCOUNT'])
      expect(JSON.stringify(result)).not.toContain(value);
  });
  it('recommends consistent key/value logs using only value-free format metadata',()=>{
    expect(candidate(kv)).toMatchObject({status:'RECOMMENDED',format:'kv',
      totalEvents:2,reviewedEvents:2});
  });
  it('never silently selects one family from mixed JSON/KV or unknown lines',()=>{
    const mixed=candidate(json+'\n'+kv.split('\n')[0]);
    expect(mixed.status).toBe('MIXED_FORMATS');
    expect(mixed.format).toBeNull();
    expect(mixed.families).toEqual([{format:'json',count:2},{format:'kv',count:1}]);
    const unknown=candidate(json+'\nCUSTOMER_SECRET string without recognized format');
    expect(unknown.status).toBe('UNKNOWN_EVENTS');
    expect(unknown.format).toBeNull();
    expect(JSON.stringify(unknown)).not.toContain('CUSTOMER_SECRET');
  });
  it('does not recommend unsupported native shapes or CSV based only on comma count',()=>{
    expect(candidate('value1,value2,value3\nvalue4,value5,value6')).toMatchObject({
      status:'MANUAL_REVIEW',format:null});
    expect(candidate('<34>Oct 12 host syslog message')).toMatchObject({
      status:'MANUAL_REVIEW',format:null});
  });
  it('refuses malformed JSON even if format signature looks recognizable',()=>{
    const invalid=candidate('{"username":"SECRET"');
    expect(invalid.status).toBe('PREVIEW_FAILED');
    expect(invalid.format).toBeNull();
    expect(JSON.stringify(invalid)).not.toContain('SECRET');
  });
  it('refuses blank-line grouped multiline, unreviewed 501 events and oversized input',()=>{
    expect(candidate('{\n "action": "allow"\n}','auto','blank-line').status)
      .toBe('MULTILINE_UNVERIFIED');
    expect(candidate(Array.from({length:501},()=>json.split('\n')[0]).join('\n')).status)
      .toBe('LIMIT_EXCEEDED');
    expect(candidate('x'.repeat(65537)).status).toBe('LIMIT_EXCEEDED');
  });
  it('rejects stale and forged worker source identity, diagnostic fields and native PASS',()=>{
    const draft=createDraft(),suite=preview(json,draft);
    suite.events[0]!.raw='source was replaced';
    expect(recommendLocalFormat(json,suite,'single-line').status).toBe('SOURCE_MISMATCH');
    const clean=preview(json,draft);
    clean.nativeFluentdVerified=true as false;
    expect(recommendLocalFormat(json,clean,'single-line').status).toBe('UNTRUSTED_PREVIEW');
    const extraneous=preview(json,draft);
    extraneous.events[0]!.detected.format='customer-secret' as 'json';
    expect(recommendLocalFormat(json,extraneous,'single-line').status).toBe('UNTRUSTED_PREVIEW');
  });
  it('returns no candidate while worker is pending or a dataset has no events',()=>{
    expect(recommendLocalFormat(json,undefined,'single-line').status).toBe('NO_PREVIEW');
    expect(candidate('   \n  ').status).toBe('NO_SAMPLES');
  });
  it('does not override a manually chosen incompatible format via a false extraction PASS',()=>{
    const selected=candidate(json,'kv');
    expect(selected.status).toBe('PREVIEW_FAILED');
    expect(selected.format).toBeNull();
  });
});
