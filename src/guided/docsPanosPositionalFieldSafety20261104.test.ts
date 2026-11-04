import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {createDraft} from '../model';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';

const raw=readFileSync(resolve('tests/fixtures/docs-practice-20261104/06-panos-traffic-issue.log'),'utf8').trimEnd();
describe('published PAN-OS positional traffic source: semantic dictionary safety',()=>{
  it('does not confuse PRI severity and PAN-OS traffic category with unrelated Stellar metadata',()=>{
    const result=buildAutomaticGenericStructuralDraft(raw,createDraft());
    expect(result).not.toBeNull();
    const draft=result!.draft;
    expect(draft.mappings).toHaveLength(97);
    const mapping=(source:string)=>draft.mappings.find(x=>x.source===source);
    expect(mapping('syslog.severity')).toBeDefined();
    expect(draft.guided?.groups[mapping('syslog.severity')!.id]).toBe('vendor_fields');
    expect(mapping('generic.fields.type')).toBeDefined();
    expect(draft.guided?.groups[mapping('generic.fields.type')!.id]).toBe('vendor_fields');
    for(const [source,target] of [
      ['generic.fields.src','srcip'],['generic.fields.dst','dstip'],
      ['generic.fields.sport','srcport'],['generic.fields.dport','dstport'],
      ['generic.fields.protocol','proto_name'],['generic.fields.action','action'],
    ]){
      expect(mapping(source)).toMatchObject({target});
      expect(draft.guided?.groups[mapping(source)!.id]).toBe('top_fields');
    }
  });
});