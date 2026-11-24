import assert from 'node:assert/strict';
import test from 'node:test';
import {validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import type {ParserProject} from '../src/types.js';

// Final independent re-audit of 62263b3 (2026-11-24), H-1: while fields are kept (Owner decision Q3-1), the
// manufacturer name is the vendor namespace, so a top or ns field may not write into it. The audit saw such projects
// validate and then fail events, or not, depending on whether an event had a field to keep. SYNTHETIC projects.
type FieldMap=ParserProject['normalization']['topFields'];
const field=(normalized_name:string,data_type='string')=>({normalized_name,data_type}) as FieldMap[string];
function kv(preserve:boolean,vendorFields:FieldMap):ParserProject{
  const p=sampleProject();
  p.extraction={format:'kv'};
  p.normalization.topFields={src:field('srcip','ip')};
  p.normalization.nsFields={};
  p.normalization.vendorFields=vendorFields;
  if(preserve)p.normalization.preserveUnmapped=true;else delete p.normalization.preserveUnmapped;
  p.classification.rules=[];
  p.enrichment=[];
  return p;
}
const issues=(p:ParserProject)=>{const r=validateProject(p);return r.ok?[]:r.issues.map(item=>item.code+' '+item.path);};

test('H-1: a top or ns field may not write into the vendor namespace while fields are kept',()=>{
  const cases:Array<[section:'topFields'|'nsFields',source:string,target:string,vendor:FieldMap]>=[
    ['topFields','user','Synthetic.x',{action:field('action')}],
    ['topFields','action','Synthetic.user',{}],
    ['nsFields','action','Synthetic',{}],
    ['topFields','user','Synthetic.parserstudio_unmapped.x',{action:field('action')}],
  ];
  for(const [section,source,target,vendor] of cases){
    const kept=kv(true,vendor);kept.normalization[section]={...kept.normalization[section],[source]:field(target)};
    assert.ok(issues(kept).includes('reserved_field /normalization/'+section+'/'+source),target+' '+JSON.stringify(issues(kept)));
    // Without the decision no field is kept there and the project validates as before.
    const plain=kv(false,{});plain.normalization[section]={...plain.normalization[section],[source]:field(target)};
    assert.deepEqual(issues(plain),[],target);
  }
  const elsewhere=kv(true,{action:field('action')});elsewhere.normalization.topFields.user=field('custom.user');
  assert.deepEqual(issues(elsewhere),[]);
});

test('H-1: the same holds for an event-profile top field',()=>{
  const p=kv(true,{});
  p.normalization.topFields={...p.normalization.topFields,type:field('event_type')};
  p.normalization.eventProfiles={discriminator:'type',unknown:'reject',variants:[
    {name:'a',equals:'a',topFields:{user:field('Synthetic.user')},nsFields:{},vendorFields:{}},
    {name:'b',equals:'b',topFields:{},nsFields:{},vendorFields:{zone:field('zone')}},
  ]};
  assert.ok(issues(p).includes('reserved_field /normalization/eventProfiles/variants/0/topFields/user'),JSON.stringify(issues(p)));
});
