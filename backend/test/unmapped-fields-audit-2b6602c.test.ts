import assert from 'node:assert/strict';
import test from 'node:test';
import {validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import type {ParserProject} from '../src/types.js';

// Repro tests of the independent audit of 2b6602c (2026-11-24, G-1..G-4): a name Owner decision Q3-1 reserves for
// the fields it keeps must be refused wherever a project could write it, before any Ruby is generated (the audit saw
// Ruby 3.2 and 2.4.9 accept these projects and write or lose fields silently). SYNTHETIC projects.
type FieldMap=ParserProject['normalization']['topFields'];
const field=(normalized_name:string,data_type='string')=>({normalized_name,data_type}) as FieldMap[string];
function plain(preserve:boolean,vendorFields=true):ParserProject{
  const p=sampleProject();
  p.extraction={format:'json'};
  p.normalization.topFields={srcip:field('srcip','ip'),dstip:field('dstip','ip')};
  p.normalization.nsFields={};
  p.normalization.vendorFields=vendorFields?{action:field('action')}:{};
  if(preserve)p.normalization.preserveUnmapped=true;else delete p.normalization.preserveUnmapped;
  p.classification.rules=[];
  p.enrichment=[];
  return p;
}
function profiled(zoneTarget:string,preserve:boolean):ParserProject{
  const p=plain(preserve);
  p.normalization.topFields={...p.normalization.topFields,type:field('event_type')};
  p.normalization.eventProfiles={discriminator:'type',unknown:'reject',variants:[
    {name:'a',equals:'a',topFields:{},nsFields:{},vendorFields:{user:field('user')}},
    {name:'b',equals:'b',topFields:{},nsFields:{},vendorFields:{zone:field(zoneTarget)}},
  ]};
  return p;
}
function issues(p:ParserProject):string[]{
  const result=validateProject(p);
  return result.ok?[]:result.issues.map(item=>item.code+' '+item.path);
}

test('G-1: an event-profile vendor field may not write parserstudio_unmapped',()=>{
  for(const target of ['parserstudio_unmapped.zone','parserstudio_unmapped'])for(const preserve of [true,false])
    assert.ok(issues(profiled(target,preserve)).includes('reserved_field /normalization/eventProfiles/variants/1/vendorFields/zone'),
      target+' preserve='+preserve+' '+JSON.stringify(issues(profiled(target,preserve))));
  assert.deepEqual(issues(profiled('zone',true)),[]);
});

test('G-2: an enrichment may not write into <vendor>.parserstudio_unmapped',()=>{
  const rules:NonNullable<ParserProject['enrichment']>=[
    {operator:'set_const',target:'Synthetic.parserstudio_unmapped.foo',value:'fabricated'},
    {operator:'copy',source:'srcip',target:'Synthetic.parserstudio_unmapped.srcip'},
    {operator:'set_const',target:'Synthetic.parserstudio_unmapped',value:'k'},
  ];
  for(const rule of rules)for(const preserve of [true,false]){
    const p=plain(preserve);p.enrichment=[rule];
    assert.ok(issues(p).includes('reserved_field /enrichment/0'),JSON.stringify(rule)+' '+JSON.stringify(issues(p)));
  }
  const p=plain(true);p.enrichment=[{operator:'set_const',target:'Synthetic.site',value:'kr'}];
  assert.deepEqual(issues(p),[]);
});

test('G-3: with fields kept, the manufacturer may not name a system-owned root, also without vendor fields',()=>{
  for(const vendor of ['msg_origin','stellar_log_index','parserstudio_transport','parserstudio_event_family']){
    const kept=plain(true,false);kept.vendor=vendor;
    assert.ok(issues(kept).includes('reserved_vendor_namespace /vendor'),vendor+' '+JSON.stringify(issues(kept)));
    // Without the decision no vendor namespace is written, so the project stays valid as before.
    const unchanged=plain(false,false);unchanged.vendor=vendor;
    assert.deepEqual(issues(unchanged),[],vendor);
  }
});

test('G-4: with fields kept, an enrichment may not write the bare manufacturer name',()=>{
  const kept=plain(true,false);kept.enrichment=[{operator:'set_const',target:'Synthetic',value:'x'}];
  assert.ok(issues(kept).includes('reserved_field /enrichment/0'),JSON.stringify(issues(kept)));
  const unchanged=plain(false,false);unchanged.enrichment=[{operator:'set_const',target:'Synthetic',value:'x'}];
  assert.deepEqual(issues(unchanged),[]);
});
