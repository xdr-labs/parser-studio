import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {defaultGuidedOptions} from './contract';
import {suggestClassification} from './classify';
import {toBackendProject} from './backendAdapter';

describe('classification type semantics match the native contract',()=>{
  it('refuses numeric equals instead of promising a Threat classification',()=>{
    const d=createDraft();d.format='json';
    d.mappings=[{id:'proto',source:'proto',target:'proto',type:'integer'}];
    const opts=defaultGuidedOptions();
    opts.groups={proto:'top_fields'};
    opts.classification={defaultIndex:'Syslog',rules:[{id:'r',sourceField:'proto',equals:'6',index:'Threat'}]};
    d.guided=opts;
    for(const raw of ['{"proto":6}','{"proto":"6"}']){
      const event=preview(raw,d).events[0]!;
      expect(event.normalized.proto).toBe(6);
      expect(suggestClassification(event,opts,d)).toMatchObject({index:'Syslog',status:'fallback'});
    }
    const verdict=toBackendProject(d);
    expect(verdict.ok).toBe(false);
    if(!verdict.ok)expect(verdict.issues.map(x=>x.code)).toContain('CLASSIFICATION_NONSTRING_FIELD');
  });
  it('compares the normalized string value rather than raw source type',()=>{
    const d=createDraft();d.format='json';
    d.mappings=[{id:'reason',source:'reason',target:'custom.reason',type:'string'}];
    const opts=defaultGuidedOptions();opts.groups={reason:'top_fields'};
    opts.classification={defaultIndex:'Syslog',rules:[{id:'r',sourceField:'reason',equals:'6',index:'Threat'}]};
    d.guided=opts;
    const event=preview('{"reason":6}',d).events[0]!;
    expect(event.normalized.custom).toEqual({reason:'6'});
    expect(suggestClassification(event,opts,d)).toMatchObject({index:'Threat',status:'matched'});
    expect(toBackendProject(d).ok).toBe(true);
  });
});
