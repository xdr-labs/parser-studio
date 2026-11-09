import {describe,expect,it} from 'vitest';
import {vendorFieldNames,compactLegacyAutoVendorMappings} from './vendorFieldNames';
import type {MappingRule} from '../model';

const source='syslog_sd.element_1.params.source-port';

describe('vendor-local field names preserve original source semantics',()=>{
  it('keeps only the JSON path leaf for unambiguous Juniper SD fields',()=>{
    const names=vendorFieldNames([source,
      'syslog_sd.element_1.params.destination-port',
      'syslog_sd.element_1.params.service-name',
      'syslog_sd.element_1.params.connection-tag',
    ]);
    expect(names.get(source)).toBe('source-port');
    expect(names.get('syslog_sd.element_1.params.destination-port')).toBe('destination-port');
    expect(names.get('syslog_sd.element_1.params.service-name')).toBe('service-name');
    expect(names.get('syslog_sd.element_1.params.connection-tag')).toBe('connection-tag');
    expect([...names.values()].every(name=>!name.startsWith('Juniper.')&&
      !name.includes('syslog_sd_element_1_params'))).toBe(true);
  });

  it('uses the exact original dotted path on duplicate leaf names, independent of event order',()=>{
    const sources=[source,'syslog_sd.element_2.params.source-port'];
    for(const ordered of [sources,[...sources].reverse()]){
      const names=vendorFieldNames(ordered);
      expect(names.get(source)).toBe(source);
      expect(names.get(sources[1]!)).toBe(sources[1]);
    }
  });

  it('falls back to the unchanged source path if a different mapping owns the leaf',()=>{
    const names=vendorFieldNames([source],['source-port','Juniper.unknown']);
    expect(names.get(source)).toBe(source);
    expect(vendorFieldNames([source],['syslog_sd.element_1.params'])
      .get(source)).toBe('source-port');
  });

  it('rejects dangerous names and does not produce colliding output paths',()=>{
    const names=vendorFieldNames([
      '__proto__.foo','constructor.name','syslog_sd.element_1.params.source-port',
      'syslog_sd.element_1.params.source-port.extra',
    ]);
    expect(names.has('__proto__.foo')).toBe(false);
    expect(names.has('constructor.name')).toBe(false);
    expect(new Set(names.values()).size).toBe(names.size);
  });

  it('solves cross-source leaf/fallback conflicts without silently losing any input',()=>{
    const paths=['src.ip','dst.ip','meta.src'];
    for(const input of [paths,[...paths].reverse()]){
      const names=vendorFieldNames(input);
      expect(Object.fromEntries(names)).toEqual({'dst.ip':'dst.ip','meta.src':'meta.src','src.ip':'src.ip'});
      expect(names.size).toBe(paths.length);
    }
  });

  it('never rewrites unmarked legacy mappings or explicit user edits',()=>{
    const legacy:MappingRule={id:'auto-1',source:'http.status',target:'http.status',type:'string'};
    expect(compactLegacyAutoVendorMappings([legacy],{'auto-1':'vendor_fields'}))
      .toEqual([legacy]);
    const edited:MappingRule={...legacy,authoring:{version:1,origin:'USER_EDITED'}};
    expect(compactLegacyAutoVendorMappings([edited],{'auto-1':'vendor_fields'}))
      .toEqual([edited]);
  });

  it('only rewrites untouched generated vendor mappings, preserving manual and official targets',()=>{
    const maps:MappingRule[]=[
      {id:'auto-1',source,target:'syslog_sd_element_1_params_source-port',type:'string',
        authoring:{version:1,origin:'AUTO'}},
      {id:'auto-2',source:'syslog_sd.element_1.params.destination-port',
        target:'syslog_sd_element_1_params_destination-port',type:'string',
        authoring:{version:1,origin:'AUTO'}},
      {id:'manual',source:'manual.field',target:'custom.destination',type:'string'},
      {id:'auto-3',source:'syslog_sd.element_1.params.source-address',target:'srcip',type:'ip'},
    ];
    const groups={'auto-1':'vendor_fields','auto-2':'vendor_fields',
      manual:'vendor_fields','auto-3':'top_fields'} as const;
    const next=compactLegacyAutoVendorMappings(maps,groups);
    expect(next.map(x=>x.target)).toEqual([
      'source-port','destination-port','custom.destination','srcip',
    ]);
    expect(compactLegacyAutoVendorMappings(next,groups)).toBe(next);
  });
});
