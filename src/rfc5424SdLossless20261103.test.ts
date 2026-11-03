import {describe,expect,it} from 'vitest';
import {createDraft} from './model';
import {parseRfc5424Subset} from './rfc5424Subset';
import {extractFields,preview} from './parser';
import {listSafeLeafPaths,lookupFieldValue} from './fieldPaths';
import {suggestUnmappedFields} from './guided/fieldMappingSuggestions';

const sample = '<14>1 2019-11-14T11:12:46.573+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_DENY '+
  '[junos@67.43.156.15 source-address="10.0.0.26" source-port="37233" '+
  'destination-address="67.43.156.13" destination-port="161" '+
  'policy-name="MgmtAccess-trust-cleanup" reason="Denied by policy"]';

describe('RFC5424 SD source-field preservation from scanner through Auto Parser',()=>{
  it('exposes structured-data parameters as independent mapping-safe source fields',()=>{
    const result=parseRfc5424Subset(sample);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.fields).toMatchObject({
      syslog_structured_data:expect.stringContaining('source-address="10.0.0.26"'),
      syslog_sd:{
        element_1:{
          sd_id:'junos@67.43.156.15',
          params:{
            'source-address':'10.0.0.26',
            'source-port':'37233',
            'destination-address':'67.43.156.13',
            'destination-port':'161',
            'policy-name':'MgmtAccess-trust-cleanup',
            reason:'Denied by policy',
          },
        },
      },
    });
    const draft=createDraft();
    draft.format='syslog_rfc5424';
    draft.syslogBodyFormat='raw';
    const extracted=extractFields(sample,'syslog_rfc5424',draft);
    expect(extracted.errors).toEqual([]);
    const key='syslog_sd.element_1.params.source-address';
    expect(listSafeLeafPaths(extracted.fields)).toContain(key);
    expect(lookupFieldValue(extracted.fields,key)).toEqual({found:true,value:'10.0.0.26'});
    expect(suggestUnmappedFields([extracted.fields],{...draft,mappings:[]}).map(x=>x.source))
      .toContain(key);
  });

  it('retains separate element identities and escaped values without inventing MSG fields',()=>{
    const raw='<165>1 2026-11-03T10:12:46Z edge app - ID '+
      '[a@32473 code="one" note="a\\]b"][b@32473 code="two"]';
    const parsed=parseRfc5424Subset(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.message).toBeNull();
    expect(parsed.fields.syslog_sd).toEqual({
      element_1:{sd_id:'a@32473',params:{code:'one',note:'a]b'}},
      element_2:{sd_id:'b@32473',params:{code:'two'}},
    });
  });

  it('keeps the original RFC5424 NILVALUE and no fabricated SD parameters',()=>{
    const raw='<165>1 2026-11-03T10:12:46Z edge app - ID - message';
    const parsed=parseRfc5424Subset(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.fields.syslog_structured_data).toBe('-');
    expect(parsed.fields.syslog_sd).toBeUndefined();
    expect(parsed.message).toBe('message');
  });
});


describe('RFC5424 browser normalization to the supported backend path grammar',()=>{
  it('maps hyphenated SD parameter values without a false preview normalization failure',()=>{
    const draft=createDraft();
    draft.format='syslog_rfc5424';
    draft.syslogBodyFormat='raw';
    draft.mappings=[{
      id:'junos-ip',source:'syslog_sd.element_1.params.source-address',
      target:'junos_source-address',type:'ip',
    }];
    draft.guided={...draft.guided!,groups:{'junos-ip':'vendor_fields'},
      classification:{defaultIndex:'Syslog',rules:[]}};
    const suite=preview(sample,draft);
    expect(suite.counts).toMatchObject({total:1,matched:1,extracted:1,normalized:1,failures:0});
    expect(JSON.stringify(suite.events[0]?.normalized)).toContain('10.0.0.26');
  });
});
