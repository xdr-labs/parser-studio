import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {validateReviewableRecipe} from './guided/parserRecipeV2';

describe('bounded Generic Structural browser compiler twin',()=>{
  it('extracts a Cisco ISE-style comma KV tail without dropping the positional prefix',()=>{
    const raw='<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: failed, AD-Admin=ise.host.local, AD-Domain=host.local, AD-IP-Address=192.0.2.10';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'180'},
      generic:{
        mode:'comma_kv',
        kv:{
          'AD-Admin':'ise.host.local',
          'AD-Domain':'host.local',
          'AD-IP-Address':'192.0.2.10',
        },
      },
    });
    expect((result.fields.generic as Record<string,unknown>).prefix_001).toBe('Mar');
    expect((result.fields.generic as Record<string,unknown>).prefix_014).toBe('Connector');
  });

  it('extracts bounded short RFC5424-style JSON',()=>{
    const raw='<5>1 2021-03-08T18:24:49Z VAULT {"format":"elastic","syslog":{"audit_record":{"Action":"Add File"}}}';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'5',version:'1',timestamp:'2021-03-08T18:24:49Z',hostname:'VAULT'},
      body:{format:'elastic',syslog:{audit_record:{Action:'Add File'}}},
    });
  });

  it('extracts bounded ASA/FTD connection structure',()=>{
    const raw='May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500 (192.0.2.44/53500) to fw111:192.168.2.2/443 (198.51.100.20/443)';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{app_tag:'%FTD-6-302013',hostname:'dev01:'},
      asa:{action:'Built',protocol:'TCP',src_ip:'10.10.10.10',dst_ip:'192.168.2.2',dst_port:'443'},
    });
  });

  it('fails closed on arbitrary prose and accepts the reviewed recipe stage only',()=>{
    expect(extractGenericStructural('free form prose with key=value').fields).toEqual({});
    const recipe={
      contract:'parser-studio.recipe.v0.2',
      schemaRevision:'0.2',
      compilerMode:'REVIEW_ONLY',
      projectId:'draft-demo_firewall',
      sourceFormat:'generic_structural',
      bodyFormat:'generic_structural',
      sample:{sha256:'a'.repeat(64),events:1},
      stages:[
        {op:'split_event',boundary:'single-line'},
        {op:'parse_generic_structural'},
        {op:'map_field',source:'generic.kv.AD-Admin',target:'custom.ad_admin',data_type:'string',group:'vendor_fields'},
        {op:'classify',defaultIndex:'syslog',rules:[]},
        {op:'fallback_unparsed',mode:'retain_unparsed'},
      ],
      nativeVerified:false,
      targetVerified:false,
    };
    expect(validateReviewableRecipe(recipe)).toBe(true);
  });
});
