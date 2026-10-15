import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {preview} from './parser';
import {createDraft} from './model';
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

  it('preserves every Generic Structural source value in final preview across optional fields',()=>{
    const first='<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: failed, AD-Admin=ise.host.local, AD-Domain=host.local, AD-IP-Address=192.0.2.10';
    const second='<182>Mar 3 10:43:05 ise-host APP 0002 1 0 2022-03-03 10:43:05.020 +00:00 0003 INFO Connector: ok, AD-Domain=host.local, AD-Log-Id=1645707128/8';
    const draft=createDraft();
    draft.format='generic_structural';
    draft.mappings=[{id:'mode',source:'generic.mode',target:'custom.mode',type:'string'}];
    if(draft.guided){draft.guided={...draft.guided,groups:{mode:'vendor_fields'},classification:{defaultIndex:'Syslog',rules:[]}};}
    const suite=preview(first+'\n'+second,draft);
    expect(suite.counts.failures).toBe(0);
    expect(suite.counts.normalized).toBe(2);
    expect(suite.events[0]!.normalized).toMatchObject({parserstudio_source:{generic:{kv:{'AD-Admin':'ise.host.local','AD-Domain':'host.local','AD-IP-Address':'192.0.2.10'}}}});
    expect(suite.events[1]!.normalized).toMatchObject({parserstudio_source:{generic:{kv:{'AD-Domain':'host.local','AD-Log-Id':'1645707128/8'}}}});
  });

  it('matches backend ignoreValues behavior for empty optional Generic Structural mappings',()=>{
    const raw='<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: failed, AD-Domain=host.local, AD-Organization-Unit=, AD-IP-Address=192.0.2.10';
    const draft=createDraft();
    draft.format='generic_structural';
    draft.mappings=[
      {id:'domain',source:'generic.kv.AD-Domain',target:'custom.ad_domain',type:'string'},
      {id:'ou',source:'generic.kv.AD-Organization-Unit',target:'custom.ad_ou',type:'string'},
    ];
    if(draft.guided){draft.guided={...draft.guided,groups:{domain:'vendor_fields',ou:'vendor_fields'},classification:{defaultIndex:'Syslog',rules:[]}};}
    const suite=preview(raw,draft);
    expect(suite.counts.failures).toBe(0);
    expect(suite.counts.normalized).toBe(1);
    expect(suite.events[0]!.normalized).toMatchObject({
      parserstudio_source:{generic:{kv:{'AD-Organization-Unit':''}}},
      'custom.ad_domain':'host.local',
    });
    expect(suite.events[0]!.normalized).not.toHaveProperty('custom.ad_ou');
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

  it('extracts bounded Junos RFC5424 structured data without inventing semantics',()=>{
    const raw='<14>1 2019-11-14T09:37:51.184+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@67.43.156.15 source-address="10.0.0.1" source-port="594" application-risk="1"]';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{
        pri:'14',version:'1',timestamp:'2019-11-14T09:37:51.184+01:00',
        hostname:'SRX-GW1',appname:'RT_FLOW',procid:'-',msgid:'RT_FLOW_SESSION_CREATE',
      },
      junos_sd:{source_address:'10.0.0.1',source_port:'594',application_risk:'1'},
    });
    expect((result.fields.syslog as Record<string,unknown>).structured_data_raw)
      .toBe('[junos@67.43.156.15 source-address="10.0.0.1" source-port="594" application-risk="1"]');
    const collision=raw.replace(' application-risk="1"', ' source_address="duplicate"');
    expect(extractGenericStructural(collision).fields).toEqual({});
  });

  it('extracts bounded bracket colon-KV and preserves the unzoned timestamp as source text',()=>{
    const raw='<134>1 2020-03-30T07:20:35 gw CheckPoint 8363 - [action:"Accept"; src:"192.0.2.1"; product:"VPN-1 & FireWall-1"; note:"x;y"]';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'134',version:'1',timestamp:'2020-03-30T07:20:35',hostname:'gw',appname:'CheckPoint',procid:'8363',msgid:'-'},
      body:{action:'Accept',src:'192.0.2.1',product:'VPN-1 & FireWall-1',note:'x;y'},
    });
    expect(extractGenericStructural(raw.replace('2020-03-30T07:20:35','2020-13-30T07:20:35')).fields).toEqual({});
  });

  it('extracts bounded prefix plus space-delimited KV and preserves the exact source',()=>{
    const raw='2023:04:28-00:50:54 sophos-test-vm1 ulogd[12511]: id="2021" severity="info" sys="SecureNet" sub="packetfilter" name="Packet dropped (GEOIP)" action="drop"';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      generic:{
        mode:'space_kv',source_raw:raw,
        prefix_001:'2023:04:28-00:50:54',prefix_002:'sophos-test-vm1',prefix_003:'ulogd[12511]',
        kv:{id:'2021',severity:'info',sys:'SecureNet',sub:'packetfilter',name:'Packet dropped (GEOIP)',action:'drop'},
      },
    });
  });

  it('keeps an unquoted multiword KV value plus its first atom for conservative recovery',()=>{
    const raw='device="SFW" date=2017-01-31 time=14:16:19 timezone="IST" device_name="CR750iNG-XP" device_id=C44313350024- P29PUA log_id=010101600001 status="Allow"';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      generic:{
        mode:'space_kv',source_raw:raw,
        kv:{device:'SFW',date:'2017-01-31',time:'14:16:19',timezone:'IST',device_name:'CR750iNG-XP',
          device_id:'C44313350024- P29PUA',log_id:'010101600001',status:'Allow'},
        atoms:{device_id_001:'C44313350024-'},
      },
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
