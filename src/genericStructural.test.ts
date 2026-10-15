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

  it('parses bounded short RFC5424-style CEF without vendor-specific semantics',()=>{
    const raw='<5>1 2023-07-28T05:01:01Z vault-host CEF:0|Example|Vault|12.2|59|Clear Safe History|5|act=Clear suser=exampleuser cs2Label=Safe Name cs2=TempSafe';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'5',version:'1',timestamp:'2023-07-28T05:01:01Z',hostname:'vault-host'},
      body:{cef_version:'0',cef_device_vendor:'Example',cef_device_product:'Vault',
        cef_signature_id:'59',act:'Clear',suser:'exampleuser',cs2:'TempSafe'},
    });
  });

  it('extracts bounded vendor-prefixed JSON without merging it with plain JSON',()=>{
    const raw='darktrace {"model":{"name":"Test Model"},"device":{"ip":"192.0.2.10"}}';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      generic:{mode:'prefixed_json',prefix:'darktrace',source_raw:raw},
      body:{model:{name:'Test Model'},device:{ip:'192.0.2.10'}},
    });
    expect(extractGenericStructural('darktrace {"model":').fields).toEqual({});
    expect(extractGenericStructural('darktrace [1,2,3]').fields).toEqual({});
    expect(extractGenericStructural('dark trace {"model":{}}').fields).toEqual({});
  });

  it('preserves repeated comma-KV source keys as ordered value occurrences',()=>{
    const raw='<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: ok, AD-Domain=host.local, AD-Srv-Record=one, AD-Srv-Record=two';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect((result.fields.generic as {kv:Record<string,unknown>}).kv['AD-Srv-Record']).toEqual(['one','two']);
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
    const raw='<134>1 2020-03-30T07:20:35 gw CheckPoint 8363 - [action:"Accept"; src:"192.0.2.1"; product:"VPN-1 & FireWall-1"; group:"ops"; group:"admins"; sys_message::"risk"; note:"x;y"]';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'134',version:'1',timestamp:'2020-03-30T07:20:35',hostname:'gw',appname:'CheckPoint',procid:'8363',msgid:'-'},
      body:{action:'Accept',src:'192.0.2.1',product:'VPN-1 & FireWall-1',group:['ops','admins'],'sys_message:':'risk',note:'x;y'},
    });
    const zoned=extractGenericStructural(raw.replace('2020-03-30T07:20:35','2020-03-30T07:20:35Z'));
    expect(zoned.errors).toEqual([]);
    expect((zoned.fields.syslog as Record<string,unknown>).timestamp).toBe('2020-03-30T07:20:35Z');
    const trailing=extractGenericStructural(raw+'  ');
    expect(trailing.errors).toEqual([]);
    expect((trailing.fields.body as Record<string,unknown>).action).toBe('Accept');
    expect(extractGenericStructural(raw+' unexpected')).toMatchObject({fields:{}});
    expect(extractGenericStructural(raw.replace('2020-03-30T07:20:35','2020-13-30T07:20:35')).fields).toEqual({});
  });

  it('extracts bounded PRI-prefixed space-delimited KV without inventing Syslog body semantics',()=>{
    const raw='<134>date=2023-02-23 time=22:49:29 tz="+0500" devname=FMG-VM device_id=FMG001 log_id=0001010018 type=event subtype=system pri=information desc="User login successful" msg="inner status=embedded value" status=success';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'134'},
      generic:{
        mode:'space_kv',source_raw:raw,
        kv:{date:'2023-02-23',time:'22:49:29',tz:'+0500',devname:'FMG-VM',
          device_id:'FMG001',log_id:'0001010018',type:'event',subtype:'system',
          pri:'information',desc:'User login successful',msg:'inner status=embedded value',status:'success'},
      },
    });
    expect(extractGenericStructural(raw.replace('<134>','<192>')).fields).toEqual({});
    expect(extractGenericStructural('<134>date=2023-02-23 time=22:49:29 type=event subtype=system').fields).toEqual({});
    expect(extractGenericStructural(raw.replace('desc="User login successful"','desc="User login successful')).fields).toEqual({});
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

  it('keeps every bounded atom from an unquoted multiword KV value for source-preserving recovery',()=>{
    const raw='device="SFW" date=2017-01-31 time=14:16:19 timezone="IST" device_name="CR750iNG-XP" device_id=C44313350024- P29PUA log_id=010101600001 status="Allow"';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      generic:{
        mode:'space_kv',source_raw:raw,
        kv:{device:'SFW',date:'2017-01-31',time:'14:16:19',timezone:'IST',device_name:'CR750iNG-XP',
          device_id:'C44313350024- P29PUA',log_id:'010101600001',status:'Allow'},
        atoms:{device_id_001:'C44313350024-',device_id_002:'P29PUA'},
      },
    });
  });

  it('extracts bounded ISO PRI mixed positional logs only with strong network evidence',()=>{
    const raw='<129>2026-10-15 14:54:44.502 +0100 edge WAF ALERT CODE 192.0.2.1 61507 198.51.100.2 443 app policy LOG NONE token1 token2 token3 token4 "-" "multi word positional value" token7 token8';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'129',date:'2026-10-15',time:'14:54:44.502',timezone:'+0100'},
    });
    expect((result.fields.generic as {tokens:string[]}).tokens.slice(0,8))
      .toEqual(['edge','WAF','ALERT','CODE','192.0.2.1','61507','198.51.100.2','443']);
    expect((result.fields.generic as {tokens:string[]}).tokens).toContain('-');
    expect((result.fields.generic as {tokens:string[]}).tokens).toContain('multi word positional value');
    const draft=createDraft();
    draft.format='generic_structural';
    draft.mappings=[{id:'pri',source:'syslog.pri',target:'custom.source_pri',type:'string'}];
    if(draft.guided){draft.guided={...draft.guided,groups:{pri:'vendor_fields'},classification:{defaultIndex:'Syslog',rules:[]}};}
    const suite=preview(raw,draft);
    expect(suite.counts.failures).toBe(0);
    expect(suite.events[0]!.normalized).toMatchObject({'custom.source_pri':'129'});
    const sourceProjection=suite.events[0]!.normalized.parserstudio_source as
      {generic:{tokens:string[]}};
    expect(sourceProjection.generic.tokens.slice(0,8))
      .toEqual(['edge','WAF','ALERT','CODE','192.0.2.1','61507','198.51.100.2','443']);
    expect(extractGenericStructural(raw.replace('<129>','<192>')).fields).toEqual({});
    expect(extractGenericStructural(raw.replace('+0100','+2500')).fields).toEqual({});
    expect(extractGenericStructural(raw.replace('2026-10-15','2026-02-30')).fields).toEqual({});
    expect(extractGenericStructural('<129>2026-10-15 14:54:44.502 +0100 edge short 192.0.2.1 198.51.100.2').fields).toEqual({});
    expect(extractGenericStructural(raw.replace('198.51.100.2','not-an-ip')).fields).toEqual({});
  });

  it('extracts the bounded WatchGuard Firebox traffic profile without semantic guessing',()=>{
    const raw='<139>Jan 16 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 (2024-01-19T08:48:15) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.1.2 175.16.199.1 39398 25 msg="SMTP request" proxy_act="SMTP-Outgoing.1" rcvd_bytes="272" sent_bytes="282" sender="tester@testnet.com" recipients="wg@localhost" (SMTP-proxy-00)';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      watchguard_header:{pri:'139',month:'Jan',day:'16',time:'15:19:05',hostname:'WatchGuard-Firebox',
        serial:'FVE6035FD3AE3',device_time:'2024-01-19T08:48:15',app_tag:'firewall'},
      watchguard:{tokens:['Allow','1-Trusted','0-External','tcp','10.0.1.2','175.16.199.1','39398','25'],
        kv:{msg_id:'1BFF-000F',msg:'SMTP request',proxy_act:'SMTP-Outgoing.1'},groups:['SMTP-proxy-00']},
    });
  });

  it('extracts the bounded Juniper legacy RT_FLOW profile as source tokens',()=>{
    const raw='Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.83.99/40275->192.168.32.1/161 None 192.168.83.99/40275->192.168.32.1/161 None None 17 allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{month:'Apr',day:'29',time:'01:14:45',hostname:'10.9.9.1',app_tag:'RT_FLOW'},
      juniper:{event:'RT_FLOW_SESSION_CREATE'},
    });
    const tokens=(result.fields.juniper as {tokens:string[]}).tokens;
    expect(tokens.slice(0,3)).toEqual(['session','created','192.168.83.99/40275->192.168.32.1/161']);
    expect(tokens).toHaveLength(14);
  });

  it('extracts bounded sentence-prefixed comma-delimited KV for secure-email events',()=>{
    const raw="Info: Response received for file reputation query from Cloud. FileName = 'mod-6.exe', MID = 5, Disposition = MALICIOUS, Malware = W32.TEST, Reputation Score = 73, sha256 = "+'a'.repeat(64)+", upload_action = 2";
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      generic:{mode:'delimited_kv',delimiter:',',
        fields:{FileName:'mod-6.exe',MID:'5',Disposition:'MALICIOUS',Malware:'W32.TEST','Reputation Score':'73',upload_action:'2'}},
    });
    expect((result.fields.generic as {prefix_tokens:string[]}).prefix_tokens.slice(0,2)).toEqual(['Info','Response']);
  });

  it('preserves RFC3164 envelope source fields around bounded secure-email comma-KV',()=>{
    const raw="<166>Mar 17 18:24:37 amp: Info: File reputation query initiating. File Name = 'mod-6.exe', MID = 5, File Size = 1673216 bytes, File Type = application/x-dosexec";
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{pri:'166',month:'Mar',day:'17',time:'18:24:37',host:'amp:',tag:'Info'},
      generic:{mode:'delimited_kv',delimiter:',',prefix_tokens:['File','reputation','query','initiating.'],
        fields:{'File Name':'mod-6.exe',MID:'5','File Size':'1673216 bytes','File Type':'application/x-dosexec'}},
    });
  });

  it('rejects prototype-bearing source keys across Generic Structural KV grammars',()=>{
    const comma='<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: ok, AD-Domain=host.local, constructor=bad';
    expect(extractGenericStructural(comma).fields).toEqual({});
    const spaced='device="SFW" date=2017-01-31 time=14:16:19 timezone="IST" constructor=bad status="Allow"';
    expect(extractGenericStructural(spaced).fields).toEqual({});
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

  it('extracts bounded ASA 106023 access-group wrapper variants and preserves the source text',()=>{
    const raw='LOCAL4.WARNING: fw-1 %ASA-4-106023: Deny udp src v1:outside:192.0.2.10/54864 dst v2:inside:198.51.100.3/53 by access-group "outside_acl" [0x0, 0x0]';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields).toMatchObject({
      syslog:{app_tag:'%ASA-4-106023',source_facility:'LOCAL4',source_level:'WARNING',hostname:'fw-1'},
      asa:{source_raw:raw,product:'ASA',severity:'4',message_id:'106023',action:'Deny',protocol:'udp',
        src_context:'v1',src_interface:'outside',src_ip:'192.0.2.10',src_port:'54864',
        dst_context:'v2',dst_interface:'inside',dst_ip:'198.51.100.3',dst_port:'53',
        access_group:'outside_acl',flag_1:'0x0',flag_2:'0x0'},
    });
    const noPorts=raw.replace('/54864','').replace('/53','');
    expect(extractGenericStructural(noPorts).errors).toEqual([]);
    const hostOnly='fw-edge : '+raw.slice(raw.indexOf('%ASA'));
    expect(extractGenericStructural(hostOnly).fields).toMatchObject({syslog:{hostname:'fw-edge'},asa:{message_id:'106023'}});
    expect(extractGenericStructural(raw.replace('v1:outside','v9:outside')).fields).toEqual({});
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
