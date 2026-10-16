import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseCiscoIseBody,parseFortinetKvBody,parseSophosKvBody} from './applianceSecurityProfiles';

describe('appliance security source refinement PoC',()=>{
  it('parses FortiGate KV bodies with source anchors and network validation',()=>{
    const body='date=2024-08-28 time=10:33:52 devname="FW01" devid="FG3000" eventtime=1724834031664506909 tz="+0200" logid="1700062307" type="utm" subtype="ssl" action="info" srcip=10.2.3.4 srcport=59968 dstip=10.3.2.1 dstport=8443 proto=6 msg="SNI mismatch"';
    const parsed=parseFortinetKvBody(body);
    expect(parsed).toMatchObject({fields:{devname:'FW01',devid:'FG3000',type:'utm',srcip:'10.2.3.4',dstport:'8443'}});
    const wrapped=extractGenericStructural('<190>'+body);
    expect(wrapped.errors).toEqual([]);
    expect(wrapped.fields).toHaveProperty('fortinet');
  });

  it('rejects malformed FortiGate anchors instead of falling into loose KV',()=>{
    const base='date=2024-08-28 time=10:33:52 devname="FW01" devid="FG3000" tz="+0200" logid="1700062307" type="utm" srcip=10.2.3.4 dstip=10.3.2.1 srcport=59968 dstport=8443';
    const invalid=[
      base.replace('2024-08-28','2024-02-30'),
      base.replace('10:33:52','25:33:52'),
      base.replace('+0200','+2500'),
      base.replace('10.2.3.4','999.2.3.4'),
      base.replace('8443','70000'),
      base.replace('logid="1700062307"','logid="bad"'),
    ];
    expect(invalid.filter(raw=>parseFortinetKvBody(raw)!==null)).toEqual([]);
    expect(invalid.filter(raw=>extractGenericStructural('<190>'+raw).errors.length===0)).toEqual([]);
  });

  it('parses Cisco ISE common envelope with long and short variants',()=>{
    const long='CISE_Authentication_Flow_Diagnostics 0000082651 1 0 2022-03-03 09:24:13.238 +00:00 0000082718 22037 DEBUG Workflow: Authentication Passed, ConfigVersionId=1628, UserName=test, SelectedAccessService=AuthenticateUserAPI, AuthenticationIdentityStore=Internal Users, AuthenticationMethod=PAP_ASCII, Response={AuthenticationResult=Passed; }';
    const short='CISE_AD_Connector 0000083089 2 1 AD-Domain=host.local, AD-Domain-Controller=host.local, AD-IP-Address=89.160.20.156, AD-Site=Default-First-Site-Name,';
    expect(parseCiscoIseBody(long)).toMatchObject({header:{category:'CISE_Authentication_Flow_Diagnostics',level:'DEBUG'},message:'Workflow: Authentication Passed',fields:{UserName:'test',AuthenticationMethod:'PAP_ASCII'}});
    expect(parseCiscoIseBody(short)).toMatchObject({header:{category:'CISE_AD_Connector',format_major:'2',format_minor:'1'},fields:{'AD-Domain':'host.local','AD-IP-Address':'89.160.20.156'}});
    const wrapped=extractGenericStructural('<183>Mar 3 09:24:13 isehost '+long);
    expect(wrapped.errors).toEqual([]);
    expect(wrapped.fields).toHaveProperty('cisco_ise');
  });

  it('rejects malformed Cisco ISE timestamp, unsafe keys and broken comma quoting',()=>{
    const base='CISE_AD_Connector 0000083094 1 0 2022-03-03 10:42:25.842 +00:00 0000083161 25012 WARN AD-Connector: Domain join failed, AD-Domain=host.local, AD-IP-Address=89.160.20.156';
    const invalid=[
      base.replace('2022-03-03','2022-02-30'),
      base.replace('+00:00','+25:00'),
      base.replace('AD-Domain=host.local','constructor=bad'),
      base+' , Broken="unterminated',
      base.replace('0000083094','ABC'),
    ];
    expect(invalid.filter(raw=>parseCiscoIseBody(raw)!==null)).toEqual([]);
  });

  it('parses Sophos XG and UTM KV variants without sharing their envelope grammar',()=>{
    const xg='device="SFW" date=2016-12-02 time=18:48:18 timezone="GMT" device_name="SFVUNL" device_id=C01001 log_id=034806208001 log_type="Anti-Virus" log_component="HTTPS" priority=Critical src_ip=192.168.73.220 dst_ip=216.160.83.61 protocol="TCP" src_port=51499 dst_port=443';
    const utm='id="2021" severity="info" sys="SecureNet" sub="packetfilter" name="Packet dropped" action="drop" srcip="67.43.156.2" dstip="89.160.20.129" proto="6" srcport="443" dstport="42181"';
    expect(parseSophosKvBody(xg)).toMatchObject({variant:'xg',fields:{device:'SFW',src_ip:'192.168.73.220'}});
    expect(parseSophosKvBody(utm)).toMatchObject({variant:'utm',fields:{sys:'SecureNet',action:'drop'}});
    const full=extractGenericStructural('2023:04:28-00:50:54 sophos-test-vm1 ulogd[12511]: '+utm);
    expect(full.errors).toEqual([]);
    expect(full.fields).toHaveProperty('sophos');
  });

  it('keeps Check Point RFC5424 proprietary bracket fields source-specific and fail-closed',()=>{
    const valid='<134>1 2023-12-29T14:20:02Z CP-Manager CheckPoint 10547 - [action:"Accept"; administrator:"WEB_API"; client_ip:"192.168.1.153"; operation:"Log In"; subject:"Administrator Login"]';
    const parsed=extractGenericStructural(valid);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.body).toMatchObject({action:'Accept',administrator:'WEB_API',client_ip:'192.168.1.153',operation:'Log In'});
    const invalid=[
      valid.replace('action:"Accept"','action:Accept'),
      valid.replace('administrator:"WEB_API"','constructor:"bad"'),
      valid.replace('subject:"Administrator Login"','subject:"unterminated'),
    ];
    expect(invalid.filter(raw=>extractGenericStructural(raw).errors.length===0)).toEqual([]);
  });

  it('rejects malformed Sophos source anchors and network tokens',()=>{
    const xg='device="SFW" date=2016-12-02 time=18:48:18 timezone="GMT" device_name="SFVUNL" device_id=C01001 log_id=034806208001 log_type="Anti-Virus" src_ip=192.168.73.220 dst_ip=216.160.83.61 src_port=51499 dst_port=443';
    const invalid=[
      xg.replace('2016-12-02','2016-02-30'),
      xg.replace('18:48:18','29:48:18'),
      xg.replace('GMT','BADZONE9'),
      xg.replace('192.168.73.220','999.168.73.220'),
      xg.replace('dst_port=443','dst_port=70000'),
      xg.replace('device="SFW"','device="OTHER"'),
    ];
    expect(invalid.filter(raw=>parseSophosKvBody(raw)!==null)).toEqual([]);
  });
});
