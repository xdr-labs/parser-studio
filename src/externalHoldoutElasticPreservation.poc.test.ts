import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const samples=[
  {id:'fortigate',raw:'<190>date=2024-08-28 time=10:33:52 devname="FW01" devid="FG3000" eventtime=1724834031664506909 tz="+0200" logid="1700062307" type="utm" subtype="ssl" eventtype="ssl-anomaly" level="information" action="info" srcip=10.2.3.4 srcport=59968 dstip=10.3.2.1 dstport=8443 proto=6 msg="SNI mismatch"',required:['FW01','FG3000','ssl-anomaly','10.2.3.4','10.3.2.1','59968','8443','SNI mismatch']},
  {id:'checkpoint',raw:'<134>1 2023-12-29T14:20:02Z CP-Manager CheckPoint 10547 - [action:"Accept"; flags:"163872"; origin:"192.168.1.153"; administrator:"WEB_API"; client_ip:"192.168.1.153"; operation:"Log In"; product:"WEB_API"; subject:"Administrator Login"]',required:['CP-Manager','CheckPoint','Accept','192.168.1.153','WEB_API','Log In','Administrator Login']},
  {id:'cisco-ise',raw:'<183>Mar 3 09:24:13 isehost CISE_Authentication_Flow_Diagnostics 0000082651 1 0 2022-03-03 09:24:13.238 +00:00 0000082718 22037 DEBUG Workflow: Authentication Passed, ConfigVersionId=1628, UserName=test, SelectedAccessService=AuthenticateUserAPI, AuthenticationIdentityStore=Internal Users, AuthenticationMethod=PAP_ASCII, Response={AuthenticationResult=Passed; }',required:['isehost','CISE_Authentication_Flow_Diagnostics','Authentication Passed','test','AuthenticateUserAPI','PAP_ASCII','AuthenticationResult=Passed']},
  {id:'sophos-xg',raw:'device="SFW" date=2016-12-02 time=18:48:18 timezone="GMT" device_name="SFVUNL" device_id=C01001 log_id=034806208001 log_type="Anti-Virus" log_component="HTTPS" priority=Critical virus="EICAR-AV-Test" src_ip=192.168.73.220 dst_ip=216.160.83.61 protocol="TCP" src_port=51499 dst_port=443',required:['SFW','SFVUNL','Anti-Virus','EICAR-AV-Test','192.168.73.220','216.160.83.61','51499','443']},
  {id:'sophos-utm',raw:'2023:04:28-00:50:54 sophos-test-vm1 ulogd[12511]: id="2021" severity="info" sys="SecureNet" sub="packetfilter" name="Packet dropped" action="drop" srcip="67.43.156.2" dstip="89.160.20.129" proto="6" srcport="443" dstport="42181"',required:['sophos-test-vm1','12511','SecureNet','packetfilter','Packet dropped','67.43.156.2','89.160.20.129','42181']},
  {id:'crowdstrike',raw:JSON.stringify({metadata:{eventType:'DetectionSummaryEvent',eventCreationTime:1698932615000,version:'1.0'},event:{ComputerName:'HOST01',UserName:'analyst',DetectName:'AttackerMethodology',SeverityName:'High',FileName:'rundll32.exe',LocalIP:'81.2.69.144',Tactic:'DefenseEvasion',Technique:'Rundll32'}}),required:['DetectionSummaryEvent','HOST01','analyst','AttackerMethodology','High','rundll32.exe','81.2.69.144','DefenseEvasion']},
  {id:'okta',raw:JSON.stringify({actor:{alternateId:'user@example.com',type:'User'},client:{ipAddress:'175.16.199.1'},displayMessage:'User login to Okta',eventType:'user.session.start',outcome:{result:'SUCCESS'},published:'2020-02-14T20:18:57.718Z',severity:'INFO',uuid:'a2'}),required:['user@example.com','175.16.199.1','User login to Okta','user.session.start','SUCCESS','INFO']},
] as const;

describe('Elastic raw holdout source-preservation audit',()=>{
  it('keeps required source values reachable in the final structured result',()=>{
    const rows=samples.map(sample=>{
      const result=parseSecurityInput(sample.raw);
      if(!result.ok)return {id:sample.id,parsed:false,missing:[...sample.required]};
      const serialized=JSON.stringify(result.events[0]?.fields??{});
      return {id:sample.id,parsed:true,missing:sample.required.filter(value=>!serialized.includes(value))};
    });
    console.log('ELASTIC_HOLDOUT_PRESERVATION '+JSON.stringify(rows));
    expect(rows.every(row=>row.parsed)).toBe(true);
    expect(rows.flatMap(row=>row.missing)).toEqual([]);
  });
});
