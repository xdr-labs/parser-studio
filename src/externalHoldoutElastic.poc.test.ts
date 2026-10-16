import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

// Independent raw holdout adapted/redacted from Elastic integrations pipeline fixtures.
const samples=[
  {id:'fortigate-utm-ssl',family:'fortigate',raw:'<190>date=2024-08-28 time=10:33:52 devname="FW01" devid="FG3000" eventtime=1724834031664506909 tz="+0200" logid="1700062307" type="utm" subtype="ssl" eventtype="ssl-anomaly" level="information" action="info" srcip=10.2.3.4 srcport=59968 dstip=10.3.2.1 dstport=8443 proto=6 msg="SNI and certificate info is mismatched"'},
  {id:'fortigate-appctrl',family:'fortigate',raw:'<190>date=2024-10-15 time=10:29:59 devname="FW02" devid="FG1000" eventtime=1728980999046121575 tz="+0200" logid="1059021234" type="utm" subtype="app-ctrl" eventtype="signature" level="information" srcip=10.8.1.2 dstip=10.1.2.3 srcport=61745 dstport=443 proto=6 action="pass" app="HTTP.BROWSER_Chrome" hostname="example.test" msg="Web.Client: HTTP.BROWSER_Chrome"'},
  {id:'fortigate-url',family:'fortigate',raw:'<190>date=2025-04-30 time=15:04:29 devname="FW03" devid="FG2000" eventtime=1746018269233394322 tz="+0200" logid="1059021234" type="utm" subtype="app-ctrl" level="information" srcip=10.2.3.4 dstip=10.4.5.6 srcport=55822 dstport=443 proto=6 service="HTTPS" action="pass" url="/dt?x=1&y=2" msg="Web.Client: HTTP.BROWSER_Chrome"'},

  {id:'checkpoint-login',family:'checkpoint',raw:'<134>1 2023-12-29T14:20:02Z CP-Manager CheckPoint 10547 - [action:"Accept"; flags:"163872"; ifdir:"outbound"; origin:"192.168.1.153"; administrator:"WEB_API"; client_ip:"192.168.1.153"; operation:"Log In"; product:"WEB_API"; subject:"Administrator Login"]'},
  {id:'checkpoint-login-failure',family:'checkpoint',raw:'<134>1 2023-12-27T09:39:55Z CP-Manager CheckPoint 10547 - [action:"Accept"; flags:"163872"; origin:"192.168.1.153"; additional_info:"Administrator failed to log in: Wrong Password"; administrator:"user@example.org"; audit_status:"Failure"; client_ip:"172.16.1.190"; operation:"Log In"; product:"SmartConsole"; subject:"Administrator Login"]'},
  {id:'checkpoint-expert-shell',family:'checkpoint',raw:'<134>1 2023-12-22T08:38:43Z CP-Manager CheckPoint 10547 - [alert:"Expert_Alert"; flags:"139296"; ifdir:"inbound"; origin:"10.16.109.248"; administrator:"admin"; client_ip:"10.16.109.244"; device_name:"GW01"; device_type:"GW"; operation:"Log In"; product:"Expert Shell"; subject:"Administrator Expert Shell login"]'},

  {id:'ise-auth-unknown',family:'cisco-ise',raw:'<183>Mar 3 09:22:59 isehost CISE_Authentication_Flow_Diagnostics 0000082628 1 0 2022-03-03 09:22:59.360 +00:00 0000082695 22016 DEBUG Workflow: Identity sequence completed iterating the IDStores, ConfigVersionId=1628, UserName=admin, SelectedAccessService=AuthenticateUserAPI, AuthenticationMethod=PAP_ASCII, Response={AuthenticationResult=UnknownUser; },'},
  {id:'ise-auth-pass',family:'cisco-ise',raw:'<183>Mar 3 09:24:13 isehost CISE_Authentication_Flow_Diagnostics 0000082651 1 0 2022-03-03 09:24:13.238 +00:00 0000082718 22037 DEBUG Workflow: Authentication Passed, ConfigVersionId=1628, UserName=test, SelectedAccessService=AuthenticateUserAPI, AuthenticationIdentityStore=Internal Users, AuthenticationMethod=PAP_ASCII, Response={AuthenticationResult=Passed; },'},
  {id:'ise-auth-fail',family:'cisco-ise',raw:'<182>Mar 3 09:22:51 isehost CISE_Authentication_Flow_Diagnostics 0000082605 1 0 2022-03-03 09:22:51.639 +00:00 0000082672 22040 INFO Authentication: Wrong password or invalid shared secret, ConfigVersionId=1628, UserName=employee1, AuthenticationMethod=PAP_ASCII, Response={AuthenticationResult=Failed; },'},
  {id:'ise-ad-fail',family:'cisco-ise',raw:'<180>Mar 3 10:42:25 cisco-ise-host CISE_AD_Connector 0000083094 1 0 2022-03-03 10:42:25.842 +00:00 0000083161 25012 WARN AD-Connector: Domain join failed, AD-Admin=ise.host.local, AD-Domain=host.local, AD-Error-Details=The user account is invalid, AD-IP-Address=89.160.20.156, AD-Organization-Unit=, AD-Site=Default-First-Site-Name,'},
  {id:'ise-ad-short',family:'cisco-ise',raw:'<182>Mar 3 10:42:25 +02:00 cisco-ise-host CISE_AD_Connector 0000083089 2 1 AD-Domain=host.local, AD-Domain-Controller=host.local, AD-IP-Address=89.160.20.156, AD-Site=Default-First-Site-Name,'},

  {id:'sophos-xg-av',family:'sophos',raw:'device="SFW" date=2016-12-02 time=18:48:18 timezone="GMT" device_name="SFVUNL" device_id=C01001K234RXPA1 log_id=034806208001 log_type="Anti-Virus" log_component="HTTPS" log_subtype="Virus" priority=Critical user_name="rich" virus="EICAR-AV-Test" src_ip=192.168.73.220 dst_ip=216.160.83.61 protocol="TCP" src_port=51499 dst_port=443 sent_bytes=0 recv_bytes=353'},
  {id:'sophos-utm-drop',family:'sophos',raw:'2023:04:28-00:50:54 sophos-test-vm1 ulogd[12511]: id="2021" severity="info" sys="SecureNet" sub="packetfilter" name="Packet dropped (GEOIP)" action="drop" fwrule="60019" initf="eth6" srcip="67.43.156.2" dstip="89.160.20.129" proto="6" srcport="443" dstport="42181" tcpflags="ACK PSH"'},
  {id:'sophos-utm-pri',family:'sophos',raw:'<30>2023:04:28-11:28:41 sophos-test-vm1 ulogd[12511]: id="2014" severity="info" sys="SecureNet" sub="packetfilter" name="DNS request" action="DNS request" fwrule="60011" srcip="67.43.156.2" dstip="89.160.20.129" proto="17" srcport="34200" dstport="53"'},

  {id:'crowdstrike-firewall',family:'crowdstrike',raw:JSON.stringify({metadata:{eventType:'FirewallMatchEvent',eventCreationTime:1698921571000,version:'1.0'},event:{EventType:'FirewallRuleIP4Matched',HostName:'ENDPOINT01',LocalAddress:'81.2.69.142',LocalPort:'445',RemoteAddress:'81.2.69.143',RemotePort:'53452',Protocol:'6',RuleAction:'2'}})},
  {id:'crowdstrike-detection',family:'crowdstrike',raw:JSON.stringify({metadata:{eventType:'DetectionSummaryEvent',eventCreationTime:1698932615000,version:'1.0'},event:{ComputerName:'HOST01',UserName:'analyst',DetectName:'AttackerMethodology',SeverityName:'High',FileName:'rundll32.exe',CommandLine:'rundll32.exe payload.dll,Entry',LocalIP:'81.2.69.144',Tactic:'DefenseEvasion',Technique:'Rundll32'}})},
  {id:'crowdstrike-auth',family:'crowdstrike',raw:JSON.stringify({metadata:{eventType:'AuthActivityAuditEvent',eventCreationTime:1698927699286,version:'1.0'},event:{UserId:'admin@example.com',UserIp:'81.2.69.144',OperationName:'saml2Assert',ServiceName:'CrowdstrikeAuthentication',Success:true}})},

  {id:'okta-logout',family:'okta',raw:JSON.stringify({actor:{alternateId:'user@example.com',type:'User'},client:{ipAddress:'175.16.199.1'},displayMessage:'User logout from Okta',eventType:'user.session.end',outcome:{result:'SUCCESS'},published:'2020-02-14T22:18:51.843Z',severity:'INFO',uuid:'a1'})},
  {id:'okta-login',family:'okta',raw:JSON.stringify({actor:{alternateId:'user@example.com',type:'User'},client:{ipAddress:'175.16.199.1'},displayMessage:'User login to Okta',eventType:'user.session.start',outcome:{result:'SUCCESS'},published:'2020-02-14T20:18:57.718Z',severity:'INFO',uuid:'a2'})},
  {id:'okta-policy',family:'okta',raw:JSON.stringify({actor:{alternateId:'user@example.com',type:'User'},client:{ipAddress:'175.16.199.1'},displayMessage:'Evaluation of sign-on policy',eventType:'policy.evaluate_sign_on',outcome:{reason:'Sign-on policy evaluation resulted in ALLOW',result:'ALLOW'},published:'2020-02-14T20:18:57.762Z',severity:'INFO',uuid:'a3'})},
] as const;

describe('external Elastic integrations raw-fixture holdout',()=>{
  it('measures current coverage before Elastic-driven improvements',()=>{
    const rows=samples.map(sample=>{
      const result=parseSecurityInput(sample.raw);
      return {id:sample.id,family:sample.family,parsed:result.ok,kind:result.ok?result.kind:'error',keys:result.ok?Object.keys(result.events[0]?.fields??{}):[]};
    });
    const families=[...new Set(samples.map(sample=>sample.family))];
    const summary={
      total:rows.length,parsed:rows.filter(row=>row.parsed).length,
      failures:rows.filter(row=>!row.parsed).map(row=>row.id),
      byFamily:Object.fromEntries(families.map(family=>[family,{
        total:rows.filter(row=>row.family===family).length,
        parsed:rows.filter(row=>row.family===family&&row.parsed).length,
      }])),
      successes:rows.filter(row=>row.parsed).map(row=>({id:row.id,keys:row.keys})),
    };
    console.log('ELASTIC_EXTERNAL_HOLDOUT '+JSON.stringify(summary));
    expect(rows).toHaveLength(samples.length);
    expect(summary.parsed).toBe(samples.length);
    expect(summary.failures).toEqual([]);
    expect(rows.filter(row=>row.family==='fortigate').every(row=>row.keys.includes('fortinet'))).toBe(true);
    expect(rows.filter(row=>row.family==='cisco-ise').every(row=>row.keys.includes('cisco_ise'))).toBe(true);
    expect(rows.filter(row=>row.family==='sophos').every(row=>row.keys.includes('sophos'))).toBe(true);
  });
});
