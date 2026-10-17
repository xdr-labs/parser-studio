import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const samples=[
  {id:'f5-asm-head',family:'f5-raw',raw:'<134>Aug  6 12:03:36 f5qa ASM:unit_hostname="f5qa",management_ip_address="10.52.34.33",http_class_name="/Common/asmpolicy",policy_name="/Common/asmpolicy",request_status="passed",response_code="200",ip_client="10.43.24.23",method="HEAD",protocol="HTTPS",x_forwarded_for_header_value="10.43.24.23, 10.43.24.24",severity="Informational",src_port="50668",dest_port="443",dest_ip="10.30.4.56",uri="/repository/file.jar"'},
  {id:'f5-asm-block',family:'f5-raw',raw:'<134>Jul 14 09:12:05 f5-asm ASM:unit_hostname="f5-asm",management_ip_address="192.0.2.10",policy_name="/Common/login_policy",violations="Illegal meta character in value",support_id="1730614276869062796",request_status="blocked",ip_client="198.51.100.201",method="POST",protocol="HTTP",severity="Error",attack_type="Non-browser Client",src_port="52344",dest_port="80",dest_ip="192.0.2.115",uri="/login"'},
  {id:'f5-asm-parser',family:'f5-raw',raw:'<134>Jul 14 09:20:11 f5-asm ASM:unit_hostname="f5-asm",management_ip_address="192.0.2.10",policy_name="/Common/login_policy",violations="Multiple host headers",request_status="blocked",ip_client="198.51.100.202",method="GET",protocol="HTTPS",severity="Critical",attack_type="HTTP Parser Attack",src_port="41022",dest_port="443",dest_ip="192.0.2.116",uri="/portal"'},

  {id:'zscaler-v1',family:'zscaler-json',raw:JSON.stringify({sourcetype:'zscalernss-fw',event:{datetime:'Mon Oct 16 22:55:48 2023',cdip:'1.128.0.0',cdport:'22',sdip:'1.128.0.0',sdport:'443',action:'Blocked',proto:'TCP',user:'jdoe@example.com',threatcat:'Botnet Callback',threat_name:'Linux.Backdoor.Tsunami'}})},
  {id:'zscaler-v2',family:'zscaler-json',raw:JSON.stringify({version:'v2',sourcetype:'zscalernss-fw',event:{datetime:'2026-06-24 12:34:56',cdip:'2a02:cf40::',cdport:'22',sdip:'67.43.156.0',sdport:'443',action:'Blocked',proto:'TCP',user:'jdoe%40example.com',rule:'Default_Firewall_Filtering_Rule'}})},
  {id:'zscaler-ipv6',family:'zscaler-json',raw:JSON.stringify({sourcetype:'zscalernss-fw',event:{datetime:'Mon Oct 16 22:55:48 2023',cdip:'2a02:cf40::',sdip:'67.43.156.0',csip:'0.0.0.0',action:'Blocked',proto:'TCP',numsessions:'5',tuntype:'L2 tunnel'}})},

  {id:'cisco-amp-detect',family:'cisco-endpoint-json',raw:JSON.stringify({version:'v1.2.0',metadata:{results:{total:972,index:500}},data:{id:6533241347137077000,date:'2021-01-14T10:06:39+00:00',event_type:'Threat Detected',event_type_id:1090519054,detection:'W32.Overdrive.RET',severity:'Medium',computer:{hostname:'Demo_AMP_Threat_Quarantined',external_ip:'81.2.69.144',user:'user@example.com'},file:{disposition:'Malicious',file_name:'BIT657.tmp',identity:{sha256:'a78c29d1fa05c2b23d1dc9b75da8c053399143682fe3779bc466f10e1a997850'}}}})},
  {id:'cisco-amp-quarantine',family:'cisco-endpoint-json',raw:JSON.stringify({version:'v1.2.0',metadata:{results:{total:972,index:500}},data:{id:6533241347137077001,date:'2021-01-14T10:06:40+00:00',event_type:'Threat Quarantined',event_type_id:553648143,severity:'Medium',computer:{hostname:'HOST01',external_ip:'81.2.69.144'},file:{disposition:'Malicious',identity:{sha256:'a78c29d1fa05c2b23d1dc9b75da8c053399143682fe3779bc466f10e1a997850'}}}})},
  {id:'cisco-amp-ioc',family:'cisco-endpoint-json',raw:JSON.stringify({version:'v1.2.0',metadata:{results:{total:972,index:500}},data:{id:1521138739875754000,date:'2021-01-14T10:05:50+00:00',event_type:'Cloud IOC',severity:'Medium',computer:{hostname:'HOST02',external_ip:'81.2.69.144'},cloud_ioc:{short_description:'W32.WScriptExecuteFakeExtension.ioc'},file:{file_name:'WScript.exe',file_path:'/C:/Windows/System32/WScript.exe'}}})},
] as const;

describe('external F5/Zscaler/Cisco raw holdout',()=>{
  it('measures current structural coverage before F5-specific refinement',()=>{
    const rows=samples.map(sample=>{
      const result=parseSecurityInput(sample.raw);
      return {id:sample.id,family:sample.family,parsed:result.ok,keys:result.ok?Object.keys(result.events[0]?.fields??{}):[]};
    });
    const families=[...new Set(samples.map(sample=>sample.family))];
    const summary={total:rows.length,parsed:rows.filter(row=>row.parsed).length,failures:rows.filter(row=>!row.parsed).map(row=>row.id),byFamily:Object.fromEntries(families.map(family=>[family,{total:rows.filter(row=>row.family===family).length,parsed:rows.filter(row=>row.family===family&&row.parsed).length}])),successes:rows.filter(row=>row.parsed).map(row=>({id:row.id,keys:row.keys}))};
    console.log('F5_ZSCALER_CISCO_HOLDOUT '+JSON.stringify(summary));
    expect(rows).toHaveLength(samples.length);
    // These Cisco AMP samples embed integer IDs greater than IEEE-754's
    // exact range. The original in-memory JS Number was already rounded
    // before JSON.stringify, so no independent original ID oracle remains.
    // Reject all three as REVIEW_ONLY/UNSCORABLE rather than re-promote
    // lossy parsed source. Historical denominator stays nine unchanged.
    const unsafeIdSamples=samples.filter(item=>item.family==='cisco-endpoint-json');
    expect(unsafeIdSamples).toHaveLength(3);
    for(const sample of unsafeIdSamples){
      const id=(JSON.parse(sample.raw) as {data:{id:number}}).data.id;
      expect(Number.isSafeInteger(id)).toBe(false);
    }
    expect(summary.parsed).toBe(6);
    expect(summary.failures).toEqual([
      'cisco-amp-detect','cisco-amp-quarantine','cisco-amp-ioc',
    ]);
    expect(rows.filter(row=>row.family==='f5-raw').every(row=>row.parsed&&row.keys.includes('f5_bigip'))).toBe(true);
    expect(rows.filter(row=>row.family==='zscaler-json').every(row=>row.parsed)).toBe(true);
  });
});
