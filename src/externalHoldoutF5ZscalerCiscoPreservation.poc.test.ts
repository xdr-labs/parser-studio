import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const samples=[
  {id:'f5',raw:'<134>Aug  6 12:03:36 f5qa ASM:unit_hostname="f5qa",management_ip_address="10.52.34.33",policy_name="/Common/asmpolicy",request_status="passed",response_code="200",ip_client="10.43.24.23",method="HEAD",protocol="HTTPS",src_port="50668",dest_port="443",dest_ip="10.30.4.56",uri="/repository/file.jar"',required:['f5qa','10.52.34.33','/Common/asmpolicy','10.43.24.23','HEAD','443','/repository/file.jar']},
  {id:'zscaler',raw:JSON.stringify({version:'v2',sourcetype:'zscalernss-fw',event:{datetime:'2026-06-24 12:34:56',cdip:'2a02:cf40::',sdip:'67.43.156.0',action:'Blocked',proto:'TCP',user:'jdoe%40example.com'}}),required:['zscalernss-fw','2a02:cf40::','67.43.156.0','Blocked','jdoe%40example.com']},
  {id:'cisco-endpoint',raw:JSON.stringify({version:'v1.2.0',metadata:{results:{total:972,index:500}},data:{event_type:'Threat Detected',detection:'W32.Overdrive.RET',severity:'Medium',computer:{hostname:'HOST01',external_ip:'81.2.69.144'},file:{file_name:'BIT657.tmp'}}}),required:['v1.2.0','Threat Detected','W32.Overdrive.RET','Medium','HOST01','81.2.69.144','BIT657.tmp']},
] as const;

describe('F5/Zscaler/Cisco holdout source-preservation audit',()=>{
  it('keeps required source values reachable in structured results',()=>{
    const rows=samples.map(sample=>{
      const result=parseSecurityInput(sample.raw);
      if(!result.ok)return {id:sample.id,parsed:false,missing:[...sample.required]};
      const serialized=JSON.stringify(result.events[0]?.fields??{});
      return {id:sample.id,parsed:true,missing:sample.required.filter(value=>!serialized.includes(value))};
    });
    console.log('F5_ZSCALER_CISCO_PRESERVATION '+JSON.stringify(rows));
    expect(rows.every(row=>row.parsed)).toBe(true);
    expect(rows.flatMap(row=>row.missing)).toEqual([]);
  });
});
