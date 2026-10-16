import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const asa=(src:string,dst:string,srcPort='443',dstPort='51822') =>
  '<166>Oct 16 15:44:21 ASA01 : %ASA-6-302013: Built outbound TCP connection 1 for outside:'+
  src+'/'+srcPort+' ('+src+'/443) to inside:'+dst+'/'+dstPort+' (198.51.100.15/51822)';

const juniper=(tuple:string) =>
  'Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created '+
  tuple+' None '+tuple+' None None 17 allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255';

describe('network token strictness PoC',()=>{
  it('keeps valid IPv4 and IPv6 ASA addresses parseable',()=>{
    const valid=[
      asa('203.0.113.50','10.1.15.27'),
      asa('2001:db8:1::10','2001:db8:2::20'),
    ];
    const failures=valid.filter(raw=>extractGenericStructural(raw).errors.length>0);
    expect(failures).toEqual([]);
  });

  it('rejects malformed ASA addresses and ports',()=>{
    const invalid=[
      asa('999.999.999.999','10.1.15.27'),
      asa('203.0.113.50','999.1.1.1'),
      asa('2001:::10','2001:db8::20'),
      asa('203.0.113.50','10.1.15.27','70000'),
      asa('203.0.113.50','10.1.15.27','443','70000'),
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('ASA_NETWORK_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });

  it('keeps valid IPv4 and IPv6 Juniper flow tuples parseable',()=>{
    const valid=[
      juniper('192.168.83.99/40275->192.168.32.1/161'),
      juniper('2001:db8:1::10/40275->2001:db8:2::20/161'),
    ];
    const failures=valid.filter(raw=>extractGenericStructural(raw).errors.length>0);
    console.log('JUNIPER_TUPLE_VALID '+JSON.stringify({total:valid.length,failures}));
    expect(failures).toEqual([]);
  });

  it('rejects malformed Juniper flow tuples',()=>{
    const invalid=[
      juniper('999.999.999.999/40275->192.168.32.1/161'),
      juniper('not-an-ip/40275->192.168.32.1/161'),
      juniper('2001:::10/40275->2001:db8::20/161'),
      juniper('192.168.83.99/70000->192.168.32.1/161'),
      juniper('192.168.83.99/40275->192.168.32.1/70000'),
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('JUNIPER_TUPLE_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
