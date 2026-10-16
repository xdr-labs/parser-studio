import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseVpcFlowLogV2} from './awsVpcFlow';
import {mapW3cRow,parseW3cFieldsHeader} from './w3cTabular';

const flow4='2 123456789012 eni-0abc1234def567890 10.0.0.10 198.51.100.20 51514 443 6 10 8400 1760000000 1760000060 ACCEPT OK';
const flow6='2 123456789012 eni-0abc1234def567890 2001:db8::10 2001:db8::20 51514 443 6 12 9200 1760000000 1760000060 REJECT OK';
const noData='2 123456789012 eni-0abc1234def567890 - - - - - - - 1760000000 1760000060 - NODATA';

describe('cloud telemetry structural PoC',()=>{
  it('parses default VPC Flow v2 field order standalone and behind Syslog',()=>{
    for(const raw of [flow4,flow6,noData]){
      const flow=parseVpcFlowLogV2(raw);
      expect(flow,raw).not.toBeNull();
      const direct=extractGenericStructural(raw);
      expect(direct.errors,raw).toEqual([]);
      expect(direct.fields.aws_vpc_flow,raw).toEqual(flow);
    }
    const wrapped='<134>Oct 16 15:44:21 FLOW01 cloudwatch: '+flow4;
    const parsed=extractGenericStructural(wrapped);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.aws_vpc_flow).toMatchObject({
      version:'2',srcaddr:'10.0.0.10',dstaddr:'198.51.100.20',
      srcport:'51514',dstport:'443',action:'ACCEPT','log-status':'OK',
    });
  });

  it('rejects malformed default VPC Flow v2 records',()=>{
    const invalid=[
      flow4.replace(/^2 /,'3 '),
      flow4.replace('123456789012','12345'),
      flow4.replace('eni-0abc1234def567890','bad-interface'),
      flow4.replace('10.0.0.10','999.0.0.10'),
      flow4.replace('51514','70000'),
      flow4.replace(' 6 10 8400 ',' 999 10 8400 '),
      flow4.replace('1760000000 1760000060','1760000060 1760000000'),
      flow4.replace('ACCEPT OK','ALLOW OK'),
      flow4.replace('ACCEPT OK','ACCEPT BAD'),
      flow4+' extra',
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('VPC_FLOW_V2_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });

  it('maps CloudFront W3C schema headers onto tab-separated rows',()=>{
    const fields=[
      'date','time','x-edge-location','sc-bytes','c-ip','cs-method','cs(Host)','cs-uri-stem',
      'sc-status','cs(Referer)','cs(User-Agent)','cs-uri-query','cs(Cookie)','x-edge-result-type',
      'x-edge-request-id','x-host-header','cs-protocol','cs-bytes','time-taken','x-forwarded-for',
      'ssl-protocol','ssl-cipher','x-edge-response-result-type','cs-protocol-version','fle-status',
      'fle-encrypted-fields','c-port','time-to-first-byte','x-edge-detailed-result-type',
      'sc-content-type','sc-content-len','sc-range-start','sc-range-end',
    ];
    const values=[
      '2026-10-16','15:44:21','ICN1','392','192.0.2.100','GET','d111.example.net','/login',
      '403','-','Mozilla%2F5.0%20Test','-','-','Error','request-id-1','www.example.test','https',
      '23','0.012','-','TLSv1.3','TLS_AES_128_GCM_SHA256','Error','HTTP/2.0','-','-','51514',
      '0.003','Error','text/html','78','-','-',
    ];
    expect(fields).toHaveLength(33);
    expect(values).toHaveLength(33);
    const schema=parseW3cFieldsHeader('#Fields: '+fields.join(' '),'tab');
    expect(schema).not.toBeNull();
    if(!schema)return;
    const mapped=mapW3cRow(values.join('\t'),schema);
    expect(mapped).toMatchObject({
      date:'2026-10-16',time:'15:44:21','c-ip':'192.0.2.100',
      'cs-uri-stem':'/login','sc-status':'403','x-edge-result-type':'Error',
      'cs(User-Agent)':'Mozilla%2F5.0%20Test',
    });
    expect(mapW3cRow(values.join(' '),schema)).toBeNull();
    expect(mapW3cRow(values.slice(0,-1).join('\t'),schema)).toBeNull();
  });
});
