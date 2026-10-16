import {describe,expect,it} from 'vitest';
import {matchOrderedVendorSchema,VENDOR_SCHEMA_CATALOG} from './vendorSchemaRegistry';

const BASE=[
  '1','2026/10/15 00:03:21','012345678901','TRAFFIC','end','2561',
  '2026/10/15 00:03:20','10.10.20.15','8.8.8.8','203.0.113.10','8.8.8.8',
  'allow-web','','','ssl','vsys1','trust','untrust','ethernet1/1','ethernet1/2',
  'forward-all','2026/10/15 00:03:21','123456','1','51234','443','45001','443',
  '0x400000','tcp','allow','1480','720','760','12','2026/10/15 00:02:55','25',
  'any','0','0x0','10.0.0.0-10.255.255.255','United States','','6','6','tcp-fin',
  '0','0','0','0','','PA-FW01','from-policy',
];

describe('vendor schema registry',()=>{
  it('names the reviewed PAN-OS TRAFFIC core layout',()=>{
    const match=matchOrderedVendorSchema(BASE);
    expect(match).toMatchObject({
      vendor:'Palo Alto Networks',product:'PAN-OS',family:'TRAFFIC',
      profile:'panos.traffic.core53',knownFieldCount:53,unknownTailCount:0,
      fields:{src:'10.10.20.15',dst:'8.8.8.8',sport:'51234',dport:'443',
        protocol:'tcp',action:'allow',device_name:'PA-FW01',action_source:'from-policy'},
    });
  });

  it('preserves appended vendor drift without shifting reviewed field names',()=>{
    const match=matchOrderedVendorSchema([...BASE,'new-value','another-value']);
    expect(match?.profile).toBe('panos.traffic.core53');
    expect(match?.unknownTailCount).toBe(2);
    expect(match?.fields.action_source).toBe('from-policy');
    expect(match?.fields.vendor_extra_001).toBe('new-value');
    expect(match?.fields.vendor_extra_002).toBe('another-value');
  });

  it('recognizes the reviewed padding variant by anchors instead of total column count',()=>{
    const padded=[...BASE.slice(0,38),'',...BASE.slice(38),'future'];
    const match=matchOrderedVendorSchema(padded);
    expect(match?.profile).toBe('panos.traffic.padding54');
    expect(match?.fields.padding).toBe('');
    expect(match?.fields.seqno).toBe('0');
    expect(match?.fields.actionflags).toBe('0x0');
    expect(match?.fields.vendor_extra_001).toBe('future');
  });

  it('does not treat an arbitrary numeric inserted field as reviewed padding',()=>{
    const padded=[...BASE.slice(0,38),'0',...BASE.slice(38)];
    expect(matchOrderedVendorSchema(padded)).toBeNull();
  });

  it('fails closed for lookalikes with invalid or shifted core anchors',()=>{
    const malformed=[...BASE];
    malformed[24]='99999';
    expect(matchOrderedVendorSchema(malformed)).toBeNull();

    const shifted=[...BASE];
    shifted.splice(37,0,'unexpected-shift');
    expect(matchOrderedVendorSchema(shifted)).toBeNull();
  });

  it('publishes drift-safe schema descriptors',()=>{
    expect(VENDOR_SCHEMA_CATALOG.every(item=>item.driftPolicy==='preserve-tail')).toBe(true);
  });
});
