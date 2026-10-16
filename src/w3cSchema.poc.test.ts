import {describe,expect,it} from 'vitest';
import {mapW3cRow,parseW3cFieldsHeader} from './w3cTabular';

const header='#Fields: date time c-ip cs-method cs-uri-stem sc-status cs(User-Agent)';
const row='2026-10-16 15:44:21 192.0.2.10 GET /login 403 "Mozilla/5.0 Test Agent"';

describe('W3C/IIS schema-aware log PoC',()=>{
  it('maps a W3C row using its explicit #Fields header',()=>{
    const schema=parseW3cFieldsHeader(header);
    expect(schema).not.toBeNull();
    if(!schema)return;
    expect(mapW3cRow(row,schema)).toMatchObject({
      date:'2026-10-16',
      time:'15:44:21',
      'c-ip':'192.0.2.10',
      'cs-method':'GET',
      'cs-uri-stem':'/login',
      'sc-status':'403',
      'cs(User-Agent)':'Mozilla/5.0 Test Agent',
    });
  });

  it('preserves unset values and quoted fields',()=>{
    const schema=parseW3cFieldsHeader('#Fields: date time c-ip cs-method cs-uri-stem sc-status');
    expect(schema).not.toBeNull();
    if(!schema)return;
    expect(mapW3cRow('2026-10-16 15:44:21 - POST "/api/login" 401',schema)).toMatchObject({
      'c-ip':'-',
      'cs-uri-stem':'/api/login',
    });
  });

  it('rejects unsafe headers, duplicate fields, malformed quoting, and cardinality mismatches',()=>{
    const invalidHeaders=[
      '#Fields: date time method',
      '#Fields: date time a b constructor',
      '#Fields: date time a b a',
      '#Fields date time a b c',
      '#Fields: date time bad$field c d e',
    ];
    expect(invalidHeaders.filter(raw=>parseW3cFieldsHeader(raw)!==null)).toEqual([]);
    const schema=parseW3cFieldsHeader(header)!;
    expect(mapW3cRow(row+' extra',schema)).toBeNull();
    expect(mapW3cRow('2026-10-16 15:44:21 192.0.2.10 GET /login 403 "unterminated',schema)).toBeNull();
    expect(mapW3cRow('#Date: 2026-10-16',schema)).toBeNull();
  });
});
