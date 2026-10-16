import {describe,expect,it} from 'vitest';
import {parseW3cLogBlock} from './w3cTabular';

describe('W3C/IIS/CloudFront block event breaker PoC',()=>{
  it('parses IIS-style space-delimited blocks with directives and quoted fields',()=>{
    const raw=[
      '#Software: Microsoft Internet Information Services 10.0',
      '#Version: 1.0',
      '#Date: 2026-10-16 15:44:20',
      '#Fields: date time c-ip cs-method cs-uri-stem sc-status cs(User-Agent)',
      '2026-10-16 15:44:21 192.0.2.10 GET /login 403 "Mozilla/5.0 Test Agent"',
      '2026-10-16 15:44:22 2001:db8::10 POST /api/login 401 "curl/8.0"',
    ].join('\n')+'\n';
    const parsed=parseW3cLogBlock(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.block.schema.delimiter).toBe('space');
    expect(parsed.block.rows).toHaveLength(2);
    expect(parsed.block.rows[0]).toMatchObject({'c-ip':'192.0.2.10','cs-method':'GET','sc-status':'403','cs(User-Agent)':'Mozilla/5.0 Test Agent'});
    expect(parsed.block.directives).toMatchObject({Software:'Microsoft Internet Information Services 10.0',Version:'1.0',Date:'2026-10-16 15:44:20'});
  });

  it('parses CloudFront-style tab-delimited blocks without changing explicit source schema names',()=>{
    const raw=[
      '#Version: 1.0',
      '#Fields: date time x-edge-location sc-bytes c-ip cs-method cs-uri-stem sc-status',
      '2026-10-16\t15:44:21\tICN1\t392\t192.0.2.100\tGET\t/login\t403',
      '2026-10-16\t15:44:22\tICN1\t412\t192.0.2.101\tPOST\t/api\t401',
    ].join('\n')+'\n';
    const parsed=parseW3cLogBlock(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.block.schema.delimiter).toBe('tab');
    expect(parsed.block.rows[1]).toMatchObject({'x-edge-location':'ICN1','c-ip':'192.0.2.101','sc-status':'401'});
  });

  it('rejects duplicate schemas, data-before-schema, mixed delimiters, malformed directives, and width drift',()=>{
    const invalid=[
      '#Fields: date time host\n#Fields: date time host\n2026-10-16 15:44:21 edge\n',
      '2026-10-16 15:44:21 edge\n#Fields: date time host\n',
      '#Fields: date time host\n2026-10-16\t15:44:21\tedge\n2026-10-16 15:44:22 edge\n',
      '#Bad Directive\n#Fields: date time host\n2026-10-16 15:44:21 edge\n',
      '#Fields: date time host\n2026-10-16 15:44:21\n',
      '#Fields: date constructor host\n2026-10-16 x edge\n',
      '#Fields: date time host\n',
    ];
    const accepted=invalid.filter(raw=>parseW3cLogBlock(raw).ok);
    console.log('W3C_BLOCK_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
