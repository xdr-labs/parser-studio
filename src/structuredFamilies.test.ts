import { describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { detectFormat, extractFields, preview } from './parser';
import { toBackendProject } from './guided/backendAdapter';

const cef = 'CEF:0|Acme|Firewall|1.0|100|Denied|5|action=deny src_ip=198.51.100.10 dst_port=443';
const leef = 'LEEF:1.0|Acme|Firewall|1.0|100|action=deny\tsrc_ip=198.51.100.10\tdst_port=443';
const rfc5424 = '<34>1 2026-10-12T00:00:00Z fw app 1 EV01 - action=deny src_ip=198.51.100.10';
describe('reviewed standalone structured log families in local no-code preview', () => {
  it.each([
    ['cef', cef, 'cef_device_vendor', 'Acme'],
    ['leef', leef, 'leef_vendor', 'Acme'],
    ['syslog_rfc5424', rfc5424, 'syslog_hostname', 'fw'],
  ] as const)('%s exposes backend-compatible field names with an explicit DRAFT contract', (format, log, key, value) => {
    const draft = createDraft();
    draft.format = format;
    expect(detectFormat(log).format).toBe(format);
    const parsed = extractFields(log, format, draft);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields[key]).toBe(value);
    const converted = toBackendProject(draft);
    expect(converted.ok).toBe(true);
    if (converted.ok) expect(converted.project.extraction.format).toBe(format);
  });

  it('extracts and normalizes a standalone CEF event, never silently stripping extension values', () => {
    const draft = createDraft();
    draft.format = 'cef';
    const result = preview(cef, draft);
    expect(result.counts).toMatchObject({ total: 1, matched: 1, normalized: 1, failures: 0 });
    expect(result.events[0].fields).toMatchObject({
      cef_device_vendor: 'Acme', cef_name: 'Denied',
      action: 'deny', src_ip: '198.51.100.10', dst_port: '443',
    });
  });

  it('keeps spaces inside CEF extension values until the next explicit key boundary',()=>{
    const draft=createDraft();draft.format='cef';
    const raw='CEF:0|Trend Micro|Vision One|1|100|Detection|7|src=192.0.2.10 msg=Malware detected on endpoint act=blocked cs1=a\\=b';
    const parsed=extractFields(raw,'cef',draft);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields).toMatchObject({
      src:'192.0.2.10',msg:'Malware detected on endpoint',act:'blocked',cs1:'a=b',
    });
    const result=preview(raw,draft);
    expect(result.counts).toMatchObject({total:1,matched:1,extracted:1,failures:0});
  });


  it.each([
    ['json', '{"action":"deny","src_ip":"198.51.100.10"}', {action:'deny',src_ip:'198.51.100.10'}],
    ['kv', 'action=deny src_ip=198.51.100.10', {action:'deny',src_ip:'198.51.100.10'}],
  ] as const)('RFC5424 %s body yields backend-compatible nested body fields', (bodyFormat, body, expected) => {
    const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat=bodyFormat;
    const log='<34>1 2026-10-12T00:00:00Z fw app 1 EV01 - '+body;
    const parsed=extractFields(log,'syslog_rfc5424',draft);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.body).toEqual(expected);
    const converted=toBackendProject(draft);
    expect(converted.ok).toBe(true);
    if (converted.ok) expect(converted.project.extraction).toEqual({
      format:'syslog_rfc5424',syslogBodyFormat:bodyFormat,
    });
  });

  it('fails closed for malformed RFC5424 JSON/KV body or unreviewed body syntax', () => {
    const draft=createDraft();draft.format='syslog_rfc5424';
    const prefix='<34>1 2026-10-12T00:00:00Z fw app 1 EV01 - ';
    draft.syslogBodyFormat='json';
    expect(extractFields(prefix+'[1,2]', 'syslog_rfc5424',draft).errors.length).toBeGreaterThan(0);
    expect(extractFields(prefix+'{"action":', 'syslog_rfc5424',draft).errors.length).toBeGreaterThan(0);
    draft.syslogBodyFormat='kv';
    expect(extractFields(prefix+'action=deny bad suffix', 'syslog_rfc5424',draft).errors.length).toBeGreaterThan(0);
    draft.syslogBodyFormat='code' as 'raw';
    expect(toBackendProject(draft).ok).toBe(false);
  });

  it('rejects malformed CEF/LEEF structures and unsupported mixed headers in local preview', () => {
    const draft = createDraft();
    draft.format = 'cef';
    expect(extractFields('CEF:0|short|header', 'cef', draft).errors.length).toBeGreaterThan(0);
    expect(extractFields('CEF:0|a|b|c|d|e|f|broken', 'cef', draft).errors.length).toBeGreaterThan(0);
    draft.format = 'leef';
    expect(extractFields('LEEF:9.9|a|b|c|d|x=1', 'leef', draft).errors.length).toBeGreaterThan(0);
    expect(extractFields('LEEF:1.0|a|b|c|d|broken', 'leef', draft).errors.length).toBeGreaterThan(0);
  });
  it('preserves the RFC3164 envelope while applying only an explicitly reviewed bounded Regex to the message body', () => {
    const raw='<134>May 5 17:51:17 dev01 %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500 to fw:192.168.2.2/443';
    const pattern='^%FTD-\\d-\\d+: Built \\w+ \\w+ connection (?<connection_id>\\d+) for [^:]+:(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<src_port>\\d+) to [^:]+:(?<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<dst_port>\\d+)$';
    const draft=createDraft();
    draft.format='syslog_rfc3164';draft.syslogBodyFormat='regex';draft.pattern=pattern;
    draft.mappings=[
      {id:'cid',source:'body.connection_id',target:'custom.connection_id',type:'integer'},
      {id:'src',source:'body.src_ip',target:'custom.source_ip',type:'ip'},
      {id:'spt',source:'body.src_port',target:'custom.source_port',type:'port'},
      {id:'dst',source:'body.dst_ip',target:'custom.destination_ip',type:'ip'},
      {id:'dpt',source:'body.dst_port',target:'custom.destination_port',type:'port'},
    ];
    draft.guided={...draft.guided!,groups:{cid:'top_fields',src:'top_fields',spt:'top_fields',dst:'top_fields',dpt:'top_fields'},
      classification:{defaultIndex:'Syslog',rules:[]}};
    const parsed=extractFields(raw,'syslog_rfc3164',draft);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields).toMatchObject({
      syslog_pri:134,syslog_hostname:'dev01',
      body:{connection_id:'111',src_ip:'10.10.10.10',src_port:'53500',dst_ip:'192.168.2.2',dst_port:'443'},
    });
    const result=preview(raw,draft);
    expect(result.counts).toMatchObject({total:1,matched:1,extracted:1,normalized:1,failures:0});
    expect(result.events[0].normalized).toMatchObject({
      'custom.connection_id':111,'custom.source_ip':'10.10.10.10','custom.source_port':53500,
      'custom.destination_ip':'192.168.2.2','custom.destination_port':443,
    });
    const converted=toBackendProject(draft);
    expect(converted.ok).toBe(true);
    if(converted.ok)expect(converted.project.extraction).toEqual({
      format:'syslog_rfc3164',syslogBodyFormat:'regex',pattern,
    });
    draft.pattern='(?<x>.*)+';
    expect(extractFields(raw,'syslog_rfc3164',draft).errors.length).toBeGreaterThan(0);
    expect(toBackendProject(draft).ok).toBe(false);
  });

});
