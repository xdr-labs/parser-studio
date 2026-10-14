import { describe, expect, it } from 'vitest';
import { createDraft } from './model';
import { extractFields, preview } from './parser';
import { toBackendProject } from './guided/backendAdapter';

const head='<165>1 2026-10-12T01:02:03Z edge fw 1 ID ';
const cef='CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny';
const leef='LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^dstPort=80^act=allow';

describe('new backend RFC5424/CEF/LEEF reviewed subset browser parity', () => {
  it.each([
    ['cef', cef, 'cef_device_vendor', 'Synthetic'],
    ['leef', leef, 'leef_vendor', 'Synthetic'],
  ] as const)('extracts nested %s under body.* and emits its typed schema setting', (kind,event,key,value)=>{
    const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat=kind;
    draft.mappings.push({
      id:'nested',source:'body.src',target:'custom.nested_src',type:'ip',
    });
    const text=head+'- '+event;
    const extracted=extractFields(text,'syslog_rfc5424',draft);
    expect(extracted.errors).toEqual([]);
    expect((extracted.fields.body as Record<string,unknown>)[key]).toBe(value);
    const project=toBackendProject(draft);
    expect(project.ok).toBe(true);
    if(project.ok)expect(project.project.extraction).toEqual({format:'syslog_rfc5424',syslogBodyFormat:kind});
    const browser=preview(text,draft);
    expect(browser.counts).toMatchObject({total:1,matched:1,normalized:1,failures:0});
  });

  it('recognizes escaped and adjacent bounded RFC5424 SD elements without dropping the message',()=>{
    const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat='kv';
    const sd=String.raw`[origin@32473 note="a\]b"][trace@32473 id="2"]`;
    const extracted=extractFields(head+sd+' action=deny src_ip=192.0.2.20','syslog_rfc5424',draft);
    expect(extracted.errors).toEqual([]);
    expect(extracted.fields.syslog_structured_data).toBe(sd);
    expect(extracted.fields.body).toEqual({action:'deny',src_ip:'192.0.2.20'});
  });

  it.each([
    '[meta@32473 name=unquoted]',
    '[meta@32473 name="unterminated]',
    '[meta@32473 name="invalid\\q"]',
    '[meta@32473 name="one" name="two"]',
    '[meta@32473][meta@32473]',
    '[meta@32473]junk',
  ])('fails closed on malformed RFC5424 SD: %s', (sd)=>{
    const draft=createDraft();draft.format='syslog_rfc5424';
    expect(extractFields(head+sd,'syslog_rfc5424',draft).errors.length).toBeGreaterThan(0);
  });

  it.each([
    '<165>2 2026-10-12T01:02:03Z edge fw 1 ID - src_ip=192.0.2.2',
    '<165>1 2026-99-99T25:01:01Z edge fw 1 ID - src_ip=192.0.2.2',
    '<165>1 2026-10-12T01:02:03 edge fw 1 ID - src_ip=192.0.2.2',
    '<165>1 2026-10-12T01:02:03Z t\u00E9st fw 1 ID - src_ip=192.0.2.2',
  ])('rejects invalid RFC5424 version/timestamp/header before preview passes', text=>{
    const draft=createDraft();draft.format='syslog_rfc5424';
    expect(extractFields(text,'syslog_rfc5424',draft).errors.length).toBeGreaterThan(0);
  });

  it('rejects CEF versions beyond the reviewed standalone version zero',()=>{
    const draft=createDraft();draft.format='cef';
    expect(extractFields(cef.replace('CEF:0|','CEF:9|'),'cef',draft).errors.length).toBeGreaterThan(0);
  });

  it('accepts LEEF 2.0 hex byte separators and rejects controls/unknown escapes',()=>{
    const draft=createDraft();draft.format='leef';
    const valid='LEEF:2.0|Synthetic|FW|1|501|0x5E|src=203.0.113.8^dstPort=443^act=deny';
    expect(extractFields(valid,'leef',draft).fields).toMatchObject({src:'203.0.113.8',dstPort:'443',act:'deny'});
    for(const invalid of ['0x0A','0x00','0x3D','0xGG']){
      expect(extractFields(valid.replace('0x5E',invalid),'leef',draft).errors.length).toBeGreaterThan(0);
    }
  });

  it('rejects malformed RFC5424 envelopes wrapping CEF/LEEF rather than silently extracting partial data',()=>{
    const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat='cef';
    expect(extractFields(head+'- CEF:0|Synthetic|FW|1|42|Blocked|8|broken extension','syslog_rfc5424',draft).errors.length).toBeGreaterThan(0);
    draft.syslogBodyFormat='leef';
    expect(extractFields(head+'- LEEF:2.0|Synthetic|FW|1|501|::|src=192.0.2.10','syslog_rfc5424',draft).errors.length).toBeGreaterThan(0);
  });
});
