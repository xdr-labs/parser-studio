import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { extractFields } from '../parser';
import { synthesizeReplayPreview } from './replayPreview';

const now=new Date('2026-10-12T11:34:56.000Z');
const entropy=()=>0.42;

describe('bounded, synthetic local replay preview: never send to a sensor',()=>{
  it('regenerates JSON timestamp, IP, user and URL while preserving parser-compatible keys',()=>{
    const draft=createDraft();draft.format='json';
    const source=JSON.stringify({
      timestamp:'2020-01-02T03:04:05Z', src_ip:'10.0.0.5',dst_ip:'172.16.2.2',
      username:'sensitive.user',url:'https://secret.example.com/customer?q=abc',
      action:'allow',nested:{user:'private.user'},
    });
    const result=synthesizeReplayPreview(source,draft,now,entropy);
    const data=JSON.parse(result.log);
    expect(data.timestamp).toBe('2026-10-12T11:34:56.000Z');
    expect(data.src_ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/);
    expect(data.dst_ip).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/);
    expect(data.username).toMatch(/^demo_user_\d+$/);
    expect(data.nested.user).toMatch(/^demo_user_\d+$/);
    expect(data.url).toMatch(/^https:\/\/example\.test\/replay\/\d+$/);
    expect(data.action).toBe('allow');
    expect(result).toMatchObject({mode:'LOCAL_PREVIEW_ONLY',sentToSensor:false});
    expect(result.mutations).toEqual(['timestamp','ip','username','url']);
    expect(extractFields(result.log,'json',draft).errors).toEqual([]);
  });

  it('rebuilds semicolon/TAB CSV with original column order and quoted separator values',()=>{
    for(const separator of [';','\t'] as const){
      const draft=createDraft();draft.format='csv';draft.csvColumns='action,src_ip,user,url,detail';draft.csvDelimiter=separator;
      const source=['deny','10.2.3.4','myname','https://private.example.com/hidden','"quoted'+separator+'detail"'].join(separator);
      const result=synthesizeReplayPreview(source,draft,now,entropy);
      const parsed=extractFields(result.log,'csv',draft);
      expect(parsed.errors).toEqual([]);
      expect(parsed.fields.action).toBe('deny');
      expect(parsed.fields.src_ip).not.toBe('10.2.3.4');
      expect(parsed.fields.user).toMatch(/^demo_user_\d+$/);
      expect(parsed.fields.url).toMatch(/^https:\/\/example\.test\//);
      expect(parsed.fields.detail).toBe('quoted'+separator+'detail');
    }
  });

  it('rewrites RFC5424 timestamp and supported CEF/LEEF body source fields without breaking extraction',()=>{
    for(const [mode,body] of [
      ['cef','CEF:0|Demo|FW|1|42|Denied|5|src_ip=10.1.1.1 username=bob url=https://hidden.example/path'],
      ['leef','LEEF:2.0|Demo|FW|1|55|^|src_ip=10.1.1.1^username=bob^url=https://hidden.example/path'],
    ] as const) {
      const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat=mode;
      const event='<34>1 2020-01-02T03:04:05Z fw app 1 ID - '+body;
      const generated=synthesizeReplayPreview(event,draft,now,entropy);
      expect(generated.log).toContain('2026-10-12T11:34:56.000Z');
      expect(generated.log).not.toContain('10.1.1.1');
      expect(generated.log).not.toContain('username=bob');
      expect(generated.log).not.toContain('https://hidden.example');
      expect(extractFields(generated.log,'syslog_rfc5424',draft).errors).toEqual([]);
    }
  });

  it('updates multiple separate JSON timestamp keys without global regular-expression state leaking',()=>{
    const draft=createDraft();draft.format='json';
    const event=JSON.stringify({
      time:'2020-01-02T03:04:05Z',timestamp:'2021-02-03T04:05:06Z',
      nested:{event_time:'2022-03-04T05:06:07Z'},
    });
    const output=JSON.parse(synthesizeReplayPreview(event,draft,now,entropy).log);
    expect(output.time).toBe(now.toISOString());
    expect(output.timestamp).toBe(now.toISOString());
    expect(output.nested.event_time).toBe(now.toISOString());
  });

  it('generates differing identities when the entropy source changes',()=>{
    const draft=createDraft();draft.format='json';
    const sample='{"user":"alice","src_ip":"10.0.0.1"}';
    expect(synthesizeReplayPreview(sample,draft,now,()=>0.1).log).not
      .toBe(synthesizeReplayPreview(sample,draft,now,()=>0.9).log);
  });

  it('fails closed for unsupported formats, malformed or oversized source and invalid entropy',()=>{
    const draft=createDraft();
    draft.format='regex';
    expect(()=>synthesizeReplayPreview('action=deny',draft,now,entropy)).toThrow();
    draft.format='json';
    expect(()=>synthesizeReplayPreview('notjson',draft,now,entropy)).toThrow();
    expect(()=>synthesizeReplayPreview('{"user":"bob"}\n{"user":"alice"}',draft,now,entropy)).toThrow();
    expect(()=>synthesizeReplayPreview('x'.repeat(4097),draft,now,entropy)).toThrow();
    expect(()=>synthesizeReplayPreview('{"user":"bob"}',draft,now,()=>-1)).toThrow();
  });
});
