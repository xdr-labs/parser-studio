import {describe,expect,it} from 'vitest';
import {createDraft} from './model';
import {convertValue,extractFields,preview} from './parser';
import {extractStructuredFamily} from './structuredFamilies';
import {hasUnsafeJsonNumbers} from './jsonNumberSafety';
import {analyzeLogEnvelopes} from './guided/autoParserEnvelope';

const slash='\\';
const path='C:'+slash+'Windows'+slash+'System32'+slash+'cmd.exe';
const body='path="'+path+'" action=deny';

describe('2026-11-03 reviewed original-source losslessness contracts',()=>{
  it.each([
    ['ordinary standalone KV',body,'kv'],
    ['RFC5424 wrapped KV','<14>1 2026-11-03T11:11:11Z fw app - ID - '+body,'syslog_rfc5424'],
    ['RFC3164 wrapped KV','<134>May 5 17:51:17 edge01 app: '+body,'syslog_rfc3164'],
  ] as const)('%s keeps original Windows path separators',(_label,raw,format)=>{
    const draft=createDraft();
    draft.format=format;
    if(format!=='kv')draft.syslogBodyFormat='kv';
    const extracted=extractFields(raw,format,draft);
    expect(extracted.errors).toEqual([]);
    expect(format==='kv'?extracted.fields.path:
      (extracted.fields.body as Record<string,unknown>).path).toBe(path);
  });
  it('decodes only defined escape sequences without stripping unknown escapes',()=>{
    const draft=createDraft();
    draft.format='kv';
    const raw='note="a'+slash+'=b" quote=\'we'+slash+'\'re okay\' path="'+path+'"';
    const extracted=extractFields(raw,'kv',draft);
    expect(extracted.errors).toEqual([]);
    expect(extracted.fields).toMatchObject({note:'a=b',quote:"we're okay",path});
    const doubled='path="C:'+slash+slash+'Windows'+slash+slash+'cmd.exe"';
    expect(extractFields(doubled,'kv',draft).fields.path).toBe('C:'+slash+'Windows'+slash+'cmd.exe');
  });
  it('never accepts an unmatched KV suffix or middle fragment as fully parsed',()=>{
    const draft=createDraft();draft.format='kv';
    for(const raw of [
      'src_ip=192.0.2.10 INVALID_FRAGMENT action=deny',
      'src_ip=192.0.2.10 action=deny INVALID',
    ]){
      expect(extractFields(raw,'kv',draft).errors.length).toBeGreaterThan(0);
      expect(preview(raw,draft).counts.failures).toBe(1);
      expect(analyzeLogEnvelopes(raw,'single-line').events[0]?.status).toBe('BODY_MALFORMED');
    }
  });
  it.each(['__proto__','prototype','constructor'])('rejects unsafe source field %s in KV and LEEF',key=>{
    const draft=createDraft();draft.format='kv';
    const kv='action=deny '+key+'=hidden src_ip=192.0.2.10';
    expect(extractFields(kv,'kv',draft).errors.length).toBeGreaterThan(0);
    expect(analyzeLogEnvelopes(kv,'single-line').events[0]?.status).toBe('BODY_MALFORMED');
    const leef='LEEF:2.0|Vendor|Product|1.0|ID101|^|src=192.0.2.10^'+key+'=hidden^action=deny';
    expect(extractFields(leef,'leef',draft).errors.length).toBeGreaterThan(0);
  });
  it('keeps regular CEF and LEEF event family extraction intact',()=>{
    expect(extractStructuredFamily('CEF:0|Vendor|Product|1.0|ID|Blocked|5|src=192.0.2.10 msg=File blocked act=deny','cef').fields)
      .toMatchObject({src:'192.0.2.10',msg:'File blocked',act:'deny'});
    expect(extractStructuredFamily('LEEF:2.0|Vendor|Product|1.0|ID|^|src=192.0.2.10^action=deny','leef').fields)
      .toMatchObject({src:'192.0.2.10',action:'deny'});
  });
  it.each([
    '{"session_id":9007199254740993}',
    '{"session_id":-9007199254740993}',
    '{"nested":{"session_id":9007199254740993}}',
    '{"items":[{"session_id":9007199254740993}]}',
    '{"session_id":9.007199254740993e15}',
    '{"fraction":0.1234567890123456789}',
    '{"fraction":1e309}',
  ])('fails closed on unsafe numeric JSON source: %s',raw=>{
    const draft=createDraft();draft.format='json';
    expect(hasUnsafeJsonNumbers(raw)).toBe(true);
    expect(extractFields(raw,'json',draft).errors.join(' ')).toMatch(/precision/);
    expect(preview(raw,draft).counts.failures).toBe(1);
    expect(analyzeLogEnvelopes(raw,'single-line').events[0]?.status).toBe('BODY_MALFORMED');
  });
  it('does not confuse escaped JSON string contents with number tokens',()=>{
    const draft=createDraft();draft.format='json';
    const raw='{"session_id":"9007199254740993","message":"quote \\" 9007199254740993"}';
    expect(hasUnsafeJsonNumbers(raw)).toBe(false);
    expect(extractFields(raw,'json',draft).fields.session_id).toBe('9007199254740993');
  });
  it('also rejects unsafe JSON numbers inside RFC5424 wrapped JSON body',()=>{
    const draft=createDraft();draft.format='syslog_rfc5424';draft.syslogBodyFormat='json';
    const raw='<14>1 2026-11-03T11:11:11Z fw app - ID - {"session_id":9007199254740993}';
    expect(extractFields(raw,'syslog_rfc5424',draft).errors.join(' ')).toMatch(/precision/);
  });
  it('preserves preview/native scalar coercion policy for whitespace, sign and IPv6 text',()=>{
    expect(convertValue(' 443 ','port')).toMatchObject({value:443});
    expect(convertValue(' +443 ','port').error).toBeDefined();
    expect(convertValue(' 192.0.2.10 ','ip')).toMatchObject({value:'192.0.2.10'});
    expect(convertValue(' 42 ','integer')).toMatchObject({value:42});
    expect(convertValue(' true ','boolean')).toMatchObject({value:true});
    expect(convertValue(' 2026-11-03T11:11:11Z ','timestamp')).toMatchObject({value:'2026-11-03T11:11:11.000Z'});
    expect(convertValue('2001:0db8::0001','ip')).toMatchObject({value:'2001:0db8::0001'});
  });
});
