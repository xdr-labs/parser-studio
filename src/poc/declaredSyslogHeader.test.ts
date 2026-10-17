import {describe,expect,it} from 'vitest';
import {inspectDeclaredSourceHeader,type DeclaredSourceHeaderProfile} from './declaredSyslogHeader';

const profile:DeclaredSourceHeaderProfile={
  framing:'INDEPENDENTLY_DECLARED_RFC3164_ORDERED_BODY_HEADER',
  fields:[
    {name:'cat_name',syntax:'opaque_token'},
    {name:'msg_id',syntax:'unsigned_integer',minimum:1,maximum:4294967295},
    {name:'total_seg',syntax:'unsigned_integer',minimum:1,maximum:1000},
    {name:'seg_num',syntax:'unsigned_integer',minimum:0,maximum:1000},
  ],
};
const input='<181>Mar 2 09:09:13 relay-host CISE_Test 0000075134 1 0 2022-03-02 09:09:13.790 +00:00 message=é';

describe('generic bounded publisher-declared ordered syslog body source header',()=>{
  it('extracts declared labels without embedding manufacturer names in grammar',()=>{
    const out=inspectDeclaredSourceHeader(input,profile);
    expect(out.disposition).toBe('REVIEW_ONLY');
    const named=new Map(out.fields.map(f=>[f.name,f]));
    expect(named.get('cat_name')?.value).toBe('CISE_Test');
    expect(named.get('msg_id')?.value).toBe('0000075134');
    expect(named.get('total_seg')?.value).toBe('1');
    expect(named.get('seg_num')?.value).toBe('0');
    expect(named.get('hostname')?.value).toBe('relay-host');
    expect(named.get('message')?.value).toBe('2022-03-02 09:09:13.790 +00:00 message=é');
    expect(named.has('appname')).toBe(false);
    expect(out.autoPromoted).toBe(false);
    expect(out.manufacturerSemantics).toBe('NOT_CERTIFIED');
    expect(out.nativeParser).toBe('NOT_VERIFIED');
    expect(out.originalRaw).toBe(input);
  });
  it('enforces exact UTF-8 source intervals, including Unicode residual',()=>{
    const out=inspectDeclaredSourceHeader(input,profile);
    const raw=new TextEncoder().encode(input);
    expect(out.sourceBytes).toBe(raw.length);
    for(const field of out.fields)
      expect(new TextDecoder('utf8',{fatal:true}).decode(
        raw.slice(field.startByte,field.endByte))).toBe(field.value);
    expect(out.branchAttempts).toBeLessThanOrEqual(3);
    expect(out.maxDepth).toBe(1);
  });
  it('returns RAW_ONLY for unknown producer instead of lexical auto-promotion',()=>{
    const out=inspectDeclaredSourceHeader(input);
    expect(out.disposition).toBe('RAW_ONLY');
    expect(out.fields).toEqual([]);
    expect(out.nativeParser).toBe('NOT_VERIFIED');
  });
  it('uses a different externally defined token schema without vendor-specific parser changes',()=>{
    const arbitrary:DeclaredSourceHeaderProfile={
      framing:profile.framing,fields:[
        {name:'eventclass',syntax:'opaque_token'},
        {name:'recordid',syntax:'unsigned_integer',minimum:0,maximum:9999},
      ],
    };
    const source='<190>May 1 12:10:09 relay-node Alert_Type 00042 payload=ok';
    const out=inspectDeclaredSourceHeader(source,arbitrary);
    expect(out.fields.find(f=>f.name==='eventclass')?.value).toBe('Alert_Type');
    expect(out.fields.find(f=>f.name==='recordid')?.value).toBe('00042');
    expect(out.disposition).toBe('REVIEW_ONLY');
  });
  it('abstains rather than guesses on malformed or unsafe received envelopes',()=>{
    for(const invalid of [
      input.replace('0000075134','not-an-id'),
      input.replace('0000075134','999999999999999999'),
      input.replace(' 1 0 2022',' 0 0 2022'),
      input.replace(' 1 0 2022',' 1 9999 2022'),
      input.replace(' 1 0 2022',' 1 0'),
      input.replace('CISE_Test 000','CISE_Test    000'),
      input.replace('CISE_Test','CISE_Test=suspicious'),
      input.replace('09:09:13','29:09:13'),
      input+'\n<181>Mar 2 09:09:14 next-host bad',
      input+'x'.repeat(9000),
      '<34>1 2026-01-01T02:03:04Z host app - - - event',
      '<181>Mar 2 09:09:13 relay-host app[123]: msg=hello',
    ]){
      const out=inspectDeclaredSourceHeader(invalid,profile);
      expect(out.disposition,'unexpected REVIEW_ONLY for control category').not.toBe('REVIEW_ONLY');
      expect(out.fields).toEqual([]);
    }
  });
  it('rejects invalid schema definition without checking any content',()=>{
    const malicious=[
      {framing:profile.framing,fields:[{name:'__proto__',syntax:'opaque_token'}]},
      {framing:profile.framing,fields:[{name:'message',syntax:'opaque_token'}]},
      {framing:profile.framing,fields:[{name:'foo',syntax:'opaque_token'},{name:'foo',syntax:'opaque_token'}]},
      {framing:profile.framing,fields:Array.from({length:12},(_,i)=>({name:'x'+i,syntax:'opaque_token'}))},
      {framing:profile.framing,fields:[{name:'n',syntax:'unsigned_integer',minimum:-1}]},
    ] as DeclaredSourceHeaderProfile[];
    for(const def of malicious){
      const out=inspectDeclaredSourceHeader(input,def);
      expect(out.disposition).toBe('ABSTAIN_UNSAFE');
      expect(out.fields).toEqual([]);
    }
  });
});
