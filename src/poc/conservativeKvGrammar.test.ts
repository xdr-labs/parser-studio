import {describe,expect,it} from 'vitest';
import {conservativeKvBody,conservativeKvFields} from './conservativeKvGrammar';

const sample=(body:string)=>'<14>'+body;
describe('bounded conservative KV escaped-value PoC',()=>{
  it('preserves unknown escaped punctuation inside double quotes',()=>{
    const raw=sample(String.raw`date=2026-10-17 msg="hello\?world" type=event`);
    expect(conservativeKvFields(raw)?.fields.msg).toBe(String.raw`hello\?world`);
  });
  it('preserves unknown escaped letters inside double quotes',()=>{
    const raw=sample(String.raw`a="line\nstill-literal" b=2`);
    expect(conservativeKvFields(raw)?.fields.a).toBe(String.raw`line\nstill-literal`);
  });
  it('decodes known escaped double quote and backslash only',()=>{
    const raw=sample(String.raw`a="say \"hello\"" b="slash \\ done"`);
    const fields=conservativeKvFields(raw)?.fields;
    expect(fields?.a).toBe('say "hello"');
    expect(fields?.b).toBe(String.raw`slash \ done`);
  });
  it('supports safe quoted spaces, literal single-quotes and empty values',()=>{
    const fields=conservativeKvFields(sample(`a='one two' b="" c=third d=`))?.fields;
    expect(fields).toMatchObject({a:'one two',b:'',c:'third',d:''});
  });
  it('supports bounded unquoted backslash-escaped spaces',()=>{
    const fields=conservativeKvFields(sample(String.raw`a=some\ value b=ordinary`))?.fields;
    expect(fields?.a).toBe('some value');
  });
  it('recognizes only safe PRI and yearless source envelopes without invented timestamps',()=>{
    expect(conservativeKvFields(sample('a=1 b=2'))?.envelope).toBe('pri_kv');
    expect(conservativeKvFields('Oct  7 23:58:59 edge.example a=1 b=2')?.envelope)
      .toBe('yearless_rfc3164_kv');
    expect(conservativeKvFields('a=1 b=2')?.envelope).toBe('bare_kv');
    expect(conservativeKvBody('<192>a=1 b=2')).toBeNull();
    expect(conservativeKvBody('Oct 7 24:00:00 edge a=1 b=2')).toBeNull();
  });
  it('rejects unsupported mixed PRI+yearless and free prose',()=>{
    expect(conservativeKvFields('<14>Oct 17 12:34:56 edge a=1 b=2')).toBeNull();
    expect(conservativeKvFields('Built TCP connection to source host')).toBeNull();
  });
  it('refuses fused quotation segments and missing separators',()=>{
    expect(conservativeKvFields(sample('a="one"two b=2'))).toBeNull();
    expect(conservativeKvFields(sample('a=one"two" b=2'))).toBeNull();
    expect(conservativeKvFields(sample('a="one"b=two'))).toBeNull();
  });
  it('rejects unclosed quotes and ambiguous single-quoted escapes',()=>{
    expect(conservativeKvFields(sample('a="unclosed b=2'))).toBeNull();
    expect(conservativeKvFields(sample(String.raw`a='literal\?unsafe' b=2`))).toBeNull();
  });
  it('rejects unsafe keys, duplicate names and hyphen-underscore collisions',()=>{
    expect(conservativeKvFields(sample('a=1 __proto__=2'))).toBeNull();
    expect(conservativeKvFields(sample('a=1 a=2'))).toBeNull();
    expect(conservativeKvFields(sample('a-b=1 a_b=2'))).toBeNull();
  });
  it('rejects unkeyed fragments and multiline/null text',()=>{
    expect(conservativeKvFields(sample('a=1 stray b=2'))).toBeNull();
    expect(conservativeKvFields(sample('a=1 b=2\nc=3'))).toBeNull();
    expect(conservativeKvFields(sample('a=1 b=2\0'))).toBeNull();
    expect(conservativeKvFields(sample('a="quoted\fcontrol" b=2'))).toBeNull();
    expect(conservativeKvFields(sample('a=1 b=2\vfragment'))).toBeNull();
  });
  it('bounds event size and field count',()=>{
    expect(conservativeKvFields(sample('a='+'x'.repeat(20000)+' b=2'))).toBeNull();
    const body=Array.from({length:258},(_,i)=>'f_'+i+'=x').join(' ');
    expect(conservativeKvFields(sample(body))).toBeNull();
    expect(conservativeKvFields(sample('a=one'))).toBeNull();
  });
});
