import {describe,expect,it} from 'vitest';
import {conservativeKvLocatedFields} from './conservativeKvUtf8Span';

const bytes=(text:string)=>new TextEncoder().encode(text);
const slice=(input:string,a:number,b:number)=>
  new TextDecoder('utf-8',{fatal:true}).decode(bytes(input).slice(a,b));

describe('isolated UTF-8 source KV byte-span observer',()=>{
  it('preserves global offsets after PRI and non-ASCII multi-byte values',()=>{
    const raw='<14>name="price € 😀" last=done';
    const located=conservativeKvLocatedFields(raw);
    expect(located?.envelope).toBe('pri_kv');
    expect(located?.spans).toHaveLength(2);
    const first=located!.spans[0]!;
    expect(first.rawStart).toBe(4);
    expect(first.rawEnd).toBe(bytes('<14>name="price € 😀"').length);
    expect(slice(raw,first.valueStart,first.valueEnd)).toBe('"price € 😀"');
    expect(located?.spans[1]?.rawStart).toBe(bytes('<14>name="price € 😀" ').length);
    expect(located?.fields.name).toBe('price € 😀');
  });
  it('includes yearless RFC3164 in the original full-event byte coordinates',()=>{
    const raw='Oct  7 23:58:59 edge.example one=1 message="two words"';
    const located=conservativeKvLocatedFields(raw);
    expect(located?.envelope).toBe('yearless_rfc3164_kv');
    expect(slice(raw,located!.spans[0]!.rawStart,located!.spans[0]!.rawEnd))
      .toBe('one=1');
    expect(slice(raw,located!.spans[1]!.rawStart,located!.spans[1]!.rawEnd))
      .toBe('message="two words"');
  });
  it('reports exact source slices with known and unknown double quote escapes',()=>{
    const raw=String.raw`alpha="say \"hi\" and \? literal" beta="C:\\Temp"`;
    const located=conservativeKvLocatedFields(raw)!;
    expect(located.fields.alpha).toBe(String.raw`say "hi" and \? literal`);
    expect(located.fields.beta).toBe(String.raw`C:\Temp`);
    expect(slice(raw,located.spans[0]!.valueStart,located.spans[0]!.valueEnd))
      .toBe(String.raw`"say \"hi\" and \? literal"`);
  });
  it('preserves byte coordinates for escaped spaces in bare tokens',()=>{
    const raw=String.raw`alpha=some\ value beta=two`;
    const located=conservativeKvLocatedFields(raw)!;
    expect(located.fields.alpha).toBe('some value');
    expect(slice(raw,located.spans[0]!.rawStart,located.spans[0]!.rawEnd))
      .toBe(String.raw`alpha=some\ value`);
  });
  it('refuses unpaired surrogates (UTF-8 replacement would erase identity)',()=>{
    expect(conservativeKvLocatedFields('a=1 b=\uD800')).toBeNull();
    expect(conservativeKvLocatedFields('a=1 b=\uDC00')).toBeNull();
  });
  it('retains a strict refusal for malformed, repeated, unsupported formats',()=>{
    for(const raw of [
      'a=1 a=2','a-b=1 a_b=2','a="broken b=2',
      '<14>Oct 17 12:34:56 host a=1 b=2',
      'a=1 b="split"tail',
      'a=1 b=two\n','a=1 __proto__=2',
    ])expect(conservativeKvLocatedFields(raw)).toBeNull();
  });
});
