import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {SOURCE_NAME_PREFIX,originalFieldName,sourceFieldName,withSourceFieldNames} from './sourceFieldNames';

// G-5: field names the JavaScript object model reserves are kept, not refused, under a reversible name. The Python
// Multi-Pass readers apply the same rule (tests/test_source_field_names_20261125.py) and the generated Ruby runs this
// grammar (translated). SYNTHETIC lines.
const RESERVED=['__proto__','constructor','prototype'];
function draft(format:ParserDraft['format']):ParserDraft{
  return {...createDraft(),format,mappings:[],preserveUnmapped:true} as ParserDraft;
}
function scalarEntries(value:unknown,path:string[]=[],out:[string,string][]=[]):[string,string][]{
  if(value!==null&&typeof value==='object'&&!Array.isArray(value))
    for(const key of Object.keys(value))scalarEntries((value as Record<string,unknown>)[key],[...path,key],out);
  else out.push([path.join('/'),String(value)]);
  return out;
}

describe('the reversible name',()=>{
  it('keeps reserved and prefixed names apart from every other name and gives the source name back',()=>{
    const names=[...RESERVED,'toString','valueOf','hasOwnProperty','src','a.b','',SOURCE_NAME_PREFIX,
      SOURCE_NAME_PREFIX+'__proto__',SOURCE_NAME_PREFIX+SOURCE_NAME_PREFIX+'x','parserstudio_ke','parserstudio_key'];
    const encoded=names.map(sourceFieldName);
    expect(new Set(encoded).size).toBe(names.length);
    expect(encoded.map(originalFieldName)).toEqual(names);
    for(const name of encoded)expect(RESERVED).not.toContain(name);
    expect(names.filter(name=>sourceFieldName(name)!==name)).toEqual([...RESERVED,SOURCE_NAME_PREFIX,
      SOURCE_NAME_PREFIX+'__proto__',SOURCE_NAME_PREFIX+SOURCE_NAME_PREFIX+'x']);
  });
  it('renames JSON member names at every depth without touching other values',()=>{
    const value=JSON.parse('{"a":[{"__proto__":{"constructor":"c"}}],"b":"__proto__"}');
    expect(JSON.stringify(withSourceFieldNames(value))).toBe(
      '{"a":[{"parserstudio_key___proto__":{"parserstudio_key_constructor":"c"}}],"b":"__proto__"}');
    const plain={x:{y:1}};
    expect(withSourceFieldNames(plain)).toBe(plain);
  });
});

describe('reserved source names are parsed and kept, without touching any prototype',()=>{
  it.each([
    ['key=value','kv','src_ip=10.0.0.1 __proto__=p1 constructor=c1 prototype=r1 parserstudio_key___proto__=x1'],
    ['CEF','cef','CEF:0|A|B|1|2|n|3|src=10.0.0.1 __proto__=p1 constructor=c1 prototype=r1 parserstudio_key___proto__=x1'],
    ['LEEF','leef','LEEF:1.0|A|B|1|2|src=10.0.0.1\t__proto__=p1\tconstructor=c1\tprototype=r1\tparserstudio_key___proto__=x1'],
    ['JSON','json','{"src_ip":"10.0.0.1","__proto__":"p1","constructor":"c1","prototype":"r1","parserstudio_key___proto__":"x1"}'],
  ])('%s: FULL, every value under a distinct field name that maps back to the source name',(_,format,raw)=>{
    const event=preview(raw,draft(format as ParserDraft['format'])).events[0]!;
    expect(event.parseStatus).toBe('FULL');
    expect(event.diagnostics.filter(item=>item.severity==='error')).toEqual([]);
    const fields=event.fields as Record<string,unknown>;
    for(const [name,value] of [['__proto__','p1'],['constructor','c1'],['prototype','r1'],[SOURCE_NAME_PREFIX+'__proto__','x1']]){
      expect(Object.prototype.hasOwnProperty.call(fields,sourceFieldName(name!)),name).toBe(true);
      expect(fields[sourceFieldName(name!)]).toBe(value);
    }
    for(const name of RESERVED)expect(Object.prototype.hasOwnProperty.call(fields,name)).toBe(false);
    // The final output keeps every value once, each under a name that gives the source name back.
    const kept=scalarEntries(event.normalized).filter(([,value])=>['p1','c1','r1','x1'].includes(value));
    expect(kept.map(([,value])=>value).sort()).toEqual(['c1','p1','r1','x1']);
    const back=Object.fromEntries(kept.map(([path,value])=>[originalFieldName(path.split('/').at(-1)!),value]));
    // An object literal would treat __proto__ as the prototype; JSON.parse makes it an own field.
    expect(back).toEqual(JSON.parse('{"__proto__":"p1","constructor":"c1","prototype":"r1","'+SOURCE_NAME_PREFIX+'__proto__":"x1"}'));
    expect(({} as Record<string,unknown>).p1).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype,'c1')).toBe(false);
    expect(Object.getPrototypeOf(fields)===null||Object.getPrototypeOf(fields)===Object.prototype).toBe(true);
  });
  it('a duplicate stays a duplicate under the reversible name',()=>{
    expect(preview('a=1 __proto__=p1 __proto__=p2',draft('kv')).events[0]!.parseStatus).not.toBe('FULL');
    expect(preview('{"__proto__":"p1","__proto__":"p2"}',draft('json')).events[0]!.parseStatus).not.toBe('FULL');
  });
});

describe('dotted source names',()=>{
  it('a literal dotted key and a nested path of the same spelling stay two different output fields',()=>{
    const event=preview('{"src_ip":"10.0.0.1","a.b":"d1","a":{"b":"n1"}}',draft('json')).events[0]!;
    expect(event.parseStatus).toBe('FULL');
    const kept=scalarEntries(event.normalized).filter(([,value])=>value==='d1'||value==='n1');
    expect(kept.length).toBe(2);
    expect(new Set(kept.map(([path])=>path)).size).toBe(2);
    expect(kept.find(([,value])=>value==='d1')![0]).toMatch(/parserstudio_unmapped\/a\.b$/);
    expect(kept.find(([,value])=>value==='n1')![0]).toMatch(/\/a\/b$/);
  });
});
