import {describe,expect,it} from 'vitest';
import {tokenizeCSV,preview} from '../parser';
import {createDraft} from '../model';

const unicode=[
  ['NBSP',String.fromCharCode(0xa0)],
  ['EM SPACE',String.fromCharCode(0x2003)],
  ['NARROW NBSP',String.fromCharCode(0x202f)],
  ['BOM',String.fromCharCode(0xfeff)],
] as const;

describe('Issue #220: browser CSV must preserve non-ASCII edge whitespace like Ruby CSV',()=>{
  it.each(unicode)('keeps %s in unquoted comma/semicolon cells',(_label,space)=>{
    for(const delimiter of [',',';']){
      const fields=tokenizeCSV(['node',space+'deny','fw01'].join(delimiter),delimiter);
      expect(fields).toEqual(['node',space+'deny','fw01']);
      const quoted=tokenizeCSV(['node','"'+space+'deny"','fw01'].join(delimiter),delimiter);
      expect(quoted?.[1]).toBe(space+'deny');
    }
  });
  it('still trims ordinary ASCII edge space and TAB for comma CSV',()=>{
    expect(tokenizeCSV('node,  deny  ,fw01',',')).toEqual(['node','deny','fw01']);
    expect(tokenizeCSV('node,\tdeny\t,fw01',',')).toEqual(['node','deny','fw01']);
  });
  it('retains TAB-delimited values byte-for-byte',()=>{
    const space=String.fromCharCode(0xa0);
    expect(tokenizeCSV('node\t'+space+'deny\tfw01','\t'))
      .toEqual(['node',space+'deny','fw01']);
  });
  it('preserves Unicode whitespace in an official mapped text field',()=>{
    const space=String.fromCharCode(0xa0);
    const draft={...createDraft(),format:'csv' as const,csvColumns:'device,action,target',
      mappings:[{id:'action',source:'action',target:'action',type:'string' as const}],
      guided:{...createDraft().guided!,groups:{action:'top_fields' as const}}};
    const result=preview('node,'+space+'deny,fw01',draft).events[0]!;
    expect(result.fields.action).toBe(space+'deny');
    expect(result.normalized.action).toBe(space+'deny');
    expect(result.normalizedOk).toBe(true);
  });
});