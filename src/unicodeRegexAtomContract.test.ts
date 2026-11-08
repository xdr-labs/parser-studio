import {describe,it,expect} from 'vitest';
import {parsePortableRegexAst} from '../backend/src/portable-regex';

describe('Unicode scalar regex atom contract',()=>{
 it('binds a bounded quantifier to the complete supplementary character',()=>{
  const result=parsePortableRegexAst('^(?<message>🙂{2,3})$');
  expect(result.ok).toBe(true);
  if(!result.ok)return;
  expect(result.ast).toEqual({kind:'sequence',nodes:[
   {kind:'anchor',text:'^'},
   {kind:'group',captureName:'message',body:{kind:'sequence',nodes:[
    {kind:'repeat',min:2,max:3,lazy:false,atom:{kind:'literal',text:'🙂'}},
   ]}},
   {kind:'anchor',text:'$'},
  ]});
 });
 it('rejects an unpaired surrogate at the AST boundary',()=>{
  expect(parsePortableRegexAst('(?<message>'+String.fromCharCode(0xd800)+')'))
   .toMatchObject({ok:false});
 });
});
