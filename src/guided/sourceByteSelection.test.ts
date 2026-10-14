import {describe,expect,it} from 'vitest';
import {toSourceByteRange} from './sourceByteSelection';

describe('UTF-8 source byte selection',()=>{
 it('preserves ASCII positions',()=>{
  expect(toSourceByteRange('src=192.0.2.1',4,13)).toEqual({startByte:4,endByte:13,text:'192.0.2.1'});
 });
 it('converts multibyte prefix offsets',()=>{
  const raw='\uD55C\uAE00\U0001F600\r\nsrc=192.0.2.1';
  const start=raw.indexOf('192.0.2.1');
  expect(toSourceByteRange(raw,start,start+9)).toEqual({
   startByte:new TextEncoder().encode(raw.slice(0,start)).byteLength,
   endByte:new TextEncoder().encode(raw.slice(0,start+9)).byteLength,text:'192.0.2.1'});
 });
 it('rejects surrogate-split and empty selections',()=>{
  expect(toSourceByteRange('A😀B',2,4)).toBeNull();
  expect(toSourceByteRange('A😀B',1,2)).toBeNull();
  expect(toSourceByteRange('A😀B',1,3)).toEqual({startByte:1,endByte:5,text:'😀'});
  expect(toSourceByteRange('x',0,0)).toBeNull();
 });
});
