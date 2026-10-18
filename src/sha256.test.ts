import {afterEach,describe,expect,it,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {sha256Utf8Hex} from './sha256';

describe('browser SHA-256 fallback',()=>{
 afterEach(()=>vi.unstubAllGlobals());
 it('matches standard SHA-256 without Web Crypto for ASCII and UTF-8 input',async()=>{
  vi.stubGlobal('crypto',{});
  for(const value of ['','abc','Parser Studio','user=José srcip=192.0.2.10']){
   expect(await sha256Utf8Hex(value)).toBe(createHash('sha256').update(value).digest('hex'));
  }
 });
});
