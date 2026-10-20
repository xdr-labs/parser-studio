import {describe,it,expect} from 'vitest';
import fixture from '../tests/fixtures/roadmap-leef2-implicit-tab-20261020.json';
import {extractLeef2ImplicitTab} from './leef2ImplicitTab';

describe('explicit standalone implicit-TAB LEEF 2.0 profile',()=>{
  for(const sample of fixture.positive){
    it('preserves exact header, fields and original source for '+sample.name,()=>{
      expect(extractLeef2ImplicitTab(sample.raw)).toEqual({
        leef_header:sample.header,leef_extension:sample.extension,
        generic:{mode:'leef2_implicit_tab',source_raw:sample.raw},
      });
    });
  }
  for(const sample of fixture.negative){
    it('rejects '+sample.name,()=>{
      expect(extractLeef2ImplicitTab(sample.raw)).toBeNull();
    });
  }
  it('refuses an unpaired surrogate instead of inventing a UTF-8 replacement value',()=>{
    expect(extractLeef2ImplicitTab('LEEF:2.0|Acme|Agent|1|event|first=one\tsecond=\ud800')).toBeNull();
  });
});
