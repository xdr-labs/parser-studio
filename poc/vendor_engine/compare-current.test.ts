/** Baseline: actual current browser Auto Parser implementation, no UI/DP calls.
 * Dataset fixtures are explicitly NOT checked in (upstream Elastic-licensed).
 * This test is opt-in when the verified local .cache contains the corpus.
 */
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {describe,it,expect} from 'vitest';
import {preview,detectFormat} from '../../src/parser';
import {createDraft} from '../../src/model';

const here=dirname(fileURLToPath(import.meta.url));
const cache=join(here,'.cache');
const cases=[
 'fortinet_traffic','fortinet_event','fortinet_utm',
 'palo_traffic','palo_threat','trellix_edr','trellix_epo','trend_vision',
] as const;
const available=cases.every(id=>existsSync(join(cache,id+'.raw')));
type Counter=Record<string,number>;
const increment=(dest:Counter,key:string)=>{
  dest[key]=(dest[key]??0)+1;
};

describe('Local-only vendor corpus baseline (requires separately acquired source data)',()=>{
  it.skipIf(!available)('runs the actual current Auto Parser preview without added source rules',()=>{
    const matrix:Record<string,unknown>[]=[];
    let expectedTotal=0,parsedTotal=0,fullyNormalized=0;
    for(const label of cases){
      const raw=readFileSync(join(cache,label+'.raw'),'utf8');
      const lines=raw.split(/\r?\n/).filter(x=>x.trim().length>0);
      const suite=preview(lines.join('\n'),createDraft());
      expect(suite.counts.total).toBe(lines.length);
      expect(suite.engine).toBe('browser-preview');
      expect(suite.nativeFluentdVerified).toBe(false);
      expect(suite.stellarExportVerified).toBe(false);
      const detected:Counter={},status:Counter={};
      for(const event of suite.events){
        increment(detected,detectFormat(event.raw).format);
        increment(status,event.status);
      }
      matrix.push({
        fixture:label,physical_rows:lines.length,
        parser_count:suite.counts,detected,status,
      });
      expectedTotal+=lines.length;
      parsedTotal+=suite.counts.extracted;
      fullyNormalized+=suite.counts.normalized;
    }
    expect(expectedTotal).toBe(256);
    writeFileSync(join(cache,'current_baseline.json'),JSON.stringify({
      contract:'parser-studio.poc.existing-browser-baseline.v0.1',
      note:'Unconfigured current createDraft + preview. No backend generation; NOT directly equivalent to new PoC gold-field scores.',
      records:expectedTotal,browser_extracted:parsedTotal,
      browser_normalized:fullyNormalized,
      native_verified:false,target_verified:false,
      fixtures:matrix,
    },null,2)+'\n','utf8');
    expect(matrix).toHaveLength(8);
  });
});
