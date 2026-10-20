import {describe,expect,it} from 'vitest';
import {inspectZeekReview} from './zeekReview';

const full='#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\n#types\ttime\tstring\taddr\taddr\tenum\n1760832000.000\tCw01\t192.0.2.10\t198.51.100.3\ttcp\n1760832001.000\tCw02\t192.0.2.11\t198.51.100.4\tudp\n#close\t2026-10-19T00:00:00';
describe('explicit browser-local Zeek schema recovery',()=>{
 it('prepares only data rows using reviewed ordered names with safe underscores',()=>{
  expect(inspectZeekReview(full)).toEqual({
   columns:'ts,uid,id_orig_h,id_resp_h,proto',
   dataRows:'1760832000.000\tCw01\t192.0.2.10\t198.51.100.3\ttcp\n1760832001.000\tCw02\t192.0.2.11\t198.51.100.4\tudp',
   metadataCount:5,recordCount:2,
  });
 });
 it('refuses duplicates, untrusted header, malformed rows, size and CRLF edits',()=>{
  for(const source of [
   full.replace('id.resp_h','id.orig_h'),
   full.replace('#path\tconn','#mystery\tbad'),
   full.replace('\tudp',''),
   full.replace('#close\t2026-10-19T00:00:00','#types\tbad'),
   full.replaceAll('\n','\r\n'),
   full+'x'.repeat(65536),
  ]) expect(inspectZeekReview(source)).toBeNull();
 });
});
