import {describe,expect,it,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import BeginnerAnalysisPanel from './BeginnerAnalysisPanel';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

function preview(raw:string,code:string):MultiPassSourcePreview{
 const bytes=new TextEncoder().encode(raw).byteLength;
 return {
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'RAW_ONLY',syntax:'UNKNOWN',
  sourceSha256:'0'.repeat(64),sourceBytes:bytes,fields:{},spans:[],
  residuals:[{startByte:0,endByte:bytes}],issues:[code],
  nativeVerified:false,targetVerified:false,
 };
}
function renderProblem(raw:string,code:string,override:Partial<MultiPassSourcePreview>={}){
 render(<BeginnerAnalysisPanel source={raw}
  events={[{startByte:0,endByte:new TextEncoder().encode(raw).byteLength,preview:{...preview(raw,code),...override}}]}
  onOpenAssisted={vi.fn()}/>);
}

describe('reason wording for a beginner',()=>{
 const raw='<166>Aug 20 2026 08:53:11 asa-vpn-01 : %ASA-6-751025: Local:203.0.113.10:4500 assigned to session';
 it('explains a Syslog body that still needs a rule without internal code words',()=>{
  renderProblem(raw,'UNSUPPORTED_PRI_BODY');
  expect(screen.getByText(/priority header was recognized, but the message text after it still needs an extraction rule/)).toBeInTheDocument();
  expect(screen.queryByText(/unsupported pri body/)).toBeNull();
 });
 it('explains an unknown reason code as a missing pattern and keeps the code for support',()=>{
  renderProblem(raw,'SOME_FUTURE_REASON');
  expect(screen.getByText(/does not match a built-in pattern yet, so it needs an extra parsing rule \(some future reason\)/)).toBeInTheDocument();
 });
 // Owner policy D-1 (2026-11-14): the reviewer is told which field is repeated and why no parser is created.
 it('names a repeated key=value field and says that no value is overwritten',()=>{
  renderProblem('srcip=192.0.2.10 dstip=198.51.100.7 srcip=203.0.113.5 action=deny','DUPLICATE_SOURCE_FIELD',
   {status:'PARTIAL',syntax:'KV',fields:{srcip:['192.0.2.10','203.0.113.5'],dstip:'198.51.100.7',action:'deny'}});
  expect(screen.getByText(/The same field name appears more than once in this event \(srcip\)\. Every value is kept in its original order and none is overwritten, but parser files are not created automatically while a field is repeated\./)).toBeInTheDocument();
 });
 it('names a repeated LEEF 2.0 attribute from the preview when the separator is not white space',()=>{
  renderProblem('LEEF:2.0|Acme|FW|1.0|100|^|usrName=alice^src=10.0.0.1^usrName=bob','DUPLICATE_SOURCE_FIELD',
   {status:'PARTIAL',syntax:'LEEF',fields:{leef_header:{version:'2.0'},leef_extension:{usrName:['alice','bob'],src:'10.0.0.1'}}});
  expect(screen.getByText(/appears more than once in this event \(usrName\)/)).toBeInTheDocument();
 });
 it('does not read a JSON array as a repeated field',()=>{
  renderProblem('{"tags":["a","b"],"id":1,"id":2}','DUPLICATE_SOURCE_FIELD',{status:'PARTIAL',syntax:'JSON',fields:{tags:['a','b'],id:1}});
  expect(screen.getByText(/The same field name appears more than once in this event\. Every value is kept/)).toBeInTheDocument();
 });
});
