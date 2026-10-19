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
function renderProblem(raw:string,code:string){
 render(<BeginnerAnalysisPanel source={raw}
  events={[{startByte:0,endByte:new TextEncoder().encode(raw).byteLength,preview:preview(raw,code)}]}
  onOpenAssisted={vi.fn()}/>);
}
describe('novice recovery is format-specific and never claims unsupported native parsing',()=>{
 it('explains Zeek header metadata and tells a beginner where to enter fields',()=>{
  renderProblem('#fields\tts\tuid\tid.orig_h','NO_SUPPORTED_GRAMMAR');
  expect(screen.getByText(/Zeek column\/header metadata/)).toBeInTheDocument();
  expect(screen.getByText(/Separate Zeek header lines from data events/)).toBeInTheDocument();
  expect(screen.getByText(/paste the data rows separately, choose TAB/)).toBeInTheDocument();
  expect(screen.getByText(/not an event/)).toBeInTheDocument();
 });
 it('describes XML as unsupported and offers JSON recovery, not a fictional parser',()=>{
  renderProblem('<Event><System><EventID>4625</EventID></System></Event>','NO_SUPPORTED_GRAMMAR');
  expect(screen.getByText(/unsupported Windows Event XML/)).toBeInTheDocument();
  expect(screen.getByText(/Export Windows Event logs as JSON/)).toBeInTheDocument();
  expect(screen.getByText(/not a qualified input format/)).toBeInTheDocument();
 });
 it('explains quoted multiline CSV boundaries and native limitations',()=>{
  renderProblem('1,deny,"first\nsecond"','FRAMING_MULTILINE_CSV_REVIEW');
  expect(screen.getByLabelText('Multiline CSV recovery')).toBeInTheDocument();
  expect(screen.getByText(/Review the CSV record boundary and closing quotes/)).toBeInTheDocument();
  expect(screen.getByText(/kept the complete logical source record/)).toBeInTheDocument();
  expect(screen.getByText(/0 of 1 log event parsed completely/)).toBeInTheDocument();
 });
});


describe('source completeness does not mean downloadable parser readiness',()=>{
 const cases=[
  {name:'free-form RFC5424 MSG',raw:'<134>1 2026-10-19T09:15:22Z fw01 app - evt - 사용자 접근 차단',
   syntax:'SYSLOG_RFC5424+RFC5424_MSG',fields:{syslog:{hostname:'fw01'},body:{message:'사용자 접근 차단'}}},
  {name:'fully extracted LEEF fields',raw:'LEEF:2.0|Acme|NSS|1.0|alert|src=192.0.2.1',
   syntax:'LEEF_2_IMPLICIT_TAB',fields:{leef_extension:{src:'192.0.2.1'}}},
 ];
 for(const item of cases){
  it('explains '+item.name+' without asking to recover nonmissing source text',()=>{
   const bytes=new TextEncoder().encode(item.raw).byteLength;
   const event:MultiPassSourcePreview={
    contract:'parser-studio.multipass-source-preview.v0.1',
    status:'SOURCE_PARSED',syntax:item.syntax,sourceSha256:'0'.repeat(64),
    sourceBytes:bytes,fields:item.fields,spans:[],residuals:[],issues:[],
    nativeVerified:false,targetVerified:false,
   };
   render(<BeginnerAnalysisPanel source={item.raw}
     events={[{startByte:0,endByte:bytes,preview:event}]}
     parserRuleReviewRequired onOpenAssisted={vi.fn()}/>);
   expect(screen.getByText('Fields extracted — parser rule needs review')).toBeInTheDocument();
   expect(screen.getByText(/All original values were extracted/)).toBeInTheDocument();
   expect(screen.getByText(/Review parser-file support for these fields/)).toBeInTheDocument();
   expect(screen.getByText(/does not verify native or Stellar Cyber parser compatibility/)).toBeInTheDocument();
   expect(screen.queryByText(/remaining message text/i)).not.toBeInTheDocument();
   expect(screen.getByText(item.raw)).toBeInTheDocument();
  });
 }
});
