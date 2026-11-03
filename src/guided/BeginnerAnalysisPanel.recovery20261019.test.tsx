import {describe,expect,it,vi} from 'vitest';
import {render,screen,within} from '@testing-library/react';
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
  expect(screen.getByText(/0 of 1 log event structurally parsed/)).toBeInTheDocument();
 });
});


describe('source completeness does not mean downloadable parser readiness',()=>{
 const cases=[
  {name:'free-form RFC5424 MSG',raw:'<134>1 2026-10-19T09:15:22Z fw01 app - evt - 사용자 접근 차단',
   syntax:'SYSLOG_RFC5424+RFC5424_MSG',fields:{syslog:{hostname:'fw01'},body:{message:'사용자 접근 차단'}}},
  {name:'fully extracted LEEF fields',raw:'LEEF:2.0|Acme|NSS|1.0|alert|0x09|src=192.0.2.1',
   syntax:'LEEF',fields:{leef_extension:{src:'192.0.2.1'}}},
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
   expect(screen.getByText(/Parser Studio read every value/)).toBeInTheDocument();
   expect(screen.getByText(/Review parser-file support for these fields/)).toBeInTheDocument();
   expect(screen.getByText(/does not verify native or Stellar Cyber parser compatibility/)).toBeInTheDocument();
   expect(screen.queryByText(/remaining message text/i)).not.toBeInTheDocument();
   expect(screen.getByText(item.raw)).toBeInTheDocument();
  });
 }
});

describe('LEEF source interpretation and explicit input preparation',()=>{
 it('explains an unreadable header without claiming that the event is understood',()=>{
  const raw='LEEF:2.0|Acme|Agent';
  renderProblem(raw,'STRUCTURED_HEADER_INCOMPLETE');
  expect(screen.getByText('LEEF header needing review')).toBeInTheDocument();
  expect(screen.getByText(/Check the LEEF header and delimiter/)).toBeInTheDocument();
  expect(screen.getByText(/reviewed LEEF 2.0 parser supports an explicit delimiter field/)).toBeInTheDocument();
  expect(screen.getByText(/\|0x09\| before TAB-separated key=value fields/)).toBeInTheDocument();
  expect(screen.queryByText(/already understands the main LEEF event/)).not.toBeInTheDocument();
  expect(screen.getByText(raw,{selector:'mark',normalizer:value=>value})).toBeInTheDocument();
 });

 it('keeps implicit TAB source success distinct from the prepared parser grammar',()=>{
  const raw='LEEF:2.0|Acme|Agent|1.0|alert|\tusrName=alice\taction=blocked';
  const bytes=new TextEncoder().encode(raw).byteLength;
  const event:MultiPassSourcePreview={
   ...preview(raw,'STRUCTURED_HEADER_INCOMPLETE'),
   status:'SOURCE_PARSED',syntax:'LEEF_2_IMPLICIT_TAB',
   fields:{leef_extension:{usrName:'alice',action:'blocked'}},
   issues:[],residuals:[],
  };
  render(<BeginnerAnalysisPanel source={raw}
   events={[{startByte:0,endByte:bytes,preview:event}]}
   parserRuleReviewRequired onOpenAssisted={vi.fn()}/>);
  expect(screen.getByText('Values found in 1 of 1 log event')).toBeInTheDocument();
  expect(screen.getByText('Fields extracted — parser rule needs review')).toBeInTheDocument();
  expect(screen.getByText(/Review the LEEF delimiter before creating parser files/)).toBeInTheDocument();
  expect(screen.getByText(/does not match the currently reviewed downloadable parser grammar/)).toBeInTheDocument();
  expect(screen.getByText(/parser files created from the edited sample target the explicit form/)).toBeInTheDocument();
  expect(screen.getByText(raw,{selector:'mark',normalizer:value=>value})).toBeInTheDocument();
  expect(screen.queryByText(/malformed|invalid LEEF/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Text recovery steps')).not.toBeInTheDocument();
 });
});

it('shows exact recovered source values and the full reviewed text-recovery path',()=>{
 const raw='정책 거절 [user "김민수 🔐"] [id "942100"] unresolved text';
 const bytes=(text:string)=>new TextEncoder().encode(text).byteLength;
 const span=(path:string,value:string)=>({path,
  startByte:bytes(raw.slice(0,raw.indexOf(value))),
  endByte:bytes(raw.slice(0,raw.indexOf(value)+value.length)),
 });
 const event:MultiPassSourcePreview={
  ...preview(raw,'NO_SUPPORTED_GRAMMAR'),
  status:'PARTIAL',syntax:'UNKNOWN+GENERIC_LABELS',
  fields:{generic_labels:{user:['김민수 🔐'],id:['942100']}},
  spans:[span('generic_labels.user.0','김민수 🔐'),span('generic_labels.id.0','942100')],
 };
 render(<BeginnerAnalysisPanel source={raw}
  events={[{startByte:0,endByte:bytes(raw),preview:event}]}
  onOpenAssisted={vi.fn()}/>);
 const values=screen.getByLabelText('Preserved source values');
 expect(within(values).getByText('Values already found · 2')).toBeInTheDocument();
 expect(within(values).getByText('generic_labels.user.0')).toBeInTheDocument();
 expect(within(values).getByText('김민수 🔐')).toBeInTheDocument();
 expect(within(values).getByText('942100')).toBeInTheDocument();
 const steps=screen.getByLabelText('Text recovery steps');
 expect(steps).toHaveTextContent('current logs and additional examples');
 expect(steps).toHaveTextContent('check that existing values stay intact');
 expect(steps).toHaveTextContent('Review Fields, Map Fields, and Create Parser');
 expect(steps).toHaveTextContent('Parser-file support is checked separately');
 expect(screen.getByText('0 of 1 log event structurally parsed')).toBeInTheDocument();
});
