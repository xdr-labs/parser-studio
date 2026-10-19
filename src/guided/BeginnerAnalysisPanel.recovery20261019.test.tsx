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
