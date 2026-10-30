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
});
