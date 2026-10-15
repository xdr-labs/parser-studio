import {describe,it,expect,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import BeginnerAnalysisPanel from './BeginnerAnalysisPanel';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

const preview=(syntax:string):MultiPassSourcePreview=>({
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'SOURCE_PARSED',syntax,sourceSha256:'0'.repeat(64),sourceBytes:5,
  fields:{field:'value'},spans:[],residuals:[],issues:[],
  nativeVerified:false,targetVerified:false,
});

describe('Beginner parser-rule review event targeting',()=>{
  it('shows the actual browser-ledger blocker instead of the first source event',()=>{
    const source='first\nsecond\nthird';
    render(<BeginnerAnalysisPanel source={source}
      events={[
        {startByte:0,endByte:5,preview:preview('JSON')},
        {startByte:6,endByte:12,preview:{...preview('KV'),sourceBytes:6}},
        {startByte:13,endByte:18,preview:preview('CEF_STANDARD')},
      ]}
      onOpenAssisted={vi.fn()}
      parserRuleReviewRequired
      parserRuleReviewEventIndexes={[2]}/>);
    expect(screen.getByText(/Original event 3 · parser rule needs review/)).toBeTruthy();
    expect(screen.getByText('third')).toBeTruthy();
    expect(screen.queryByText(/Original event 1 · parser rule needs review/)).toBeNull();
  });

  it('lists only the actual blockers when more than one browser family needs review',()=>{
    const source='first\nsecond\nthird';
    render(<BeginnerAnalysisPanel source={source}
      events={[
        {startByte:0,endByte:5,preview:preview('JSON')},
        {startByte:6,endByte:12,preview:{...preview('KV'),sourceBytes:6}},
        {startByte:13,endByte:18,preview:preview('CEF_STANDARD')},
      ]}
      onOpenAssisted={vi.fn()}
      parserRuleReviewRequired
      parserRuleReviewEventIndexes={[1,2]}/>);
    const options=screen.getAllByRole('option').map(option=>option.textContent);
    expect(options).toEqual([
      'Event 2 · Parser rule needs review',
      'Event 3 · Parser rule needs review',
    ]);
  });
});
