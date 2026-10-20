import {useState} from 'react';
import {fireEvent,render,screen,within} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import NormalizationMappingReview from './NormalizationMappingReview';

const logs=[
  JSON.stringify({src_ip:'192.0.2.11',source_ip:'203.0.113.20',request_status:200}),
  JSON.stringify({src_ip:'192.0.2.12',source_ip:'203.0.113.21',request_status:403}),
].join('\n');

function Harness(){
  const [draft,setDraft]=useState<ParserDraft>({...createDraft(),format:'json',mappings:[]});
  return <NormalizationMappingReview draft={draft} setDraft={setDraft}
    suite={preview(logs,draft)} selected={0} setSelected={vi.fn()}
    pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>;
}

describe('Stellar Cyber 7.0 Map Fields ambiguity and semantic safety',()=>{
  it('never bulk-applies two source fields competing for one official destination',()=>{
    render(<Harness/>);
    const recommendations=screen.getByLabelText('Recommended field matches');
    expect(screen.getByRole('button',{name:'Apply 0 recommended matches'})).toBeDisabled();
    expect(within(recommendations).getAllByText(/multiple source fields map to the same/i)).toHaveLength(2);
    expect(within(recommendations).getByRole('button',{name:'Apply official mapping src_ip'})).toBeEnabled();
    expect(within(recommendations).getByRole('button',{name:'Apply official mapping source_ip'})).toBeEnabled();
    expect(within(recommendations).queryByRole('button',{name:'Apply official mapping request_status'})).toBeNull();
    expect(screen.getByText('Stellar field dictionary 7.0.xs')).toBeInTheDocument();

    fireEvent.click(within(recommendations).getByRole('button',{name:'Apply official mapping src_ip'}));
    expect(screen.getByLabelText('Field mapping summary')).toHaveTextContent('Matched to Stellar1');
    expect(screen.getByLabelText('Field mapping checks')).toHaveTextContent('All current field mappings passed the sample checks');
    expect(within(recommendations).queryByRole('button',{name:'Apply official mapping source_ip'})).toBeNull();
  });
});
