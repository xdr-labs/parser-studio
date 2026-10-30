import {useState} from 'react';
import {render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {preview} from '../parser';
import {createDraft,type ParserDraft} from '../model';
import {defaultGuidedOptions} from './contract';
import NormalizationMappingReview from './NormalizationMappingReview';

// Event 1 carries `extra`, event 2 does not: a non-blocking SOURCE_NOT_FOUND note.
const sample=[
  '{"src_ip":"192.0.2.10","extra":"a"}',
  '{"src_ip":"192.0.2.11"}',
].join('\n');

function Harness(){
  const draft:ParserDraft={...createDraft(),format:'json',mappings:[
    {id:'m-ip',source:'src_ip',target:'srcip',type:'ip'},
    {id:'m-extra',source:'extra',target:'extra',type:'string'},
  ],guided:{...defaultGuidedOptions(),groups:{'m-ip':'top_fields','m-extra':'vendor_fields'}}};
  const [state,setDraft]=useState(draft);
  const suite=preview(sample,state);
  return <NormalizationMappingReview draft={state} setDraft={setDraft} suite={suite}
    selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>;
}

describe('Map Fields sample check badge with non-blocking notes',()=>{
  it('does not claim "No mapping problems found" next to a missing-field note',()=>{
    render(<Harness/>);
    const checks=screen.getByLabelText('Field mapping checks');
    expect(checks).toHaveTextContent('This source field is missing from some sample logs');
    expect(checks).not.toHaveTextContent('No mapping problems found');
    expect(checks).toHaveTextContent('1 field to double-check');
    expect(checks).toHaveTextContent('You can still continue');
  });

  it('keeps Create Parser available because the note does not block', ()=>{
    render(<Harness/>);
    expect(screen.getByRole('button',{name:/Create Parser/})).not.toBeDisabled();
  });
});
