import {useState} from 'react';
import {render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {preview} from '../parser';
import {createDraft,type ParserDraft} from '../model';
import {defaultGuidedOptions} from './contract';
import NormalizationMappingReview from './NormalizationMappingReview';

// Event 1 carries `extra`, event 2 does not: a legitimate optional source field.
const sample=[
  '{"src_ip":"192.0.2.10","extra":"a"}',
  '{"src_ip":"192.0.2.11"}',
].join('\n');

function Harness(){
  const draft:ParserDraft={...createDraft(),vendor:'SampleVendor',format:'json',mappings:[
    {id:'m-ip',source:'src_ip',target:'srcip',type:'ip'},
    {id:'m-extra',source:'extra',target:'extra',type:'string'},
  ],guided:{...defaultGuidedOptions(),groups:{'m-ip':'top_fields','m-extra':'vendor_fields'}}};
  const [state,setDraft]=useState(draft);
  const suite=preview(sample,state);
  return <NormalizationMappingReview draft={state} setDraft={setDraft} suite={suite}
    selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>;
}

describe('Map Fields sample check badge with non-blocking notes',()=>{
  it('preserves the exact vendor value only in events where its source exists',()=>{
    const draft:ParserDraft={...createDraft(),vendor:'SampleVendor',format:'json',mappings:[
      {id:'m-ip',source:'src_ip',target:'srcip',type:'ip'},
      {id:'m-extra',source:'extra',target:'extra',type:'string'},
    ],guided:{...defaultGuidedOptions(),groups:{'m-ip':'top_fields','m-extra':'vendor_fields'}}};
    const result=preview(sample,draft);
    expect(result.events[0]?.normalized).toMatchObject({
      srcip:'192.0.2.10',SampleVendor:{extra:'a'},
    });
    expect(result.events[1]?.normalized).toMatchObject({srcip:'192.0.2.11'});
    expect(result.events[1]?.normalized.SampleVendor).toBeUndefined();
    expect(result.counts).toMatchObject({total:2,normalized:2,failures:0});
  });
  it('does not warn that an optional event field was lost',()=>{
    render(<Harness/>);
    const checks=screen.getByLabelText('Field mapping checks');
    expect(checks).not.toHaveTextContent('SOURCE_NOT_FOUND');
    expect(checks).not.toHaveTextContent('missing from some sample logs');
    expect(checks).toHaveTextContent('No mapping problems found');
  });

  it('keeps Create Parser available because the note does not block', ()=>{
    render(<Harness/>);
    expect(screen.getByRole('button',{name:/Create Parser/})).not.toBeDisabled();
  });
});
