import {useState} from 'react';
import {fireEvent,render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {preview} from '../parser';
import {createDraft,type ParserDraft} from '../model';
import {defaultGuidedOptions} from './contract';
import NormalizationMappingReview from './NormalizationMappingReview';

const sample=[
  '{"src_ip":"192.0.2.10","dst_port":443,"action":"allow"}',
  '{"src_ip":"192.0.2.11","dst_port":8443,"action":"deny"}',
].join('\n');

function initialDraft():ParserDraft{
  return {...createDraft(),format:'json',mappings:[
    {id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'ip'},
    {id:'auto-2',source:'dst_port',target:'custom.dst_port',type:'integer'},
    {id:'auto-3',source:'action',target:'custom.action',type:'string'},
  ],guided:{...defaultGuidedOptions(),groups:{
    'auto-1':'vendor_fields','auto-2':'vendor_fields','auto-3':'vendor_fields',
  }}};
}

function Harness(){
  const [draft,setDraft]=useState(initialDraft());
  const suite=preview(sample,draft);
  return <NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
    selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>;
}

describe('normalization mapping review UI',()=>{
  it('bulk-applies only high-confidence official Stellar mappings and previews results',()=>{
    render(<Harness/>);
    expect(screen.getByLabelText('Normalization mapping summary')).toHaveTextContent('Official mappings0');
    const bulk=screen.getByRole('button',{name:/Apply 3 high-confidence suggestions/});
    fireEvent.click(bulk);
    expect(screen.getByLabelText('Normalization mapping summary')).toHaveTextContent('Official mappings3');
    expect(screen.getByLabelText('Normalization validation')).toHaveTextContent('No local mapping issues detected');
    expect(screen.getByLabelText('Normalization changes only')).toHaveTextContent('srcip');
    expect(screen.getByLabelText('Normalization changes only')).toHaveTextContent('192.0.2.10');
  });

  it('blocks an unknown non-custom target and lets the user search the official catalog',()=>{
    render(<Harness/>);
    const firstTarget=screen.getByLabelText('Normalized destination 0');
    fireEvent.change(firstTarget,{target:{value:'not_a_stellar_field'}});
    expect(screen.getByLabelText('Normalization validation')).toHaveTextContent('UNVERIFIED_TARGET');
    expect(screen.getByRole('button',{name:'Create Parser'})).toBeDisabled();

    fireEvent.click(screen.getAllByRole('button',{name:'Find Stellar field'})[0]!);
    const search=screen.getByLabelText('Search Stellar metadata catalog');
    fireEvent.change(search,{target:{value:'srcip'}});
    const catalog=screen.getByLabelText('Search official Stellar metadata catalog');
    expect(catalog).toHaveTextContent('srcip');
    fireEvent.click(catalog.getElementsByTagName('button')[1]!);
    expect(screen.getByLabelText('Normalized destination 0')).toHaveValue('srcip');
  });
});
