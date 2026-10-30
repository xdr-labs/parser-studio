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
    expect(screen.getByLabelText('Field mapping summary')).toHaveTextContent('Matched to Stellar0');
    const bulk=screen.getByRole('button',{name:/Apply 3 recommended matches/});
    fireEvent.click(bulk);
    expect(screen.getByLabelText('Field mapping summary')).toHaveTextContent('Matched to Stellar3');
    expect(screen.getByLabelText('Field mapping checks')).toHaveTextContent('All current field mappings passed the sample checks');
    expect(screen.getByLabelText('Field changes only')).toHaveTextContent('srcip');
    expect(screen.getByLabelText('Field changes only')).toHaveTextContent('192.0.2.10');
  });

  it('keeps a non-dictionary target as a vendor field and still lets the user search the official catalog',()=>{
    render(<Harness/>);
    const firstTarget=screen.getByLabelText('Stellar field 0');
    fireEvent.change(firstTarget,{target:{value:'not_a_stellar_field'}});
    expect(screen.getByLabelText('Field mapping checks')).toHaveTextContent('No mapping problems found');
    expect(screen.getByLabelText('Field mapping 1')).toHaveTextContent('Vendor field');
    expect(screen.getByRole('button',{name:'Create Parser'})).not.toBeDisabled();

    fireEvent.click(screen.getAllByRole('button',{name:'Choose Stellar field'})[0]!);
    const search=screen.getByLabelText('Search Stellar field list');
    fireEvent.change(search,{target:{value:'srcip'}});
    const catalog=screen.getByLabelText('Stellar field chooser');
    expect(catalog).toHaveTextContent('srcip');
    fireEvent.click(catalog.getElementsByTagName('button')[1]!);
    expect(screen.getByLabelText('Stellar field 0')).toHaveValue('srcip');
  });

  it('says that removing a mapping leaves the field out of the parser output',()=>{
    render(<Harness/>);
    expect(screen.getByLabelText('Field mapping summary')).toHaveTextContent('Left out of output0');
    expect(screen.getByText(/does not appear in the generated parser output/)).toBeInTheDocument();
    expect(screen.getByText(/original log is not changed/)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('never deleted');
    expect(screen.getAllByRole('button',{name:/Remove normalization/})[0]).toHaveTextContent('Leave out of output');
    fireEvent.click(screen.getAllByRole('button',{name:/Remove normalization/})[0]!);
    expect(screen.getByLabelText('Field mapping summary')).toHaveTextContent('Left out of output1');
  });
});
