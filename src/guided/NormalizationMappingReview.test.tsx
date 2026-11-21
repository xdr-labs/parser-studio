import {useState} from 'react';
import {fireEvent,render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import {preview} from '../parser';
import {createDraft,type ParserDraft} from '../model';
import {sha256Utf8Hex} from '../sha256';
import {defaultGuidedOptions} from './contract';
import NormalizationMappingReview from './NormalizationMappingReview';

const sample=[
  '{"src_ip":"192.0.2.10","dst_port":443,"action":"allow"}',
  '{"src_ip":"192.0.2.11","dst_port":8443,"action":"deny"}',
].join('\n');

function initialDraft():ParserDraft{
  return {...createDraft(),format:'json',mappings:[
    {id:'auto-1',source:'src_ip',target:'custom.src_ip',type:'ip',
      authoring:{version:1,origin:'AUTO'}},
    {id:'auto-2',source:'dst_port',target:'custom.dst_port',type:'integer',
      authoring:{version:1,origin:'AUTO'}},
    {id:'auto-3',source:'action',target:'custom.action',type:'string',
      authoring:{version:1,origin:'AUTO'}},
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
  it('reports a rule with a missing normalized target as not emitted',()=>{
    const raw='{"src_ip":"192.0.2.10","items":["x"],"empty":null}';
    const draft:ParserDraft={...createDraft(),format:'json',mappings:[
      {id:'ip',source:'src_ip',target:'srcip',type:'ip'}],
      guided:{...defaultGuidedOptions(),groups:{ip:'top_fields'}}};
    const suite=preview(raw,draft);
    const normalized={...suite.events[0]!.normalized};delete normalized.srcip;
    suite.events[0]={...suite.events[0]!,normalized};
    render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite}
      selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NOT EMITTED · source value present');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NOT MAPPABLE · arrays need a supported native selector');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NOT MAPPABLE · null source value');
    expect(screen.getByLabelText('Final event preview')).toHaveTextContent('Output values present: 0 / 1');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('["x"]');
  });

  it('shows no rule for an unmapped source and keeps its original sample visible',()=>{
    const raw='{"unmapped":"retained","name":"sample"}';
    const draft:ParserDraft={...createDraft(),format:'json',mappings:[]};
    const suite=preview(raw,draft);
    render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite}
      selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NO MAPPING RULE · source value present');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('retained');
  });

  it('recomputes this event after a manual rename and explicit leave-out',()=>{
    const raw='{"source-port":443,"note":"original-value"}';
    function EditableHarness(){
      const [draft,setDraft]=useState<ParserDraft>({...createDraft(),vendor:'DeviceX',format:'json',
        mappings:[{id:'port',source:'source-port',target:'srcport',type:'integer',
          authoring:{version:1,origin:'APPROVED'}}]});
      const suite=preview(raw,draft);
      return <><NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
        originalRawSample={raw} selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
        <output aria-label="current normalized event">{JSON.stringify(suite.events[0]?.normalized)}</output></>;
    }
    render(<EditableHarness/>);
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('EMITTED IN BROWSER PREVIEW');
    fireEvent.change(screen.getByLabelText('Stellar field 0'),{target:{value:'client_port'}});
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('EMITTED IN BROWSER PREVIEW');
    expect(screen.getByLabelText('current normalized event')).toHaveTextContent('client_port');
    fireEvent.click(screen.getByRole('button',{name:'Remove normalization 0'}));
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NO MAPPING RULE · source value present');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('443');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('original-value');
    expect(screen.getByLabelText('Final event preview')).toHaveTextContent('Output values present: 0 / 0');
  });

  it('accounts exact original UTF-8 bytes and updates with selected event and mapping edits',async()=>{
    const raw='{"message":"診断ログ","source-port":443,"destination-port":444,"nullable":null}\n{"message":"終端","source-port":8443,"destination-port":8444,"nullable":null}';
    const draft:ParserDraft={...createDraft(),vendor:'DeviceX',format:'json',mappings:[
      {id:'port',source:'source-port',target:'srcport',type:'integer'}]};
    const suite=preview(raw,draft);
    const bytes=new TextEncoder().encode(raw).length;
    const residuals=suite.events.map(()=>[] as {startByte:number;endByte:number}[]);
    const raws=suite.events.map(event=>event.raw);
    const {rerender}=render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite}
      originalRawSample={raw} multipassSourceSample={raw} multipassResiduals={residuals} multipassRawEvents={raws}
      selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    expect(await screen.findByText(new RegExp(`Total source: ${bytes} UTF-8 bytes`))).toBeInTheDocument();
    expect(screen.getByLabelText('Lossless source accounting')).toHaveTextContent(await sha256Utf8Hex(raw));
    expect(screen.getByLabelText('Lossless source accounting')).toHaveTextContent('Events accounted: 2 / 2');
    expect(screen.getByLabelText('Lossless source accounting')).toHaveTextContent('Residual evidence: available for every event');
    expect(screen.getByLabelText('Lossless source accounting')).toHaveTextContent('NOT verified with native Ruby / DP');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NOT MAPPABLE · null source value');
    expect(screen.getByRole('button',{name:'source-port'})).toHaveAttribute('title','Full source path: source-port');
    expect(screen.getByRole('button',{name:'destination-port'})).toHaveAttribute('title','Full source path: destination-port');
    rerender(<NormalizationMappingReview draft={{...draft,mappings:[{...draft.mappings[0]!,target:'dstport'}]}} setDraft={vi.fn()} suite={suite}
      originalRawSample={raw} multipassSourceSample={raw} multipassResiduals={residuals} multipassRawEvents={raws}
      selected={1} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    expect(await screen.findByText(/Record accounting/)).toBeInTheDocument();
    expect(screen.getByLabelText('Field changes only')).toHaveTextContent('dstport');
  });
  it('keeps missing or index-mismatched Multi-Pass evidence UNKNOWN and shows read-only raw',async()=>{
    const raw='{"x":1}\n{"x":1}';
    const draft:ParserDraft={...createDraft(),format:'json'};
    const suite=preview(raw,draft);
    render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite} originalRawSample={raw}
      multipassSourceSample={raw} multipassResiduals={[[]]} multipassRawEvents={[suite.events[0]!.raw]}
      selected={1} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    expect(await screen.findByText('Record accounting UNKNOWN')).toBeInTheDocument();
    expect(await screen.findByText(/Missing or mismatched evidence/)).toBeInTheDocument();
    expect(screen.getByLabelText('Read-only raw sample')).toHaveValue(raw);
    expect(screen.getByLabelText('Unparsed source evidence')).toHaveTextContent('UNKNOWN / UNVERIFIED');
  });
  it('shows exact reviewed residual bytes and offers the existing Review Fields repair path',()=>{
    const raw='{"ok":true} tail';
    const suite=preview(raw,{...createDraft(),format:'json'});
    const start=new TextEncoder().encode('{"ok":true} ').length;
    const onReviewResiduals=vi.fn();
    render(<NormalizationMappingReview draft={{...createDraft(),format:'json'}} setDraft={vi.fn()} suite={suite}
      multipassResiduals={[[{startByte:start,endByte:new TextEncoder().encode(raw).length}]]}
      multipassRawEvents={[raw]}
      onReviewResiduals={onReviewResiduals} selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    const evidence=screen.getByLabelText('Unparsed source evidence');
    expect(evidence).toHaveTextContent(`Bytes ${start}–${new TextEncoder().encode(raw).length}`);
    expect(evidence).toHaveTextContent('tail');
    fireEvent.click(screen.getByRole('button',{name:'Review Fields and repair unparsed text'}));
    expect(onReviewResiduals).toHaveBeenCalledOnce();
  });
  it('shows safe source paths with leaf labels, retains selected vendor fields, and keeps arrays not mappable',()=>{
    const raw='{"vendor":{"source-port":443},"evidence":["ioc-1","ioc-2"],"empty":null}';
    function SourceTreeHarness(){
      const [draft,setDraft]=useState<ParserDraft>({...createDraft(),vendor:'DeviceX',format:'json',mappings:[]});
      const suite=preview(raw,draft);
      return <><NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
        selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
        <output aria-label="source path output">{JSON.stringify(suite.events[0]?.normalized)}</output>
      </>;
    }
    render(<SourceTreeHarness/>);
    expect(screen.getByLabelText('Independent parsing and output coverage')).toHaveTextContent('Raw events retained1 / 1');
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NOT MAPPABLE · arrays need a supported native selector');
    expect(screen.getByRole('button',{name:'source-port'})).toHaveAttribute('title','Full source path: vendor.source-port');
    fireEvent.click(screen.getByRole('button',{name:'source-port'}));
    expect(screen.getAllByText('vendor.source-port').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button',{name:'Keep as vendor field'}));
    expect(screen.getByLabelText('source path output')).toHaveTextContent('"DeviceX":{"source-port":"443"}');
    expect(screen.getByLabelText('Final event preview')).toHaveTextContent('Output values present: 1 / 1');
  });

  it('shows complete long UTF-8 values and labels retained nulls without truncation',()=>{
    const longValue='診断ログ-'.repeat(20)+'終端';
    const raw=JSON.stringify({message:longValue,nullable:null});
    const draft:ParserDraft={...createDraft(),format:'json',mappings:[]};
    const suite=preview(raw,draft);
    render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite}
      selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    expect(screen.getByLabelText('Source fields')).toHaveTextContent(longValue);
    expect(screen.getByLabelText('Source fields')).toHaveTextContent('NOT MAPPABLE · null source value');
    expect(screen.getByLabelText('Source fields')).not.toHaveTextContent('…');
  });

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

  it('does not bulk-refresh a user-edited mapping from automatic suggestions',()=>{
    function EditedMappingHarness(){
      const initial=initialDraft();
      const [draft,setDraft]=useState<ParserDraft>({...initial,mappings:initial.mappings.map(mapping=>
        mapping.id==='auto-1'?{...mapping,target:'manual_source_ip',
          authoring:{version:1,origin:'USER_EDITED'}}:mapping)});
      const suite=preview(sample,draft);
      return <><NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
        selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
        <output aria-label="edited target">{draft.mappings.find(mapping=>mapping.id==='auto-1')?.target}</output>
      </>;
    }
    render(<EditedMappingHarness/>);
    fireEvent.click(screen.getByRole('button',{name:/Apply \d+ recommended matches/}));
    expect(screen.getByLabelText('edited target')).toHaveTextContent('manual_source_ip');
  });
  it('does not let an individually applied official suggestion overwrite an approved mapping',()=>{
    function ApprovedHarness(){
      const base=initialDraft();
      const [draft,setDraft]=useState<ParserDraft>({...base,mappings:base.mappings.map(mapping=>
        mapping.source==='src_ip'?{...mapping,target:'approved_destination',authoring:{version:1,origin:'APPROVED'}}:mapping)});
      const suite=preview(sample,draft);
      return <><NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
        selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
        <output aria-label="protected mapping target">{draft.mappings.find(mapping=>mapping.source==='src_ip')?.target}</output></>;
    }
    render(<ApprovedHarness/>);
    fireEvent.click(screen.getByRole('button',{name:'Apply official mapping src_ip'}));
    expect(screen.getByLabelText('protected mapping target')).toHaveTextContent('approved_destination');
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


  it('keeps an edited auto-generated destination through rerenders and review reconciliation',()=>{
    function EditedHarness(){
      const base=createDraft();
      const [draft,setDraft]=useState<ParserDraft>({...base,format:'json',mappings:[
        {id:'auto-1',source:'http.status',target:'status',type:'string',
          authoring:{version:1,origin:'AUTO'}},
      ],guided:{...defaultGuidedOptions(),groups:{'auto-1':'vendor_fields'}}});
      const suite=preview('{"http":{"status":200}}',draft);
      return <><NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
        selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
        <output aria-label="authoring status">{draft.mappings[0]?.authoring?.origin}</output>
        <output aria-label="saved current mapping">{JSON.stringify(draft.mappings[0])}</output>
      </>;
    }
    render(<EditedHarness/>);
    const target=screen.getByLabelText('Stellar field 0');
    fireEvent.change(target,{target:{value:'http.status'}});
    expect(target).toHaveValue('http.status');
    expect(screen.getByLabelText('authoring status')).toHaveTextContent('USER_EDITED');
    expect(screen.getByLabelText('saved current mapping')).toHaveTextContent('http.status');
    expect(target).toHaveValue('http.status');
  });

  it('shows actual destination field names without treating the draft manufacturer as part of the name',()=>{
    render(<Harness/>);
    const comparison=screen.getByLabelText('Field changes only');
    const destinations=[...comparison.querySelectorAll('div > strong:nth-of-type(2)')]
      .map(node=>node.textContent);
    expect(destinations).toEqual(['custom.src_ip','custom.dst_port','custom.action']);
    expect(destinations.every(name=>!name?.startsWith('Demo Local Draft.'))).toBe(true);
    // The real output contract remains namespaced until a manufacturer is set;
    // this changes the destination label only, not parser emission semantics.
    const normalized=screen.getByText('Stellar output preview').parentElement;
    expect(normalized?.textContent).toContain('Demo Local Draft');
    expect(normalized?.textContent).toContain('custom');
  });


  it('does not display a nested source value when a reviewed literal-root selector is absent',()=>{
    const draft:ParserDraft={...createDraft(),format:'json',
      mappings:[{id:'literal-ip',source:'source.ip',sourcePathKind:'literal_root',
        target:'vendor_ip',type:'string'}],
      guided:{...defaultGuidedOptions(),groups:{'literal-ip':'vendor_fields'}}};
    const suite=preview('{"source":{"ip":"192.0.2.40"}}',draft);
    expect(suite.events[0]?.normalized).not.toHaveProperty('Demo Local Draft');
    render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite}
      selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    const row=screen.getByLabelText('Field changes only').firstElementChild;
    expect(row?.querySelector('strong')?.textContent).toBe('source.ip');
    expect(row?.querySelector('span')?.textContent).toBe('Not present');
    expect(row?.querySelectorAll('span')[1]?.textContent).toBe('Not emitted');
  });

  it('does not display an unrelated top-level enrichment as an absent vendor field',()=>{
    const options=defaultGuidedOptions();
    const draft:ParserDraft={...createDraft(),format:'json',
      mappings:[{id:'vendor-marker',source:'missing_source',target:'review_marker',type:'string'}],
      guided:{...options,groups:{'vendor-marker':'vendor_fields'},
        enrichment:[{id:'marker',operator:'set_const',source:'',target:'review_marker',value:'ENRICHED_ROOT'}]}};
    const suite=preview('{"device":"fw1"}',draft);
    expect(suite.events[0]?.normalized).toHaveProperty('review_marker','ENRICHED_ROOT');
    expect(suite.events[0]?.normalized).not.toHaveProperty('Demo Local Draft');
    render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite}
      selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    const row=screen.getByLabelText('Field changes only').firstElementChild;
    expect(row?.querySelectorAll('strong')[1]?.textContent).toBe('review_marker');
    expect(row?.querySelectorAll('span')[1]?.textContent).toBe('Not emitted');
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

  it('lets a Generic Structural parser leave the full raw line out of the output, and hides the switch for other formats',()=>{
    const kv='<134>date=2023-02-23 time=22:49:29 devname=FMG-VM user=alice status=success';
    function GenericHarness(){
      const [draft,setDraft]=useState<ParserDraft>({...createDraft(),format:'generic_structural',
        mappings:[{id:'g-1',source:'generic.kv.user',target:'custom.user',type:'string'}],
        guided:{...defaultGuidedOptions(),groups:{'g-1':'vendor_fields'}}});
      const suite=preview(kv,draft);
      return <><NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
        selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
        <output aria-label="omit flag">{String(draft.omitSourceRaw??'unset')}</output></>;
    }
    const {unmount}=render(<GenericHarness/>);
    const toggle=screen.getByRole('checkbox',{name:/Copy the full original line/});
    expect(toggle).toBeChecked();
    expect(screen.getByText(/about twice the size/i)).toBeInTheDocument();
    fireEvent.click(toggle);
    expect(screen.getByLabelText('omit flag')).toHaveTextContent('true');
    expect(screen.getByRole('checkbox',{name:/Copy the full original line/})).not.toBeChecked();
    fireEvent.click(screen.getByRole('checkbox',{name:/Copy the full original line/}));
    expect(screen.getByLabelText('omit flag')).toHaveTextContent('unset');
    unmount();
    render(<Harness/>);
    expect(screen.queryByRole('checkbox',{name:/Copy the full original line/})).toBeNull();
  });
});

describe('Juniper nested vendor field naming',()=>{
  it('fixes persisted generated names in the editor, comparison and parser preview',()=>{
    const raw='<14>1 2019-11-14T09:37:51.184+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_CREATE '+
      '[junos@67.43.156.15 source-address="10.0.0.1" source-port="594" '+
      'destination-address="67.43.156.13" destination-port="10400" protocol-id="1"]';
    const source='syslog_sd.element_1.params.source-port';
    function JuniperHarness(){
      const [draft,setDraft]=useState<ParserDraft>({...createDraft(),vendor:'Juniper',
        format:'syslog_rfc5424',syslogBodyFormat:'raw',
        mappings:[
          {id:'auto-1',source,target:'syslog_sd_element_1_params_source-port',type:'string',
            authoring:{version:1,origin:'AUTO'}},
          {id:'auto-2',source:'syslog_sd.element_1.params.destination-port',
            target:'syslog_sd_element_1_params_destination-port',type:'string',
            authoring:{version:1,origin:'AUTO'}},
          {id:'auto-3',source:'syslog_sd.element_1.params.source-address',target:'srcip',type:'ip'},
        ],guided:{...defaultGuidedOptions(),groups:{
          'auto-1':'vendor_fields','auto-2':'vendor_fields','auto-3':'top_fields',
        },classification:{defaultIndex:'Syslog',rules:[]}}});
      const suite=preview(raw,draft);
      return <><NormalizationMappingReview draft={draft} setDraft={setDraft} suite={suite}
        selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
        <output aria-label="native vendor target">{JSON.stringify(suite.events[0]?.normalized.Juniper)}</output>
      </>;
    }
    render(<JuniperHarness/>);
    expect(screen.getByLabelText('Source field 0')).toHaveValue(source);
    expect(screen.getByLabelText('Stellar field 0')).toHaveValue('srcport');
    expect(screen.getByLabelText('Stellar field 1')).toHaveValue('dstport');
    const comparison=screen.getByLabelText('Field changes only');
    expect(comparison).toHaveTextContent('source-port');
    expect(comparison).not.toHaveTextContent('Juniper.syslog_sd_element_1_params_source-port');
    expect(comparison).not.toHaveTextContent('Juniper.source-port');
    expect(screen.getByLabelText('Field changes only')).toHaveTextContent('srcport');
    expect(screen.getByLabelText('Stellar field 2')).toHaveValue('srcip');
  });
});

describe('unmappable source field disclosure',()=>{
  it('counts unsupported @ keys and arrays while preserving selectable dotted paths',()=>{
    const sample=JSON.stringify({
      srcip:'192.0.2.10',
      metadata:{'session.id':'s1','actor@realm':'alice',evidence:['ioc-1','ioc-2']},
    });
    const draft:ParserDraft={...createDraft(),format:'json',mappings:[
      {id:'src',source:'srcip',target:'srcip',type:'ip'},
    ]};
    const suite=preview(sample,draft);
    render(<NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={suite}
      selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>);
    expect(screen.getByLabelText('Field mapping summary')).toHaveTextContent('Unmappable source values3');
    expect(screen.getByLabelText('Field mapping summary')).toHaveTextContent('Left out of output4');
  });
});
