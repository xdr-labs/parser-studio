import {afterEach,describe,expect,it,vi} from 'vitest';
import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {createHash,webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import ChatGPTAssist from './ChatGPTAssist';

describe('Assisted: a mapping correction that only changes the JSON type',()=>{
  afterEach(()=>vi.unstubAllGlobals());
  it('explains that a type-only fix is not applied instead of a generic failure',async()=>{
    vi.stubGlobal('crypto',webcrypto);
    const source=[
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"code":"200"}',
      '{"action":"deny","src_ip":"203.0.113.5","dst_port":22,"code":"404"}',
    ].join('\n');
    const holdout=[
      '{"action":"allow","src_ip":"192.0.2.10","dst_port":8443,"code":"301"}',
      '{"action":"deny","src_ip":"192.0.2.11","dst_port":2222,"code":"500"}',
    ].join('\n');
    const base=createDraft();
    const draft={...base,format:'json' as const,
      mappings:[...base.mappings,{id:'vendor-code',source:'code',target:'code',type:'string' as const}],
      guided:{...base.guided!,groups:{...base.guided!.groups,'vendor-code':'vendor_fields' as const}}};
    const recipe={
      contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
      projectId:'draft-demo_firewall',sourceFormat:'json',bodyFormat:'json',
      sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
      stages:[
        {op:'split_event',boundary:'single-line'},{op:'parse_json'},
        {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
        {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
        {op:'map_field',source:'dst_port',target:'custom.destination_port',data_type:'port',group:'ns_fields'},
        {op:'cast_type',target:'custom.destination_port',data_type:'port'},
        {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
        {op:'map_field',source:'code',target:'code',data_type:'integer',group:'vendor_fields'},
        {op:'cast_type',target:'code',data_type:'integer'},
        {op:'classify',defaultIndex:'syslog',rules:[
          {field:'custom.action',operator:'equals',value:'deny',index:'threat'},
          {field:'custom.action',operator:'equals',value:'allow',index:'session'},
        ]},{op:'fallback_unparsed',mode:'retain_unparsed'},
      ],nativeVerified:false,targetVerified:false,
    };
    await act(async()=>{render(<ChatGPTAssist draft={draft} setDraft={vi.fn()}
      sample={source} setSample={vi.fn()} suite={preview(source,draft)} pending={false}
      runPreview={async(candidate,text)=>preview(text??source,candidate)}
      onAutoParser={vi.fn()} namedLogTypes={null}
      onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={vi.fn()}
      onExitNamedLogTypes={vi.fn()}/>);});
    await act(async()=>{fireEvent.click(screen.getByRole('button',{name:'Prepare ChatGPT Prompt'}));});
    await waitFor(()=>expect(screen.getByLabelText('ChatGPT copyable prompt')).toBeTruthy());
    fireEvent.change(screen.getByLabelText('ChatGPT result JSON'),{target:{value:JSON.stringify(recipe)}});
    await act(async()=>{fireEvent.click(screen.getByRole('button',{name:'Check ChatGPT Result'}));});
    const holdoutBox=await screen.findByLabelText('Additional ChatGPT test logs');
    fireEvent.change(holdoutBox,{target:{value:holdout}});
    fireEvent.click(screen.getByLabelText('Confirm test examples are different'));
    await act(async()=>{fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));});
    const message=await screen.findByText(/would change the type of the corrected field \(text → number\)/);
    expect(message.textContent).toMatch(/Map Fields/);
    expect(message.textContent).toMatch(/no rules changed/i);
  });
});
