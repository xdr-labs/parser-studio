import {afterEach,describe,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import {createHash,webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import AutoParserAIReview from './AutoParserAIReview';

// Component tests use a deterministic parser simulation, never browser workers.
vi.mock('../previewWorkerClient',()=>({
 runInWorker:async(raw:string,draft:import('../model').ParserDraft)=>
   (await import('../parser')).preview(raw,draft),
}));

describe('ChatGPT answer with explanation around the JSON recipe',()=>{
 afterEach(()=>vi.unstubAllGlobals());
 it('filters the prose and reviews the recipe instead of rejecting it as invalid JSON',async()=>{
  vi.stubGlobal('crypto',webcrypto);
  const source=[
   '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"event_type":"login-ok"}',
   '{"action":"deny","src_ip":"203.0.113.5","dst_port":22,"event_type":"login-bad"}',
  ].join('\n');
  const holdout=[
   '{"action":"allow","src_ip":"192.0.2.10","dst_port":8443,"event_type":"logout-ok"}',
   '{"action":"deny","src_ip":"192.0.2.11","dst_port":2222,"event_type":"login-ok"}',
  ].join('\n');
  const base=createDraft();
  const draft={...base,format:'json' as const,
   mappings:[...base.mappings,{id:'vendor-event-type',source:'event_type',target:'event_type',type:'string' as const}],
   guided:{...base.guided!,groups:{...base.guided!.groups,'vendor-event-type':'vendor_fields' as const}}};
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
    {op:'map_field',source:'event_type',target:'event_type',data_type:'string',group:'vendor_fields'},
    {op:'split_field',source:'event_type',delimiter:'-',targets:['custom.event_kind','custom.event_result']},
    {op:'classify',defaultIndex:'syslog',rules:[
     {field:'custom.action',operator:'equals',value:'deny',index:'threat'},
     {field:'custom.action',operator:'equals',value:'allow',index:'session'},
    ]},{op:'fallback_unparsed',mode:'retain_unparsed'},
   ],nativeVerified:false,targetVerified:false,
  };
  const apply=vi.fn();
  render(<AutoParserAIReview raw={source} status="partial" onChatGPT={vi.fn()}
   source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}/>);
  fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:'Sure! Here is the recipe.\n\n```json\n'+JSON.stringify(recipe,null,2)+'\n```\n\nLet me know if you want changes.'}});
  fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
  fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
  fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
  const message=await screen.findByText(/splits or merges a vendor-only field \(event_type\)/);
  expect(message.textContent).not.toMatch(/INVALID_JSON/);
  expect(screen.getByText(/Text around the JSON recipe was ignored/)).toBeInTheDocument();
  expect(message.textContent).toMatch(/Map Fields/);
  expect(message.textContent).toMatch(/No changes were made/);
  expect(message.textContent).not.toMatch(/BACKEND_UNSUPPORTED/);
  expect(apply).not.toHaveBeenCalled();
 });
});
