import {afterEach,describe,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {createHash,webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import AutoParserAIReview from './AutoParserAIReview';

describe('AI recovery review safety',()=>{
 afterEach(()=>vi.unstubAllGlobals());
 it('requires user-reviewed excerpt and request before copying whole log',()=>{
  render(<AutoParserAIReview raw="RAW event" status="unsupported" onChatGPT={vi.fn()}/>);
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
  fireEvent.change(screen.getByRole('textbox',{name:'AI correction request'}),{target:{value:'Extract source IP'}});
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('checkbox',{name:'Confirm reviewed AI excerpt'}));
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
  fireEvent.change(screen.getByRole('textbox',{name:'Reviewed and redacted AI excerpt'}),{target:{value:'REDACTED event'}});
  fireEvent.click(screen.getByRole('checkbox',{name:'Confirm reviewed AI excerpt'}));
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(false);
 });
 it('does not authorize selected-area copy without exact selection',()=>{
  render(<AutoParserAIReview raw="src=192.0.2.1" status="partial" onChatGPT={vi.fn()}/>);
  fireEvent.change(screen.getByRole('textbox',{name:'AI correction request'}),{target:{value:'Extract IP'}});
  fireEvent.click(screen.getByRole('checkbox',{name:'Confirm reviewed AI excerpt'}));
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
 });
 it('shows exact field or residual correction scope while preserving accepted fields',()=>{
  render(<AutoParserAIReview raw="src=192.0.2.1 tail=?" status="partial" onChatGPT={vi.fn()}
   initialByteRange={{startByte:4,endByte:13}} selectionContext={{kind:'field',path:'src'}}/>);
  expect(screen.getByText(/Editing extracted field: src/)).toBeTruthy();
  expect(screen.getByText(/Accepted fields outside this exact range are preserved/)).toBeTruthy();
  expect(screen.getByText('192.0.2.1')).toBeTruthy();
 });
 it('copies canonical parser metadata without leaking the unreviewed source sample',async()=>{
  vi.stubGlobal('crypto',webcrypto);
  const source=[
   '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"user":"PRIVATE_A"}',
   '{"action":"deny","src_ip":"203.0.113.5","dst_port":22,"user":"PRIVATE_B"}',
  ].join('\n');
  const draft={...createDraft(),format:'json' as const};
  const writeText=vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText}});
  render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
   source={source} draft={draft} suite={preview(source,draft)}/>);
  fireEvent.change(screen.getByRole('textbox',{name:'AI correction request'}),{target:{value:'Correct the source IP mapping'}});
  fireEvent.change(screen.getByRole('textbox',{name:'Reviewed and redacted AI excerpt'}),{target:{value:'src_ip=REDACTED'}});
  fireEvent.click(screen.getByRole('checkbox',{name:'Confirm reviewed AI excerpt'}));
  fireEvent.click(screen.getByRole('button',{name:'Copy AI Prompt'}));
  await waitFor(()=>expect(writeText).toHaveBeenCalledTimes(1));
  const copied=String(writeText.mock.calls[0]![0]);
  expect(copied).toContain('BEGIN CANONICAL PARSER RECIPE');
  expect(copied).toContain('custom.source_ip');
  expect(copied).toContain('src_ip=REDACTED');
  expect(copied).not.toContain('PRIVATE_A');
  expect(copied).not.toContain('198.51.100.10');
 });
 it('applies a fully verified RAW recovery candidate only after independent holdout approval',async()=>{
  vi.stubGlobal('crypto',webcrypto);
  const source='allow,198.51.100.10\ndeny,203.0.113.4';
  const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
  const draft=createDraft(),apply=vi.fn();
  const recipe={
   contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
   projectId:'draft-demo_firewall',sourceFormat:'csv',bodyFormat:'csv',
   sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
   stages:[
    {op:'split_event',boundary:'single-line'},{op:'parse_csv',columns:['action','src_ip'],delimiter:','},
    {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
    {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
    {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
    {op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'},
   ],nativeVerified:false,targetVerified:false,
  };
  render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
   source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}/>);
  fireEvent.change(screen.getByRole('textbox',{name:'AI Recipe JSON'}),{target:{value:JSON.stringify(recipe)}});
  fireEvent.change(screen.getByRole('textbox',{name:'AI candidate holdout logs'}),{target:{value:holdout}});
  fireEvent.click(screen.getByRole('checkbox',{name:'Confirm independent AI holdout provenance'}));
  fireEvent.click(screen.getByRole('button',{name:'Validate Proposal (Review Only)'}));
  expect(await screen.findByText(/Ready for explicit approval: full parser recovery/)).toBeTruthy();
  fireEvent.click(screen.getByRole('checkbox',{name:'Approve verified inline AI candidate'}));
  fireEvent.click(screen.getByRole('button',{name:'Apply Approved Recovery Parser to Draft'}));
  await waitFor(()=>expect(apply).toHaveBeenCalledTimes(1));
  expect(apply.mock.calls[0]![0]).toMatchObject({format:'csv',csvColumns:'action,src_ip'});
 });
 it('rejects unverified AI recipe and never applies changes',()=>{
  render(<AutoParserAIReview raw="RAW" status="unsupported" onChatGPT={vi.fn()}/>);
  fireEvent.click(screen.getByText('Paste AI Recipe for strict review'));
  fireEvent.change(screen.getByRole('textbox',{name:'AI Recipe JSON'}),{target:{value:'{"code":"unsafe"}'}});
  expect(screen.getByRole('button',{name:'Validate Proposal (Review Only)'}).hasAttribute('disabled')).toBe(true);
 });
 it('opens the existing assisted parser path',()=>{
  const onChatGPT=vi.fn();
  render(<AutoParserAIReview raw="RAW" status="unsupported" onChatGPT={onChatGPT}/>);
  fireEvent.click(screen.getByRole('button',{name:'Open Assisted Parser'}));
  expect(onChatGPT).toHaveBeenCalledTimes(1);
 });
});
