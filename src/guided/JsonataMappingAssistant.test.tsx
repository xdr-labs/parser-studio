import {useState} from 'react';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {describe,expect,it,vi} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import JsonataMappingAssistant from './JsonataMappingAssistant';
import {JSONATA_MAPPING_CONTRACT} from './jsonataMappingAssist';

const raw=[
  '{"src_ip":"192.0.2.10","action":"allow"}',
  '{"src_ip":"192.0.2.11","action":"deny"}',
].join('\n');
function Harness(){
  const base=createDraft();
  const [draft,setDraft]=useState<ParserDraft>({...base,format:'json',
    mappings:[{id:'s',source:'src_ip',target:'custom.src',type:'ip'}],
    guided:{...base.guided!,groups:{s:'vendor_fields'},classification:{defaultIndex:'Syslog',rules:[]}}});
  const suite=preview(raw,draft);
  return <>
    <JsonataMappingAssistant draft={draft} setDraft={setDraft} suite={suite} pending={false}/>
    <output aria-label="Applied source target">{draft.mappings.find(m=>m.source==='src_ip')?.target}</output>
    <output aria-label="Applied mapping group">{draft.guided?.groups.s}</output>
  </>;
}
const open=()=>fireEvent.click(screen.getByRole('button',{name:'Improve mappings with ChatGPT JSONata'}));
async function preparedSha(){
  fireEvent.click(screen.getByRole('button',{name:'Prepare Mapping Prompt'}));
  await waitFor(()=>expect(screen.getByLabelText('ChatGPT JSONata mapping prompt')).toBeInTheDocument());
  const prompt=(screen.getByLabelText('ChatGPT JSONata mapping prompt') as HTMLTextAreaElement).value;
  const match=prompt.match(/"sha256":\s*"([a-f0-9]{64})"/);
  expect(match).not.toBeNull();
  return {sha:match![1]!,prompt};
}
function reply(sha:string,expression:string,target:string){
  fireEvent.change(screen.getByLabelText('Paste ChatGPT JSONata mapping response'),
    {target:{value:JSON.stringify({
      contract:JSONATA_MAPPING_CONTRACT,sample:{sha256:sha,events:2},
      mappings:[{expression,target}],
    })}});
  fireEvent.click(screen.getByRole('button',{name:'Check JSONata Mappings'}));
}
describe('manual, privacy-conscious ChatGPT JSONata field mapping UI',()=>{
  it('copies only field names by default, validates a proposal, and requires explicit approval before saving',async()=>{
    render(<Harness/>);
    open();
    const {sha,prompt}=await preparedSha();
    expect(prompt).not.toContain('192.0.2.10');
    expect(screen.getByLabelText('Applied source target')).toHaveTextContent('custom.src');
    reply(sha,'$.src_ip','srcip');
    await waitFor(()=>expect(screen.getByLabelText('Reviewed ChatGPT JSONata mappings')).toHaveTextContent('READY'));
    const apply=screen.getByRole('button',{name:'Apply 1 Reviewed Mapping'});
    expect(apply).toBeDisabled();
    fireEvent.click(screen.getByLabelText('I reviewed the selected JSONata mappings'));
    expect(apply).toBeEnabled();
    fireEvent.click(apply);
    expect(screen.getByLabelText('Applied source target')).toHaveTextContent('srcip');
    expect(screen.getByLabelText('Applied mapping group')).toHaveTextContent('top_fields');
  });
  it('blocks unsupported JSONata functions before any field mapping can change',async()=>{
    render(<Harness/>);
    open();
    const {sha}=await preparedSha();
    reply(sha,'$lookup(src_ip,"x")','srcip');
    await waitFor(()=>expect(screen.getByLabelText('Reviewed ChatGPT JSONata mappings')).toHaveTextContent('BLOCKED'));
    expect(screen.getByLabelText(/Approve JSONata mapping.*to srcip/)).toBeDisabled();
    expect(screen.getByLabelText('Applied source target')).toHaveTextContent('custom.src');
  });
  it('includes sensitive values only after the explicit opt-in',async()=>{
    render(<Harness/>);
    open();
    fireEvent.click(screen.getByLabelText('Include observed values in ChatGPT mapping prompt'));
    const {prompt}=await preparedSha();
    expect(prompt).toContain('192.0.2.10');
  });
  it('keeps draft unchanged for an inconsistent response fingerprint',async()=>{
    render(<Harness/>);
    open();
    await preparedSha();
    reply('0'.repeat(64),'$.src_ip','srcip');
    await waitFor(()=>expect(screen.getByRole('alert')).toHaveTextContent('fingerprint'));
    expect(screen.getByLabelText('Applied source target')).toHaveTextContent('custom.src');
  });
  it('never calls external AI APIs by itself',async()=>{
    const fetchSpy=vi.spyOn(globalThis,'fetch');
    render(<Harness/>);
    open();
    await preparedSha();
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});