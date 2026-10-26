import {describe,expect,it,vi} from 'vitest';
import {useState} from 'react';
import {render,screen,fireEvent,act} from '@testing-library/react';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import ChatGPTAssist from './ChatGPTAssist';

describe('ChatGPT Assisted combined source UI',()=>{
  const groups=[
    {id:'type-threat',name:'Threat',sample:'event_type=threat action=blocked src_ip=10.11.1.1 dst_port=443 threat_score=9'},
    {id:'type-user',name:'User',sample:'event_type=user action=login src_ip=10.11.1.2 dst_port=443 username=somebody'},
  ];
  it('keeps producer information, two original log types, and one privacy warning without extra sharing editors',async()=>{
    const source=groups.map(group=>group.sample).join('\n');
    const draft={...createDraft(),format:'kv' as const};
    const onChangeNamedLogTypes=vi.fn();
    let actualDraft:ParserDraft=draft;
    function Harness(){
      const [current,setCurrent]=useState<ParserDraft>(draft);
      return <ChatGPTAssist draft={current} setDraft={next=>setCurrent(old=>{
        actualDraft=typeof next==='function'?next(old):next;
        return actualDraft;
      })}
        sample={source} setSample={vi.fn()}
        suite={preview(source,current)} pending={false}
        runPreview={async(candidate,text)=>preview(text??source,candidate)}
        onAutoParser={vi.fn()} namedLogTypes={groups}
        onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={onChangeNamedLogTypes}
        onExitNamedLogTypes={vi.fn()}/>;
    }
    await act(async()=>{render(<Harness/>);});
    expect(screen.getByLabelText('Parser product identity')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Parser manufacturer'),
      {target:{value:'Example Firewall Vendor'}});
    expect((screen.getByLabelText('Parser manufacturer') as HTMLInputElement).value)
      .toBe('Example Firewall Vendor');
    fireEvent.change(screen.getByLabelText('Parser product',{exact:true}),
      {target:{value:'Security Gateway'}});
    fireEvent.change(screen.getByLabelText('Parser product version'),
      {target:{value:'9.4'}});
    expect(actualDraft.vendor).toBe('Example Firewall Vendor');
    expect(actualDraft.name).toBe('Security Gateway');
    expect(actualDraft.version).toBe('9.4');
    expect(actualDraft.guided?.slug).toBe('example_firewall_vendor_security_gateway');
    fireEvent.change(screen.getByRole('spinbutton',{name:'Parser listener port'}),
      {target:{value:'6819'}});
    expect(actualDraft.guided?.receiver.port).toBe(6819);
    expect(screen.getByText('Generated .conf receiving port: 6819')).toBeTruthy();
    expect(screen.getByLabelText('Log type entry 1')).toBeTruthy();
    expect(screen.getByLabelText('Log type entry 2')).toBeTruthy();
    const combined=screen.getByLabelText('ChatGPT local sample logs') as HTMLTextAreaElement;
    expect(combined.readOnly).toBe(true);
    expect(combined.value).toContain('10.11.1.1');
    for(const index of [1,2])
      expect(screen.queryByLabelText('ChatGPT sharing example '+index)).toBeNull();
    expect(screen.queryByLabelText('ChatGPT redacted examples')).toBeNull();
    expect(screen.getByText(/ChatGPT prompt includes your original log text/i)).toBeTruthy();
    expect(screen.getByLabelText('Combined parser routing review')).toBeTruthy();
  });
  it('blocks prompt preparation if a named type is missing its original logs',()=>{
    const draft={...createDraft(),format:'kv' as const};
    render(<ChatGPTAssist draft={draft} setDraft={vi.fn()}
      sample={groups[0]!.sample} setSample={vi.fn()}
      suite={preview(groups[0]!.sample,draft)} pending={false}
      runPreview={async(candidate,text)=>preview(text??groups[0]!.sample,candidate)}
      onAutoParser={vi.fn()} namedLogTypes={[groups[0]!,{...groups[1]!,sample:''}]}
      onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={vi.fn()}
      onExitNamedLogTypes={vi.fn()}/>);
    expect((screen.getByRole('button',{name:'Prepare ChatGPT Prompt'}) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('Complete two or more valid named log types before preparing a combined parser.')).toBeTruthy();
  });
});
