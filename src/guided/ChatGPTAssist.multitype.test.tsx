import {describe,expect,it,vi} from 'vitest';
import {render,screen,fireEvent,act} from '@testing-library/react';
import {createDraft} from '../model';
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
    const setDraft=vi.fn(),onChangeNamedLogTypes=vi.fn();
    await act(async()=>{render(<ChatGPTAssist draft={draft} setDraft={setDraft}
      sample={source} setSample={vi.fn()}
      suite={preview(source,draft)} pending={false}
      runPreview={async(candidate,text)=>preview(text??source,candidate)}
      onAutoParser={vi.fn()} namedLogTypes={groups}
      onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={onChangeNamedLogTypes}
      onExitNamedLogTypes={vi.fn()}/>);});
    expect(screen.getByLabelText('Log-generating solution information')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('ChatGPT solution vendor'),
      {target:{value:'Example Firewall Vendor'}});
    expect((screen.getByLabelText('ChatGPT solution vendor') as HTMLInputElement).value)
      .toBe('Example Firewall Vendor');
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
