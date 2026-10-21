import {describe,it,expect,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import {createDraft} from '../model';
import {preview} from '../parser';
import ChatGPTAssist from './ChatGPTAssist';

describe('ChatGPT Assisted Parser beginner defaults',()=>{
  it('has exactly one source-log editor, one privacy warning and no redaction workflow',()=>{
    const sample='date=2026-10-15 time=00:04:12 devname="FGT-EDGE01" action="blocked" srcip=10.0.0.10 dstip=10.0.0.20 dstport=443';
    const draft={...createDraft(),format:'kv' as const};
    const suite=preview(sample,draft);
    render(<ChatGPTAssist draft={draft} setDraft={vi.fn()} sample={sample}
      setSample={vi.fn()} namedLogTypes={null}
      onEnableNamedLogTypes={vi.fn()} onChangeNamedLogTypes={vi.fn()}
      onExitNamedLogTypes={vi.fn()} suite={suite} pending={false}
      runPreview={async()=>suite} onAutoParser={vi.fn()}/>);
    expect(screen.getByLabelText('ChatGPT local sample logs')).toHaveProperty('value',sample);
    expect(screen.queryByLabelText('ChatGPT redacted examples')).toBeNull();
    expect(screen.queryByRole('button',{name:'Reset to safe example'})).toBeNull();
    expect(screen.queryByRole('button',{name:'Use current logs as an editable copy'})).toBeNull();
    expect(screen.getByText(/ChatGPT prompt includes your original log text/i)).toBeTruthy();
    expect(screen.getByRole('button',{name:'Prepare ChatGPT Prompt'})).toBeTruthy();
  });
});
