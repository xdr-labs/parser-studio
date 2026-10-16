import {describe,it,expect,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import {createDraft} from '../model';
import {preview} from '../parser';
import ChatGPTAssist from './ChatGPTAssist';

describe('ChatGPT Assisted Parser beginner defaults',()=>{
  it('pre-fills a safe redacted example so a first-time user does not start from a blank box',()=>{
    const sample='date=2026-10-15 time=00:04:12 devname="FGT-EDGE01" action="blocked" srcip=10.0.0.10 dstip=10.0.0.20 dstport=443';
    const draft={...createDraft(),format:'kv' as const};
    const suite=preview(sample,draft);
    render(<ChatGPTAssist draft={draft} setDraft={vi.fn()} sample={sample}
      setSample={vi.fn()} suite={suite} pending={false}
      runPreview={async()=>suite} onAutoParser={vi.fn()}/>);
    const redacted=screen.getByLabelText('ChatGPT redacted examples') as HTMLTextAreaElement;
    expect(redacted.value).toContain('EXAMPLE-FW');
    expect(redacted.value).toContain('192.0.2.10');
    expect(redacted.value).toContain('[REDACTED]');
    expect(redacted.value).not.toContain('10.0.0.10');
    expect(screen.getByRole('button',{name:'Reset to safe example'})).toBeTruthy();
  });
});
