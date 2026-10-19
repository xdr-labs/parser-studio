import {describe,it,expect,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import {createDraft} from '../model';
import {preview} from '../parser';
import DeclaredRelayProfilePanel from './DeclaredRelayProfilePanel';
import ReviewedEventProfilesPanel from './ReviewedEventProfilesPanel';

describe('review controls initialized from saved local version',()=>{
  it('shows the saved relay allowlist and hop limit without reapplying or modifying source',()=>{
    const draft={...createDraft(),format:'json' as const,
      forwarder:{maxHops:2 as const,relayHosts:['relay01','relay02']}};
    const source='<134>Jan 16 15:19:05 relay01 fw: {"kind":"threat","username":"김민수"}';
    const before=structuredClone(draft);
    render(<DeclaredRelayProfilePanel sample={source} draft={draft} setDraft={vi.fn()}/>);
    expect((screen.getByLabelText('Declared relay hostname list') as HTMLInputElement).value)
      .toBe('relay01,relay02');
    expect((screen.getByLabelText('Maximum declared relay hops') as HTMLSelectElement).value)
      .toBe('2');
    expect(draft).toEqual(before);
    expect(source).toContain('김민수');
  });

  it('shows the saved non-default event family discriminator rather than event_type',()=>{
    const source=[
      '{"kind":"threat","action":"deny"}',
      '{"kind":"user","username":"山田"}',
    ].join('\n');
    const draft={...createDraft(),format:'json' as const,
      eventProfiles:{discriminator:'kind',unknown:'reject' as const,variants:[
        {name:'threat',equals:'threat',mappings:[]},
        {name:'user',equals:'user',mappings:[]},
      ]}};
    const suite=preview(source,draft);
    render(<ReviewedEventProfilesPanel
      suite={suite} draft={draft} setDraft={vi.fn()} source={source}
      pending={false}/>);
    expect((screen.getByLabelText('One-parser event discriminator') as HTMLInputElement).value)
      .toBe('kind');
  });
});
