import {afterEach,describe,expect,it,vi} from 'vitest';
import {act,cleanup,fireEvent,render} from '@testing-library/react';
import {createDraft} from '../model';
import AutoParserLocalReplay from './AutoParserLocalReplay';

afterEach(()=>{cleanup();vi.useRealTimers();});

describe('Auto Parser local-only synthetic replay result',()=>{
  it('rotates only reviewed source, stops and revokes the in-memory plan on source edit',()=>{
    vi.useFakeTimers();
    const draft=createDraft();draft.format='json';
    const first=JSON.stringify({
      timestamp:'2020-01-02T03:04:05Z',action:'deny',
      src_ip:'10.0.0.4',username:'private.username',
      url:'https://sensitive.internal.example/case',
    });
    const sample=first+'\n'+JSON.stringify({action:'allow',src_ip:'10.0.0.5'});
    const {getByRole,getByLabelText,rerender,unmount}=render(
      <AutoParserLocalReplay sample={sample} draft={draft}/>);
    fireEvent.change(getByLabelText('Replay preview rate'),{target:{value:'10'}});
    fireEvent.click(getByRole('button',{name:'Start Local Preview'}));
    expect(getByRole('status').textContent).toContain('Preview running');
    expect(getByRole('status').textContent).toContain('Based on source event 1/2');
    const text=getByLabelText('Local synthetic replay output').textContent??'';
    expect(text).toContain('example.test/replay/');
    expect(text).toContain('demo_user_');
    expect(text).not.toContain('10.0.0.4');
    expect(text).not.toContain('sensitive.internal.example');
    act(()=>vi.advanceTimersByTime(150));
    expect(getByRole('status').textContent).toContain('Based on source event 2/2');
    expect(getByRole('status').textContent).toContain('2 synthetic events generated locally');
    fireEvent.click(getByRole('button',{name:'Stop Preview'}));
    expect(vi.getTimerCount()).toBe(0);
    act(()=>vi.advanceTimersByTime(500));
    expect(getByRole('status').textContent).toContain('2 synthetic events generated locally');
    fireEvent.click(getByRole('button',{name:'Start Local Preview'}));
    expect(vi.getTimerCount()).toBe(1);
    rerender(<AutoParserLocalReplay sample={sample+'\n'+first} draft={draft}/>);
    expect(getByRole('status').textContent).toContain('0 synthetic events generated locally');
    expect(getByRole('status').textContent).toContain('Preview stopped');
    expect(vi.getTimerCount()).toBe(0);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('clearly disables local replay of mixed CSV families without falsely starting a sender',()=>{
    const draft=createDraft();draft.format='mixed';
    const {getByRole,getByLabelText,queryByLabelText}=render(
      <AutoParserLocalReplay sample={'action=deny\\nsrc_ip,action'} draft={draft}/>);
    expect((getByRole('button',{name:'Start Local Preview'}) as HTMLButtonElement).disabled).toBe(true);
    expect((getByLabelText('Replay preview rate') as HTMLSelectElement).disabled).toBe(true);
    expect(getByLabelText('Local replay unsupported format notice').textContent)
      .toContain('not available for mixed or multi-line parser formats');
    expect(getByLabelText('Local synthetic replay status').textContent)
      .toContain('Nothing sent');
    expect(queryByLabelText('Local synthetic replay output')).toBeNull();
  });

  it('fails closed on malformed later records with no partial output or backend request',()=>{
    vi.useFakeTimers();
    const draft=createDraft();draft.format='json';
    const {getByRole,queryByLabelText,unmount}=render(
      <AutoParserLocalReplay sample={'{"action":"allow"}\naction=deny'} draft={draft}/>);
    fireEvent.click(getByRole('button',{name:'Start Local Preview'}));
    expect(getByRole('alert').textContent).toContain('Cannot start local replay');
    expect(getByRole('status').textContent).toContain('0 synthetic events generated locally');
    expect(queryByLabelText('Local synthetic replay output')).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
    unmount();
  });
});
