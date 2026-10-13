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
    fireEvent.click(getByRole('button',{name:'Start Local Replay'}));
    expect(getByRole('status').textContent).toContain('Running locally');
    expect(getByRole('status').textContent).toContain('Source 1/2');
    const text=getByLabelText('Local synthetic replay output').textContent??'';
    expect(text).toContain('example.test/replay/');
    expect(text).toContain('demo_user_');
    expect(text).not.toContain('10.0.0.4');
    expect(text).not.toContain('sensitive.internal.example');
    act(()=>vi.advanceTimersByTime(150));
    expect(getByRole('status').textContent).toContain('Source 2/2');
    expect(getByRole('status').textContent).toContain('Locally generated 2 events');
    fireEvent.click(getByRole('button',{name:'Stop Local Replay'}));
    expect(vi.getTimerCount()).toBe(0);
    act(()=>vi.advanceTimersByTime(500));
    expect(getByRole('status').textContent).toContain('Locally generated 2 events');
    fireEvent.click(getByRole('button',{name:'Start Local Replay'}));
    expect(vi.getTimerCount()).toBe(1);
    rerender(<AutoParserLocalReplay sample={sample+'\n'+first} draft={draft}/>);
    expect(getByRole('status').textContent).toContain('Locally generated 0 events');
    expect(getByRole('status').textContent).toContain('Stopped');
    expect(vi.getTimerCount()).toBe(0);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('fails closed on malformed later records with no partial output or backend request',()=>{
    vi.useFakeTimers();
    const draft=createDraft();draft.format='json';
    const {getByRole,queryByLabelText,unmount}=render(
      <AutoParserLocalReplay sample={'{"action":"allow"}\naction=deny'} draft={draft}/>);
    fireEvent.click(getByRole('button',{name:'Start Local Replay'}));
    expect(getByRole('alert').textContent).toContain('Cannot start local replay');
    expect(getByRole('status').textContent).toContain('Locally generated 0 events');
    expect(queryByLabelText('Local synthetic replay output')).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
    unmount();
  });
});
