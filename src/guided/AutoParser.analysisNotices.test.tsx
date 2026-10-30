import type {ComponentProps} from 'react';
import {afterEach,describe,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {createDraft} from '../model';
import AutoParser from './AutoParser';
import {newNamedLogType} from './namedLogTypes';

const GENERIC=/Parser Studio could not complete analysis/;
const line=(index:number)=>`<34>Oct 30 10:00:00 host sshd[${index}]: Accepted password for user${index} from 192.0.2.1 port 22 ssh2`;
const lines=(count:number)=>Array.from({length:count},(_,index)=>line(index)).join('\n')+'\n';

function props(sample:string,extra:Partial<ComponentProps<typeof AutoParser>>={}):ComponentProps<typeof AutoParser>{
  return {
    draft:createDraft(),setDraft:vi.fn(),sample,setSample:vi.fn(),
    namedLogTypes:null,onEnableNamedLogTypes:vi.fn(),onChangeNamedLogTypes:vi.fn(),onExitNamedLogTypes:vi.fn(),
    datasetName:'Notice fixture',setDatasetName:vi.fn(),suite:undefined,pending:false,
    runPreview:vi.fn(),onChatGPT:vi.fn(),advanced:false,...extra,
  };
}

afterEach(()=>{cleanup();vi.unstubAllGlobals();});

describe('Analyze Logs explains why it cannot run',()=>{
  it('does not send a sample larger than 64 KiB and says so instead of offering a retry',async()=>{
    const request=vi.fn(async()=>new Response('{}',{status:200}));
    vi.stubGlobal('fetch',request);
    const big=Array.from({length:700},(_,index)=>line(index)+' '+'x'.repeat(20)).join('\n')+'\n';
    expect(new TextEncoder().encode(big).byteLength).toBeGreaterThan(64*1024);
    render(<AutoParser {...props(big)}/>);
    fireEvent.click(screen.getByRole('button',{name:'Analyze Logs'}));
    await waitFor(()=>expect(screen.getAllByText(/Analysis was not started.*larger than 64 KiB/).length).toBe(1));
    expect(request).not.toHaveBeenCalled();
    expect(screen.queryByText(GENERIC)).toBeNull();
    expect(screen.queryByText(/Analyzing source/)).toBeNull();
  });

  it('still analyzes more than 500 physical lines under 64 KiB because events can span lines',async()=>{
    const request=vi.fn(async()=>new Response('{}',{status:200}));
    vi.stubGlobal('fetch',request);
    const text=Array.from({length:600},(_,index)=>'a'+index).join('\n')+'\n';
    render(<AutoParser {...props(text)}/>);
    fireEvent.click(screen.getByRole('button',{name:'Analyze Logs'}));
    await waitFor(()=>expect(request).toHaveBeenCalled());
    expect(screen.queryByText(/Analysis was not started/)).toBeNull();
  });

  it('shows only the specific reason when a log type is incomplete',async()=>{
    const request=vi.fn(async()=>new Response('{}',{status:200}));
    vi.stubGlobal('fetch',request);
    const types=[newNamedLogType('a','Auth',lines(2)),newNamedLogType('b','Extra','')];
    render(<AutoParser {...props(lines(2),{namedLogTypes:types})}/>);
    fireEvent.click(screen.getByRole('button',{name:'Analyze Logs'}));
    await waitFor(()=>expect(screen.getAllByText(/Every log type needs a unique name and at least one sample/).length).toBe(1));
    expect(request).not.toHaveBeenCalled();
    expect(screen.queryByText(GENERIC)).toBeNull();
  });

  it('keeps the retry advice for a real analysis failure',async()=>{
    vi.stubGlobal('fetch',vi.fn(async()=>{throw new Error('offline');}));
    render(<AutoParser {...props(lines(2))}/>);
    fireEvent.click(screen.getByRole('button',{name:'Analyze Logs'}));
    await waitFor(()=>expect(screen.getAllByText(GENERIC).length).toBe(1));
  });
});
