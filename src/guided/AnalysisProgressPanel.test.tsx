import {act,cleanup,fireEvent,render,screen} from '@testing-library/react';
import {afterEach,describe,expect,it,vi} from 'vitest';
import AnalysisProgressPanel from './AnalysisProgressPanel';

describe('truthful analysis waiting state',()=>{
  afterEach(()=>{cleanup();vi.useRealTimers();});
  it('shows actual bytes and elapsed time without inventing a completion count or percentage',()=>{
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-20T12:00:00Z'));
    const progress={startedAt:Date.now(),sourceBytes:30400,phase:'analyzing' as const};
    const onCancel=vi.fn();
    const {rerender}=render(<AnalysisProgressPanel progress={progress} interruption={null} onCancel={onCancel}/>);
    expect(screen.getByRole('status')).toHaveTextContent('Analyzing source');
    expect(screen.getByText('30,400 UTF-8 bytes · 0s elapsed')).toBeVisible();
    expect(screen.getByRole('progressbar')).not.toHaveAttribute('value');
    expect(screen.getByRole('progressbar')).not.toHaveAttribute('aria-valuenow');
    act(()=>vi.advanceTimersByTime(3000));
    expect(screen.getByText('30,400 UTF-8 bytes · 3s elapsed')).toBeVisible();
    rerender(<AnalysisProgressPanel progress={{...progress,phase:'validating'}} interruption={null} onCancel={onCancel}/>);
    expect(screen.getByRole('status')).toHaveTextContent('Checking analysis results');
    expect(screen.getByText('30,400 UTF-8 bytes · 3s elapsed')).toBeVisible();
    fireEvent.click(screen.getByRole('button',{name:'Cancel analysis'}));
    expect(onCancel).toHaveBeenCalledOnce();
    rerender(<AnalysisProgressPanel progress={null} interruption="cancelled" onCancel={onCancel}/>);
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('status')).toHaveTextContent('Analysis canceled. Your logs are unchanged.');
  });
});
