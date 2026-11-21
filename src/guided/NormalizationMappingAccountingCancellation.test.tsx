import {act,render,screen,waitFor} from '@testing-library/react';
import {describe,expect,it,vi} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import NormalizationMappingReview from './NormalizationMappingReview';

const deferred=vi.hoisted(()=>({resolvers:[] as Array<(value:any)=>void>}));
vi.mock('./losslessAccounting',async importOriginal=>{
  const actual=await importOriginal<typeof import('./losslessAccounting')>();
  return {...actual,accountLosslessSource:vi.fn(()=>new Promise(resolve=>deferred.resolvers.push(resolve)))};
});

describe('lossless accounting React cancellation',()=>{
  it('discards stale SHA-256 accounting after the selected sample changes',async()=>{
    const first='{"message":"old sample"}';
    const second='{"message":"new sample"}';
    const draft={...createDraft(),format:'json' as const};
    const props=(raw:string)=>(
      <NormalizationMappingReview draft={draft} setDraft={vi.fn()} suite={preview(raw,draft)}
        originalRawSample={raw} selected={0} setSelected={vi.fn()} pending={false} onBack={vi.fn()} onContinue={vi.fn()}/>
    );
    const view=render(props(first));
    await waitFor(()=>expect(deferred.resolvers).toHaveLength(1));
    view.rerender(props(second));
    await waitFor(()=>expect(deferred.resolvers).toHaveLength(2));
    const result=(hash:string)=>({sourceBytes:1,sourceSha256:hash.repeat(64),eventCount:1,events:[],
      structuralCounts:{FULL:0,PARTIAL:0,UNKNOWN:1,ERROR:0},normalizedPathCount:0,
      unaccountedEventIds:['event-1'],proof:'UNKNOWN' as const});
    await act(async()=>{deferred.resolvers[0]!(result('a'));});
    expect(screen.getByLabelText('Lossless source accounting')).not.toHaveTextContent('a'.repeat(64));
    await act(async()=>{deferred.resolvers[1]!(result('b'));});
    await waitFor(()=>expect(screen.getByLabelText('Lossless source accounting')).toHaveTextContent('bbbbbbbbbbbb'));
  });
});
