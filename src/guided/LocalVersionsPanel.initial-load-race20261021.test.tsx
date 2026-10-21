import {act,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {beforeEach,describe,expect,it,vi} from 'vitest';
import {createDraft} from '../model';
import type {LocalVersion,LocalWorkingCopy,VersionList} from './localWorkspaceHistory';
import LocalVersionsPanel from './LocalVersionsPanel';

// Force the first asynchronous IndexedDB list to finish AFTER two successful
// local saves and manual A/B selection. A stale list must never reset the
// user's chosen comparison or discard the newer saved versions.
const storage=vi.hoisted(()=>({
  calls:0,
  snapshots:[] as LocalVersion[],
  finishFirst:null as null|((value:VersionList)=>void),
}));
vi.mock('./localWorkspaceHistory',async()=>{
  const real=await vi.importActual<typeof import('./localWorkspaceHistory')>('./localWorkspaceHistory');
  return {...real,
    listLocalVersions:vi.fn(async():Promise<VersionList>=>{
      storage.calls++;
      if(storage.calls===1)return new Promise<VersionList>(resolve=>{storage.finishFirst=resolve;});
      return {versions:storage.snapshots.slice().reverse(),rejected:0};
    }),
    saveLocalVersion:vi.fn(async(copy:LocalWorkingCopy,label:string):Promise<LocalVersion>=>{
      const saved:LocalVersion={
        ...(JSON.parse(JSON.stringify(copy)) as LocalWorkingCopy),
        contract:'parser-studio.browser-version.v1',
        id:'v'+(storage.snapshots.length+1),
        label,createdAt:'2026-10-20T15:00:00.000Z',sha256:'a'.repeat(64),
      };
      storage.snapshots.push(saved);
      return saved;
    }),
  };
});

describe('desktop local version comparison under pending initial browser-storage reads',()=>{
  beforeEach(()=>{storage.calls=0;storage.snapshots=[];storage.finishFirst=null;});

  it('preserves manual A/B selection and named event-type differences after a late first read',async()=>{
    const source='{"event_type":"user","username":"김민수"}';
    const draft=createDraft();
    const a:LocalWorkingCopy={
      datasetName:'Original security events',source,draft,
      logTypes:[{id:'one',name:'User',sample:source}],
    };
    const b:LocalWorkingCopy={
      ...a,logTypes:[{id:'one',name:'Renamed User',sample:source}],
    };
    const {rerender}=render(<LocalVersionsPanel working={a} onRestore={vi.fn()} onClose={vi.fn()}/>);
    await waitFor(()=>expect(storage.calls).toBe(1));

    fireEvent.change(screen.getByLabelText('Local version name'),{target:{value:'Three source types'}});
    fireEvent.click(screen.getByRole('button',{name:'Save Version'}));
    await waitFor(()=>expect(within(screen.getByLabelText('Saved local versions')).getByText('Three source types')).toBeTruthy());
    await waitFor(()=>expect(screen.getByLabelText('Compare version A')).toHaveValue('v1'));

    rerender(<LocalVersionsPanel working={b} onRestore={vi.fn()} onClose={vi.fn()}/>);
    fireEvent.change(screen.getByLabelText('Local version name'),{target:{value:'Renamed type'}});
    fireEvent.click(screen.getByRole('button',{name:'Save Version'}));
    await waitFor(()=>expect(within(screen.getByLabelText('Saved local versions')).getByText('Renamed type')).toBeTruthy());

    fireEvent.change(screen.getByLabelText('Compare version A'),{target:{value:'v1'}});
    fireEvent.change(screen.getByLabelText('Compare version B'),{target:{value:'v2'}});
    expect(screen.getByLabelText('Compare version A')).toHaveValue('v1');
    expect(screen.getByLabelText('Compare version B')).toHaveValue('v2');
    expect(screen.getByLabelText('Local version differences'))
      .toHaveTextContent('Named log type samples / labels');

    await act(async()=>{storage.finishFirst!({
      versions:storage.snapshots.slice().reverse(),rejected:0,
    });});
    // Old code reset the selected Version A to v2 here even after the user's
    // explicit choice, producing a false "No differences" result.
    expect(screen.getByLabelText('Compare version A')).toHaveValue('v1');
    expect(screen.getByLabelText('Compare version B')).toHaveValue('v2');
    expect(screen.getByLabelText('Local version differences'))
      .toHaveTextContent('Named log type samples / labels');
    expect(within(screen.getByLabelText('Saved local versions')).getByText('Three source types')).toBeTruthy();
    expect(within(screen.getByLabelText('Saved local versions')).getByText('Renamed type')).toBeTruthy();
  });
  it('keeps baseline comparison A selected after subsequent saves instead of silently comparing V2 against itself',async()=>{
    const source='{"event_type":"user","username":"김민수"}';
    const draft=createDraft();
    const baseline:LocalWorkingCopy={
      datasetName:'Reviewed examples',source,draft,
      logTypes:[{id:'one',name:'User',sample:source}],
    };
    const revised:LocalWorkingCopy={
      ...baseline,
      draft:{...draft,mappings:[
        {id:'source',source:'src_ip',target:'srcip',type:'ip'},
      ]},
      logTypes:[{id:'one',name:'Renamed User',sample:source}],
    };
    const {rerender}=render(<LocalVersionsPanel working={baseline}
      onRestore={vi.fn()} onClose={vi.fn()}/>);
    await waitFor(()=>expect(storage.calls).toBe(1));
    fireEvent.change(screen.getByLabelText('Local version name'),{target:{value:'Baseline V1'}});
    fireEvent.click(screen.getByRole('button',{name:'Save Version'}));
    await waitFor(()=>expect(within(screen.getByLabelText('Saved local versions'))
      .getByText('Baseline V1')).toBeTruthy());
    expect(screen.getByLabelText('Compare version A')).toHaveValue('v1');

    rerender(<LocalVersionsPanel working={revised} onRestore={vi.fn()} onClose={vi.fn()}/>);
    fireEvent.change(screen.getByLabelText('Local version name'),{target:{value:'Updated V2'}});
    fireEvent.click(screen.getByRole('button',{name:'Save Version'}));
    await waitFor(()=>expect(within(screen.getByLabelText('Saved local versions'))
      .getByText('Updated V2')).toBeTruthy());
    // A save is not a decision to replace the left-hand comparison choice.
    // Old behavior setLeft(saved.id), causing an A=B false "No differences".
    expect(screen.getByLabelText('Compare version A')).toHaveValue('v1');
    fireEvent.change(screen.getByLabelText('Compare version B'),{target:{value:'v2'}});
    expect(screen.getByLabelText('Local version differences'))
      .toHaveTextContent('Named log type samples / labels');
    expect(screen.getByLabelText('Local version differences'))
      .toHaveTextContent('Field mappings');
  });

});
