import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {assembleNamedLogs,newNamedLogType} from './namedLogTypes';
import {prepareLocalVersion,verifyLocalVersion,
  sameLocalWorking,compareLocalVersions} from './localWorkspaceHistory';

describe('named log type browser-local checkpoints',()=>{
  const logs=[
    newNamedLogType('a','Threat','{"event_type":"threat","actor":"김민수"}'),
    newNamedLogType('b','User','{"event_type":"user","actor":"山田"}'),
  ];
  it('saves and verifies explicit log type labels together with the exact source bytes',async()=>{
    const source=assembleNamedLogs(logs).source;
    const working={datasetName:'Multi-type',source,draft:createDraft(),logTypes:logs};
    const version=await prepareLocalVersion(working,'All types V1');
    expect(version.logTypes).toEqual(logs);
    expect(await verifyLocalVersion(version)).toBe(true);
    expect(await verifyLocalVersion({...version,logTypes:[
      {...logs[0]!,name:'Altered'},logs[1]!,
    ]})).toBe(false);
    expect(await verifyLocalVersion({...version,source:source.replace('김민수','김민수2')}))
      .toBe(false);
    await expect(prepareLocalVersion({...working,logTypes:[logs[0]!]},'Dropped user'))
      .rejects.toThrow(/do not match/);
  });
  it('distinguishes type-label edits from raw-log changes and retains legacy snapshots',async()=>{
    const a={source:assembleNamedLogs(logs).source,datasetName:'Multi',draft:createDraft(),logTypes:logs};
    const b={...a,logTypes:logs.map((row,i)=>i===0?{...row,name:'Alert'}:row)};
    expect(sameLocalWorking(a,b)).toBe(false);
    expect(compareLocalVersions(a,b).changes).toContain('Named log type samples / labels');
    expect(compareLocalVersions(a,b).sourceChanged).toBe(false);
    const old=await prepareLocalVersion({datasetName:'Legacy',source:a.source,draft:a.draft},'Legacy');
    expect(await verifyLocalVersion(old)).toBe(true);
    expect(old.logTypes).toBeUndefined();
  });
});
