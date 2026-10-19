import {describe,expect,it} from 'vitest';
import {createHash} from 'node:crypto';
import {createDraft} from '../model';
import {assembleNamedLogs,newNamedLogType} from './namedLogTypes';
import {prepareLocalVersion,verifyLocalVersion,
  sameLocalWorking,compareLocalVersions,restoredNamedSource} from './localWorkspaceHistory';

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
  it('verifies a prior valid named snapshot with old application-added separators and upgrades only the working copy',async()=>{
    const original=[
      newNamedLogType('a','Threat','{"event_type":"threat","user":"김민수"}\n'),
      newNamedLogType('b','User','{"event_type":"user","user":"山田"}\n'),
    ];
    // Earlier Parser Studio added a second LF even when the first type
    // already ended with one. Reproduce an authentic signed revision.
    const canonical=assembleNamedLogs(original).source;
    const oldSource=original[0]!.sample+'\n'+original[1]!.sample;
    const base=await prepareLocalVersion({
      datasetName:'Old named types',source:canonical,draft:createDraft(),logTypes:original,
    },'Legacy named V1');
    const legacy={...base,source:oldSource};
    legacy.sha256=createHash('sha256').update(JSON.stringify([
      legacy.contract,legacy.id,legacy.label,legacy.createdAt,legacy.datasetName,
      legacy.source,legacy.draft,legacy.logTypes,
    ])).digest('hex');
    expect(await verifyLocalVersion(legacy)).toBe(true);
    const restored=restoredNamedSource(legacy);
    expect(restored).toEqual({source:canonical,removedLegacySeparators:true});
    expect(restored.source).toBe(original.map(x=>x.sample).join(''));
    expect(base.logTypes).toEqual(original);
    // Never save fresh versions with the bad legacy assembly.
    await expect(prepareLocalVersion({
      datasetName:legacy.datasetName,source:oldSource,draft:legacy.draft,logTypes:original,
    },'New must not be legacy')).rejects.toThrow(/do not match/);
    expect(await verifyLocalVersion({...legacy,source:oldSource+'tampered'})).toBe(false);
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
