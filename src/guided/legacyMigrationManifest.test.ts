import {describe,it,expect} from 'vitest';
import {readFileSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';

type Entry={legacySuite:string;status:
 'MIGRATED_CURRENT'|'SUPERSEDED_TWO_PATH'|'GATED_EXTERNAL'|'P1_REMAINING';replacement:string};
type Manifest={contract:string;legacySuiteCount:number;ownerDecision:string;
 releaseRule:string;entries:Entry[]};

describe('retired Wizard/Workbench behavioral migration manifest',()=>{
 it('accounts for every archived browser suite without counting it as current PASS',()=>{
  const root=resolve(process.cwd(),'tests/legacy-removed-ui');
  const archived=readdirSync(root).filter(x=>x.endsWith('.spec.ts')).sort();
  const manifest=JSON.parse(readFileSync(resolve(root,'migration-manifest.json'),'utf8')) as Manifest;
  expect(manifest.contract).toBe('parser-studio.legacy-ui-migration.v1');
  expect(manifest.legacySuiteCount).toBe(archived.length);
  expect(manifest.entries.map(x=>x.legacySuite).sort()).toEqual(archived);
  expect(new Set(manifest.entries.map(x=>x.legacySuite)).size).toBe(archived.length);
  expect(manifest.entries.every(x=>x.replacement.length>=20)).toBe(true);
  expect(manifest.releaseRule).toContain('never count as current PASS');
 });
 it('has no undispositioned legacy behavior; remaining non-migrated behavior is owner-superseded or external-gated',()=>{
  const manifest=JSON.parse(readFileSync(resolve(process.cwd(),
   'tests/legacy-removed-ui/migration-manifest.json'),'utf8')) as Manifest;
  const allowed=new Set(['MIGRATED_CURRENT','SUPERSEDED_TWO_PATH','GATED_EXTERNAL','P1_REMAINING']);
  expect(manifest.entries.every(x=>allowed.has(x.status))).toBe(true);
  const pending=manifest.entries.filter(x=>x.status==='P1_REMAINING').map(x=>x.legacySuite);
  expect(pending).toEqual([]);
  expect(manifest.entries.some(x=>x.status==='MIGRATED_CURRENT')).toBe(true);
  expect(manifest.entries.some(x=>x.status==='SUPERSEDED_TWO_PATH')).toBe(true);
  expect(manifest.entries.some(x=>x.status==='GATED_EXTERNAL')).toBe(true);
 });
});
