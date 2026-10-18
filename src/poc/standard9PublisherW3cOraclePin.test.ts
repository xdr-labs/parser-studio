import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';

const pathToManifest=path.join(__dirname,
  '../../scripts/poc/standard9PublisherW3cExample.pinned.json');
const frozen=fs.readFileSync(pathToManifest);
const sha='76b37af28dee2538121801320269b6152ff8199a169f458021d6d5762a5d64e5';
type Field={rowIndex:number;ordinal:number;name:string;startByte:number;endByte:number;
 lexemeSha256:string;decodedSha256:string};
type Oracle={canonicalSourceSha256:string;canonicalSourceBytes:number;
 fieldClaims:number;rows:number;physicalLines:number;publisherExpectedFields:Field[][];
 nativeTarget:string;sourceClass:string};
describe('STD-9 publisher-original W3C oracle pinned and private',()=>{
 it('validates only the committed expected digest provenance, never fabricates source',()=>{
   expect(createHash('sha256').update(frozen).digest('hex')).toBe(sha);
   const manifest=JSON.parse(frozen.toString('utf8')) as Oracle;
   expect(manifest.sourceClass).toBe('PUBLISHER_AUTHORED_STANDARDS_EXAMPLE_NOT_PRODUCTION_WIRE');
   expect(manifest.publisherExpectedFields).toHaveLength(4);
   expect(manifest.rows).toBe(4);
   expect(manifest.fieldClaims).toBe(12);
   expect(manifest.physicalLines).toBe(7);
   expect(manifest.nativeTarget).toBe('NOT_VERIFIED');
   expect(manifest.canonicalSourceSha256).toMatch(/^[a-f0-9]{64}$/);
   expect(manifest.canonicalSourceBytes).toBe(172);
   for(const [row,fields] of manifest.publisherExpectedFields.entries()){
     expect(fields).toHaveLength(3);
     for(const [index,item] of fields.entries()){
       expect(item.rowIndex).toBe(row);
       expect(item.ordinal).toBe(index);
       expect(item.name).toBe(['time','cs-method','cs-uri'][index]);
       expect(item.startByte).toBeLessThan(item.endByte);
       expect(item.lexemeSha256).toMatch(/^[a-f0-9]{64}$/);
     }
   }
 });
});
