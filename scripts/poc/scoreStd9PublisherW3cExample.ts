/**
 * Publisher-authored standards example scoring, private original only.
 * Does not certify manufacturer wire capture or native Stellar behavior.
 */
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {parseW3cLogBlock} from '../../src/w3cTabular';

const digest=(raw:Uint8Array|string)=>createHash('sha256').update(raw).digest('hex');
const expectedOracleSha='76b37af28dee2538121801320269b6152ff8199a169f458021d6d5762a5d64e5';
const manifest=fs.readFileSync('scripts/poc/standard9PublisherW3cExample.pinned.json');
if(digest(manifest)!==expectedOracleSha)throw Error('Publisher W3C frozen independent oracle drift');
type Field={
 rowIndex:number;ordinal:number;name:string;startByte:number;endByte:number;
 lexemeSha256:string;decodedSha256:string;
};
type Manifest={
 canonicalSourceSha256:string;canonicalSourceBytes:number;
 rows:number;physicalLines:number;fieldClaims:number;
 publisherExpectedFields:Field[][];
 sourceClass:string;nativeTarget:'NOT_VERIFIED';
};
const answer=JSON.parse(manifest.toString('utf8')) as Manifest;
const privateFile=path.join(os.homedir(),
  '.local/state/parserstudio-std9-publisher-w3c-20261018/w3c-efl-publisher-example.raw');
if(!fs.existsSync(privateFile))throw Error('Private publisher original is absent: UNSCORABLE');
const original=fs.readFileSync(privateFile);
if(digest(original)!==answer.canonicalSourceSha256||original.length!==answer.canonicalSourceBytes)
  throw Error('Pinned publisher example original byte source drift');
const parsed=parseW3cLogBlock(new TextDecoder('utf-8',{fatal:true}).decode(original));
const report={
  scope:'PUBLISHER_PUBLISHED_EXAMPLE_ONLY_NOT_PRODUCTION_WIRE_OR_NATIVE',
  originalSha256:digest(original),sourceBytes:original.length,
  expectedEvents:answer.rows,expectedClaims:answer.fieldClaims,
  tp:0,fp:0,fn:0,exactEvents:0,originalByteDrift:0,
  parserOk:parsed.ok,nativeTarget:'NOT_VERIFIED',
  completeEventAccuracy:'UNSCORABLE',
  historicalRegressionRelabeled:false,
};
if(parsed.ok){
  if(parsed.block.rows.length!==answer.rows||
     parsed.block.physicalLines!==answer.physicalLines||
     parsed.block.sourceBytes!==answer.canonicalSourceBytes)
    throw Error('Publisher W3C physical record accounting drift');
  const seen=new Set<string>();
  for(const oracle of answer.publisherExpectedFields){
    const rowNumber=oracle[0]!.rowIndex;
    const observed=parsed.block.rowFieldSpans[rowNumber]||[];
    const actual=parsed.block.rows[rowNumber]||{};
    let exact=true;
    for(const expected of oracle){
      const key=expected.rowIndex+'/'+expected.ordinal;
      const got=observed[expected.ordinal];
      const value=actual[expected.name];
      const replay=got?original.subarray(got.startByte,got.endByte):new Uint8Array();
      const correct=got?.name===expected.name&&
        got.startByte===expected.startByte&&got.endByte===expected.endByte&&
        digest(got.rawLexeme)===expected.lexemeSha256&&
        digest(replay)===expected.lexemeSha256&&
        typeof value==='string'&&digest(value)===expected.decodedSha256;
      if(correct){report.tp++;seen.add(key);}
      else {report.fn++;exact=false;}
      if(got&&new TextDecoder('utf8',{fatal:true}).decode(replay)!==got.rawLexeme)
        report.originalByteDrift++;
    }
    if(exact)report.exactEvents++;
  }
  const observedCount=parsed.block.rowFieldSpans.flat().length;
  report.fp=observedCount-report.tp;
}else report.fn=answer.fieldClaims;
console.log('STD9_PUBLISHER_ORIGINAL_SOURCE_SCORE '+JSON.stringify(report));
if(report.fn||report.fp||report.tp!==answer.fieldClaims||
  report.exactEvents!==answer.rows||report.originalByteDrift)
  process.exitCode=1;
