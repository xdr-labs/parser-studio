import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import {extractFields} from '../parser';
import type {ParserDraft} from '../model';
import {parseJsonObjectBatch} from '../jsonBatch';
import {parseJsonTextSequence} from '../jsonTextSequence';
import {parseNdjsonObjectStream} from '../ndjsonStream';
import {extractStructuredFamily} from '../structuredFamilies';
import {inspectSourceCompleteness} from './standardSourceCompletenessGate';
const filename=path.join(__dirname,'../../scripts/poc/standardJsonSourceSafety.pinned.json');
const frozen=fs.readFileSync(filename);
const sha='e30314ba68ec1165e79eff85f05a1cfa96abeb5ba0a614816e1d405d64e1054c';
if(createHash('sha256').update(frozen).digest('hex')!==sha)
  throw Error('Independent RFC8259/RFC7464 JSON source oracle changed');
type TestCase={
  id:string;wire:string;expectedDisposition:'review_lexical'|'review_uncertain'|'abstain';
  issues:string[];sourceBytes:number;sourceSha256:string;expectedSourceValue?:string;
};
const {cases}=JSON.parse(frozen.toString('utf8')) as {cases:TestCase[]};
const syslog='<34>1 2026-10-18T12:34:56Z edge app 1 TEST - ';

describe('P0-STD-5 JSON source-fidelity safety across authoring & stream surfaces',()=>{
  it('pins independently authored normative truth and denominators',()=>{
    expect(cases).toHaveLength(14);
    expect(cases.filter(x=>x.expectedDisposition==='review_lexical')).toHaveLength(4);
    expect(cases.filter(x=>x.expectedDisposition==='review_uncertain')).toHaveLength(7);
    expect(cases.filter(x=>x.expectedDisposition==='abstain')).toHaveLength(3);
  });
  it.each(cases)('prevents any unsupported JSON source from completing: $id',c=>{
    const bytes=new TextEncoder().encode(c.wire);
    expect(bytes.length).toBe(c.sourceBytes);
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(c.sourceSha256);
    const audit=inspectSourceCompleteness(c.wire,'json');
    const state={
      REVIEW_ONLY_LEXICAL:'review_lexical',
      REVIEW_ONLY_UNCERTAIN:'review_uncertain',
      ABSTAIN_UNSAFE:'abstain',
    } as const;
    expect(state[audit.disposition]).toBe(c.expectedDisposition);
    expect(audit.issues).toEqual(c.issues);
    expect(audit.sourceBytes).toBe(c.sourceBytes);
    expect(audit.raw).toBe(c.wire);
    expect(audit.autoPromoted).toBe(false);
    expect(audit.completeSourceClaim).toBe(false);
    expect(audit.nativeStellar).toBe('NOT_VERIFIED');

    const acceptable=c.expectedDisposition==='review_lexical';
    const single=extractFields(c.wire,'json',{} as ParserDraft);
    const batch=parseJsonObjectBatch('['+c.wire+']');
    const seq=parseJsonTextSequence('\u001e'+c.wire+'\n');
    const ndjson=parseNdjsonObjectStream(c.wire+'\n');
    const wrapped=extractStructuredFamily(syslog+c.wire,'syslog_rfc5424','json');
    expect(single.errors.length===0).toBe(acceptable);
    expect(batch.ok).toBe(acceptable);
    expect(seq.ok).toBe(acceptable);
    expect(ndjson.ok).toBe(acceptable);
    expect(wrapped.errors.length===0).toBe(acceptable);
    if(acceptable){
      expect(batch.ok&&batch.batch.records).toHaveLength(1);
      expect(seq.ok&&seq.sequence.records).toHaveLength(1);
      expect(ndjson.ok&&ndjson.stream.rawRecords).toEqual([c.wire]);
      expect(wrapped.fields.body).toEqual(single.fields);
      expect(JSON.stringify(single.fields)).toContain(c.expectedSourceValue!);
    }else {
      expect(audit.namedRawFields).toEqual([]);
    }
  });
});
