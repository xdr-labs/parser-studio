import {expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {createHash,webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import AutoParserAIReview from './AutoParserAIReview';

// Component tests use a deterministic parser simulation, never browser workers.
vi.mock('../previewWorkerClient',()=>({
 runInWorker:async(raw:string,draft:import('../model').ParserDraft)=>
   (await import('../parser')).preview(raw,draft),
}));
import type {MultiPassBatchPreview} from './multipassPreviewClient';


function batchEvidence(source:string,valuesByEvent:string[][]):MultiPassBatchPreview{
 const lines=source.split('\n');let cursor=0;
 const events=lines.map((raw,index)=>{
  const startByte=cursor,endByte=startByte+new TextEncoder().encode(raw).byteLength;
  cursor=endByte+(index<lines.length-1?1:0);
  const spans=(valuesByEvent[index]??[]).map((value,position)=>{
   const charStart=raw.indexOf(value);
   if(charStart<0)throw new Error('test evidence value missing');
   const byteStart=new TextEncoder().encode(raw.slice(0,charStart)).byteLength;
   const byteEnd=byteStart+new TextEncoder().encode(value).byteLength;
   return {path:'field_'+position,startByte:byteStart,endByte:byteEnd};
  });
  return {index,startByte,endByte,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1' as const,status:'PARTIAL' as const,
   syntax:'TEST_EVIDENCE',sourceSha256:'0'.repeat(64),sourceBytes:endByte-startByte,
   fields:{},spans,residuals:[],issues:[],nativeVerified:false as const,targetVerified:false as const,
  }};
 });
 const separators=events.slice(0,-1).map(event=>({
  startByte:event.endByte,endByte:event.endByte+1,kind:'WHITESPACE' as const,
 }));
 return {contract:'parser-studio.multipass-source-batch-preview.v0.1',
  sourceSha256:'0'.repeat(64),sourceBytes:new TextEncoder().encode(source).byteLength,
  eventCount:events.length,events,separators,nativeVerified:false,targetVerified:false};
}


it('accepts source values preserved by reviewed enrichment outputs',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='allow,198.51.100.10\ndeny,203.0.113.4';
 const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^(?<pair>[^,]+,[^,]+)$'},
   {op:'map_field',source:'pair',target:'custom.buffer',data_type:'string',group:'top_fields'},
   {op:'split_field',source:'custom.buffer',delimiter:',',targets:['custom.action','custom.src_ip']},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['allow','198.51.100.10'],['deny','203.0.113.4']]}
  holdoutEvidenceRequester={async()=>batchEvidence(holdout,
   [['allow','192.0.2.10'],['deny','192.0.2.11']])}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/Fix passed: full parser recovery/)).toBeTruthy();
 fireEvent.click(screen.getByRole('checkbox',{name:'Approve tested fix'}));
 fireEvent.click(screen.getByRole('button',{name:'Apply Verified Fix'}));
 await waitFor(()=>expect(apply).toHaveBeenCalledTimes(1));
 vi.unstubAllGlobals();
});

it('rejects recovery when Funnel holdout values would disappear despite browser holdout success',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='allow,198.51.100.10';
 const holdout='allow,192.0.2.10\nallow,192.0.2.11';
 // Owner decision Q3-1 keeps every capture a reply leaves unmapped (src/unmappedFields.ts), so this recipe loses
 // source text the one way a recovery still can: it reads that text as a regex literal outside any capture.
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^allow,(?<src_ip>[^,]+)$'},
   {op:'map_field',source:'src_ip',target:'custom.src_ip',data_type:'string',group:'vendor_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['198.51.100.10']]}
  holdoutEvidenceRequester={async()=>batchEvidence(holdout,
   [['allow','192.0.2.10'],['allow','192.0.2.11']])}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/additional test event 1 would lose 1 of 2 source values that must be preserved/)).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Apply Verified Fix'})).toBeNull();
 expect(apply).not.toHaveBeenCalled();
 vi.unstubAllGlobals();
});

it('accepts exact lossless Generic Structural source projection for protected values and residuals',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='<142>May 10 15:19:05 WatchGuard-Firebox (2024-05-10T09:49:05) firewall: msg_id="3000-0152" IPv4 source route attack from 10.0.1.34 detected. (IPS)';
 const holdout='<142>May 10 15:19:06 WatchGuard-Firebox (2024-05-10T09:49:06) firewall: msg_id="3000-0153" IPv4 source route attack from 10.0.1.35 detected. (IPS)\n<142>May 10 15:19:07 WatchGuard-Firebox (2024-05-10T09:49:07) firewall: msg_id="3000-0154" IPv4 source route attack from 10.0.1.36 detected. (IPS)';
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'generic_structural',bodyFormat:'generic_structural',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_generic_structural'},
   {op:'map_field',source:'watchguard_message.msg_id',target:'custom.msg_id',data_type:'string',group:'vendor_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="partial" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['3000-0152','10.0.1.34']]}
  protectedResidualTextByEvent={[['May 10 15:19:05 WatchGuard-Firebox','IPv4 source route attack']]}
  holdoutEvidenceRequester={async()=>batchEvidence(holdout,
   [['3000-0153','10.0.1.35'],['3000-0154','10.0.1.36']])}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/Fix passed: full parser recovery/)).toBeTruthy();
 fireEvent.click(screen.getByRole('checkbox',{name:'Approve tested fix'}));
 fireEvent.click(screen.getByRole('button',{name:'Apply Verified Fix'}));
 await waitFor(()=>expect(apply).toHaveBeenCalledTimes(1));
 vi.unstubAllGlobals();
});

it('rejects full recovery when extracted source values would be omitted from final parser output',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='allow,198.51.100.10';
 const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
 // Owner decision Q3-1 keeps every capture a reply leaves unmapped (src/unmappedFields.ts), so this recipe loses
 // source text the one way a recovery still can: it reads that text as a regex literal outside any capture.
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^allow,(?<src_ip>[^,]+)$'},
   {op:'map_field',source:'src_ip',target:'custom.src_ip',data_type:'string',group:'vendor_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['allow','198.51.100.10']]}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/would drop 1 of 2 source value occurrences from the final parser output/)).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Apply Verified Fix'})).toBeNull();
 expect(apply).not.toHaveBeenCalled();
 vi.unstubAllGlobals();
});


it('allows explicit empty string source spans to follow backend ignore semantics during full recovery',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='allow,198.51.100.10';
 const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^(?<action>[^,]+),(?<src_ip>[^,]+)$'},
   {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
   {op:'map_field',source:'src_ip',target:'custom.src_ip',data_type:'string',group:'vendor_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['allow','198.51.100.10','""']]}
  holdoutEvidenceRequester={async()=>batchEvidence(holdout,
   [['allow','192.0.2.10'],['deny','192.0.2.11']])}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/Fix passed: full parser recovery/)).toBeTruthy();
 fireEvent.click(screen.getByRole('checkbox',{name:'Approve tested fix'}));
 fireEvent.click(screen.getByRole('button',{name:'Apply Verified Fix'}));
 await waitFor(()=>expect(apply).toHaveBeenCalledTimes(1));
 vi.unstubAllGlobals();
});

it('rejects full recovery when previously unparsed text is read but not kept in the final output',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='prefix id=123 suffix';
 const holdout='prefix id=456 suffix\nprefix id=789 suffix';
 // Owner decision Q3-1 keeps every capture a reply leaves unmapped (src/unmappedFields.ts), so this recipe loses
 // source text the one way a recovery still can: it reads that text as a regex literal outside any capture.
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^prefix id=(?<id>\\d+) suffix$'},
   {op:'map_field',source:'id',target:'custom.id',data_type:'string',group:'top_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="partial" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['123']]}
  protectedResidualTextByEvent={[['prefix ',' suffix']]}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/would leave 2 of 2 previously unparsed source regions outside the final parser output/)).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Apply Verified Fix'})).toBeNull();
 vi.unstubAllGlobals();
});

// Final independent re-audit of 62263b3 (2026-11-24), H-2: the real Multi-Pass evidence of these Squid lines
// (runtime/multipass preview_batch at 62263b3, copied below) reports multi-token residual regions such as
// " TCP_MISS/200 5120 GET ". A recipe that reads such a region into several fields keeps it; one that reads part of it
// as literal pattern text does not.
const SQUID='1763859723.123    245 192.0.2.51 TCP_MISS/200 5120 GET http://www.example.test/index.html - HIER_DIRECT/198.51.100.10 text/html\n'+
 '1763859724.456     12 192.0.2.52 TCP_DENIED/403 3900 CONNECT blocked.example.test:443 alice HIER_NONE/- text/html';
const SQUID_HOLDOUT='1763859725.789     77 192.0.2.53 TCP_HIT/200 777 GET http://cdn.example.test/a.js - HIER_NONE/- application/javascript\n'+
 '1763859726.012      9 192.0.2.54 TCP_DENIED/407 3900 GET http://intranet.example.test/ 김민수 HIER_NONE/- text/html';
const SQUID_VALUES=[['192.0.2.51','http://www.example.test/index.html','198.51.100.10'],['192.0.2.52']];
const SQUID_RESIDUALS=[['1763859723.123    245 ',' TCP_MISS/200 5120 GET ',' - HIER_DIRECT/',' text/html'],
 ['1763859724.456     12 ',' TCP_DENIED/403 3900 CONNECT blocked.example.test:443 alice HIER_NONE/- text/html']];
const HOLDOUT_VALUES=[['192.0.2.53','http://cdn.example.test/a.js'],['192.0.2.54','http://intranet.example.test/']];
const HOLDOUT_RESIDUALS=[['1763859725.789     77 ',' TCP_HIT/200 777 GET ',' - HIER_NONE/- application/javascript'],
 ['1763859726.012      9 ',' TCP_DENIED/407 3900 GET ',' 김민수 HIER_NONE/- text/html']];
function evidenceWithResiduals(source:string,values:string[][],residuals:string[][]):MultiPassBatchPreview{
 const batch=batchEvidence(source,values);
 const lines=source.split('\n');
 for(const [index,event] of batch.events.entries()){
  const raw=lines[index]!;let from=0;
  (event.preview as unknown as {residuals:unknown[]}).residuals=(residuals[index]??[]).map(text=>{
   const charStart=raw.indexOf(text,from);
   if(charStart<0)throw new Error('test residual missing');
   from=charStart+text.length;
   const startByte=new TextEncoder().encode(raw.slice(0,charStart)).byteLength;
   return {startByte,endByte:startByte+new TextEncoder().encode(text).byteLength};
  });
 }
 return batch;
}
const SQUID_PATTERN=String.raw`^(?<time>\d+\.\d{3}) +(?<elapsed>\d+) (?<client>[0-9.]+) (?<code>[A-Z_]+)/(?<status>\d{3}) (?<bytes>\d+) (?<method>[A-Z]+) (?<url>\S+) (?<user>\S+) (?<hierarchy>[A-Z_]+)/(?<peer>\S+) (?<type>\S+)$`;
async function squidReview(pattern:string,apply:(draft:import('../model').ParserDraft)=>void){
 vi.stubGlobal('crypto',webcrypto);
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(SQUID).digest('hex'),events:2},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern},
   {op:'map_field',source:'client',target:'srcip',data_type:'ip',group:'top_fields'},
   {op:'cast_type',target:'srcip',data_type:'ip'},
   {op:'map_field',source:'url',target:'url',data_type:'string',group:'top_fields'},
   {op:'map_field',source:'method',target:'method',data_type:'string',group:'vendor_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 const draft=createDraft();
 render(<AutoParserAIReview raw={SQUID} status="partial" onChatGPT={vi.fn()}
  source={SQUID} draft={draft} suite={preview(SQUID,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={SQUID_VALUES} protectedResidualTextByEvent={SQUID_RESIDUALS}
  holdoutEvidenceRequester={async()=>evidenceWithResiduals(SQUID_HOLDOUT,HOLDOUT_VALUES,HOLDOUT_RESIDUALS)}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:SQUID_HOLDOUT}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
}

it('accepts a lossless recovery that reads multi-token Multi-Pass residuals into several fields (re-audit H-2)',async()=>{
 const apply=vi.fn<(draft:import('../model').ParserDraft)=>void>();
 await squidReview(SQUID_PATTERN,apply);
 expect(await screen.findByText(/Fix passed: full parser recovery/)).toBeTruthy();
 fireEvent.click(screen.getByRole('checkbox',{name:'Approve tested fix'}));
 fireEvent.click(screen.getByRole('button',{name:'Apply Verified Fix'}));
 await waitFor(()=>expect(apply).toHaveBeenCalledTimes(1));
 const applied=apply.mock.calls[0]![0] as Parameters<typeof preview>[1];
 for(const line of [...SQUID.split('\n'),...SQUID_HOLDOUT.split('\n')]){
  const text=JSON.stringify(preview(line,applied).events[0]!.normalized);
  for(const value of line.split(/[ /]+/).filter(value=>value&&value!=='-'))expect(text,line).toContain(value);
 }
 vi.unstubAllGlobals();
});

it('still rejects a recovery that reads part of a multi-token residual as literal text (re-audit H-2)',async()=>{
 const apply=vi.fn<(draft:import('../model').ParserDraft)=>void>();
 await squidReview(SQUID_PATTERN.replace(' (?<hierarchy>[A-Z_]+)/',' HIER_(?<hierarchy>[A-Z_]+)/'),apply);
 expect(await screen.findByText(/event 1 would leave 1 of 4 previously unparsed source regions outside the final parser output/)).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Apply Verified Fix'})).toBeNull();
 expect(apply).not.toHaveBeenCalled();
 vi.unstubAllGlobals();
});

function scalarOutput(value:unknown,out:string[]=[]):string[]{
 if(typeof value==='string')out.push(value);
 else if(Array.isArray(value))for(const item of value)scalarOutput(item,out);
 else if(value&&typeof value==='object')for(const item of Object.values(value))scalarOutput(item,out);
 return out;
}

async function approveAndApply(apply:ReturnType<typeof vi.fn>){
 expect(await screen.findByText(/Fix passed: full parser recovery/)).toBeTruthy();
 fireEvent.click(screen.getByRole('checkbox',{name:'Approve tested fix'}));
 fireEvent.click(screen.getByRole('button',{name:'Apply Verified Fix'}));
 await waitFor(()=>expect(apply).toHaveBeenCalledTimes(1));
 const applied=apply.mock.calls[0]![0] as Parameters<typeof preview>[1];
 expect(applied.preserveUnmapped).toBe(true);
 return applied;
}

// Owner decision Q3-1: the recipes the two tests below send were rejected before because the final output dropped a
// capture the reply left unmapped. A ChatGPT recovery now keeps that capture, so the same recipes pass and every
// source value is checked in the applied parser's final output, for the sample and for each additional test log.
it('keeps a capture a ChatGPT recovery leaves unmapped in the final output (Q3-1)',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='allow,198.51.100.10';
 const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^(?<action>[^,]+),(?<src_ip>[^,]+)$'},
   {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="unsupported" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['allow','198.51.100.10']]}
  holdoutEvidenceRequester={async()=>batchEvidence(holdout,
   [['allow','192.0.2.10'],['deny','192.0.2.11']])}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 const applied=await approveAndApply(apply);
 for(const line of [source,...holdout.split('\n')]){
  const event=preview(line,applied).events[0]!;
  expect(event.parseStatus).toBe('FULL');
  const values=scalarOutput(event.normalized);
  for(const value of line.split(','))expect(values).toContain(value);
 }
 vi.unstubAllGlobals();
});

it('keeps previously unparsed text a ChatGPT recovery captures but leaves unmapped in the final output (Q3-1)',async()=>{
 vi.stubGlobal('crypto',webcrypto);
 const source='prefix id=123 suffix';
 const holdout='prefix id=456 suffix\nprefix id=789 suffix';
 const draft=createDraft(),apply=vi.fn();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^(?<raw>prefix id=(?<id>\\d+) suffix)$'},
   {op:'map_field',source:'id',target:'custom.id',data_type:'string',group:'top_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 render(<AutoParserAIReview raw={source} status="partial" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={[['123']]}
  protectedResidualTextByEvent={[['prefix ',' suffix']]}
  holdoutEvidenceRequester={async()=>batchEvidence(holdout,[['456'],['789']])}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 const applied=await approveAndApply(apply);
 for(const line of [source,...holdout.split('\n')]){
  const event=preview(line,applied).events[0]!;
  expect(event.parseStatus).toBe('FULL');
  const values=scalarOutput(event.normalized);
  expect(values).toContain(line);
  expect(values).toContain(line.match(/\d+/)![0]);
 }
 vi.unstubAllGlobals();
});
