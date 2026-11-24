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
 runResidualAccountingInWorker:async(raw:string,draft:import('../model').ParserDraft,
  regions:import('./residualProvenance').ResidualRegion[][])=>
   (await import('./residualProvenance')).accountResidualRegions(raw,draft,regions),
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
// " TCP_MISS/200 5120 GET ". The review accounts for such a region character by character (UTF-8 byte spans of
// every capture, src/guided/residualProvenance.ts), so a lossless recipe that reads it into several fields passes,
// while recipes that read source text as literal pattern text are refused (the HIER_ test and the D-1 IIS and
// Apache tests below).
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

// Re-audit H-2 (fixed): this lossless recipe was refused while a region had to be kept whole in one value.
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
 // Only the third region (" - HIER_DIRECT/") loses text ("HIER_" is pattern text); the other three are read
 // into fields whole. The strict whole-region rule reported 3 of 4 here before the H-2 fix.
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

// Verification of 3f363d2 (D-1): recipes that drop literal digits (IIS sc-substatus and sc-win32-status read as the
// pattern text "0 0") or a sign (Apache "-0500" read as "-" + digits) must be refused. Real Multi-Pass evidence
// (runtime/multipass preview_batch at 3f363d2) of the lines below.
async function residualReview(source:string,holdout:string,values:string[][],residuals:string[][],
 holdoutValues:string[][],holdoutResiduals:string[][],pattern:string,apply:(draft:import('../model').ParserDraft)=>void){
 vi.stubGlobal('crypto',webcrypto);
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern},
   {op:'map_field',source:'client',target:'srcip',data_type:'ip',group:'top_fields'},
   {op:'cast_type',target:'srcip',data_type:'ip'},
   {op:'map_field',source:'status',target:'status',data_type:'string',group:'vendor_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 const draft=createDraft();
 render(<AutoParserAIReview raw={source} status="partial" onChatGPT={vi.fn()}
  source={source} draft={draft} suite={preview(source,draft)} onApplyCandidate={apply}
  protectedSourceValuesByEvent={values} protectedResidualTextByEvent={residuals}
  holdoutEvidenceRequester={async()=>evidenceWithResiduals(holdout,holdoutValues,holdoutResiduals)}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
}
it('refuses a recovery that reads IIS status digits as literal pattern text (verification D-1)',async()=>{
 const apply=vi.fn<(draft:import('../model').ParserDraft)=>void>();
 await residualReview(
  '2026-11-24 10:00:00 10.0.0.1 GET /index.html - 80 - 192.0.2.10 Mozilla/5.0 - 200 0 0 15\n'+
  '2026-11-24 10:00:01 10.0.0.1 POST /login.aspx - 443 - 192.0.2.11 Mozilla/5.0 - 302 0 0 31',
  '2026-11-24 10:00:02 10.0.0.1 GET /missing.html - 80 - 192.0.2.12 Mozilla/5.0 - 404 0 0 7\n'+
  '2026-11-24 10:00:03 10.0.0.1 GET /error.aspx - 443 - 192.0.2.13 Mozilla/5.0 - 500 0 0 120',
  [['10.0.0.1','192.0.2.10'],['10.0.0.1','192.0.2.11']],
  [['2026-11-24 10:00:00 ',' GET /index.html - 80 - ',' Mozilla/5.0 - 200 0 0 15'],
   ['2026-11-24 10:00:01 ',' POST /login.aspx - 443 - ',' Mozilla/5.0 - 302 0 0 31']],
  [['10.0.0.1','192.0.2.12'],['10.0.0.1','192.0.2.13']],
  [['2026-11-24 10:00:02 ',' GET /missing.html - 80 - ',' Mozilla/5.0 - 404 0 0 7'],
   ['2026-11-24 10:00:03 ',' GET /error.aspx - 443 - ',' Mozilla/5.0 - 500 0 0 120']],
  String.raw`^(?<date>\S+) (?<time>\S+) (?<server>[0-9.]+) (?<method>[A-Z]+) (?<uri>\S+) - (?<port>\d+) - (?<client>[0-9.]+) (?<ua>\S+) - (?<status>\d+) 0 0 (?<taken>\d+)$`,
  apply);
 expect(await screen.findByText(/would leave \d+ of \d+ previously unparsed source regions outside the final parser output/)).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Apply Verified Fix'})).toBeNull();
 expect(apply).not.toHaveBeenCalled();
 vi.unstubAllGlobals();
});
it('refuses a recovery that drops the sign of an Apache time zone (verification D-1)',async()=>{
 const apply=vi.fn<(draft:import('../model').ParserDraft)=>void>();
 await residualReview(
  '192.0.2.7 - alice [24/Nov/2026:10:00:00 -0500] "GET /a HTTP/1.1" 200 2326\n'+
  '192.0.2.8 - bob [24/Nov/2026:10:00:01 -0500] "GET /b HTTP/1.1" 404 512',
  '192.0.2.9 - carol [24/Nov/2026:10:00:02 -0800] "GET /c HTTP/1.1" 200 100\n'+
  '192.0.2.10 - dave [24/Nov/2026:10:00:03 -0800] "POST /d HTTP/1.1" 500 0',
  [['192.0.2.7'],['192.0.2.8']],
  [[' - alice [24/Nov/2026:10:00:00 -0500] "GET /a HTTP/1.1" 200 2326'],[' - bob [24/Nov/2026:10:00:01 -0500] "GET /b HTTP/1.1" 404 512']],
  [['192.0.2.9'],['192.0.2.10']],
  [[' - carol [24/Nov/2026:10:00:02 -0800] "GET /c HTTP/1.1" 200 100'],[' - dave [24/Nov/2026:10:00:03 -0800] "POST /d HTTP/1.1" 500 0']],
  String.raw`^(?<client>[0-9.]+) - (?<user>\S+) \[(?<time>\S+) -(?<tz>\d{4})\] "(?<method>[A-Z]+) (?<path>\S+) (?<proto>\S+)" (?<status>\d+) (?<bytes>\d+)$`,
  apply);
 expect(await screen.findByText(/would leave \d+ of \d+ previously unparsed source regions outside the final parser output/)).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Apply Verified Fix'})).toBeNull();
 expect(apply).not.toHaveBeenCalled();
 vi.unstubAllGlobals();
});
