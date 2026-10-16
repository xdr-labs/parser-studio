import {expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {createHash,webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import AutoParserAIReview from './AutoParserAIReview';
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
  protectedSourceValuesByEvent={[['allow']]}
  holdoutEvidenceRequester={async()=>batchEvidence(holdout,
   [['allow','192.0.2.10'],['deny','192.0.2.11']])}/>);
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

it('rejects full recovery when an unparsed residual survives extraction but not final output',async()=>{
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
  protectedResidualTextByEvent={[['prefix ',' suffix']]}/>);
 fireEvent.change(screen.getByRole('textbox',{name:'ChatGPT JSON result'}),{target:{value:JSON.stringify(recipe)}});
 fireEvent.change(screen.getByRole('textbox',{name:'Additional test logs'}),{target:{value:holdout}});
 fireEvent.click(screen.getByRole('checkbox',{name:'Confirm different test examples'}));
 fireEvent.click(screen.getByRole('button',{name:'Test Proposed Fix'}));
 expect(await screen.findByText(/would leave 2 of 2 previously unparsed source regions outside the final parser output/)).toBeTruthy();
 expect(screen.queryByRole('button',{name:'Apply Verified Fix'})).toBeNull();
 vi.unstubAllGlobals();
});
