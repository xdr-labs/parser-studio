import {describe,expect,it} from 'vitest';
import {createHash} from 'node:crypto';
import {createDraft,type ParserDraft} from '../model';
import {preview,splitEvents} from '../parser';
import {composeChatGPTPrompt} from './chatGptPromptBuilder';
import {buildEventCoverageEvidence} from './chatGptEventCoverage';
import {importRecoveryAIRecipe,proposeV01RecoveryParserFromAI} from './aiRecipeExchange';
import {extractRecipeJson} from './aiReplyExtract';
import {describeRejectedReason} from './chatGptResultNotice';
import {toBackendProject} from './backendAdapter';
import {regexReadsUncapturedText} from './regexSourceCoverage';

// Phase 3 P2: logs the automatic parser does not read (Squid native access.log, BIND query log; SYNTHETIC lines
// after the documented formats) go to ChatGPT Assisted. The replies below are written by this test, not by
// ChatGPT: they check what Parser Studio does with a correct and with deliberately wrong answers.
const SQUID=[
  '1763859723.123    245 192.0.2.51 TCP_MISS/200 5120 GET http://www.example.test/index.html - HIER_DIRECT/198.51.100.10 text/html',
  '1763859724.456     12 192.0.2.52 TCP_DENIED/403 3900 CONNECT blocked.example.test:443 alice HIER_NONE/- text/html',
].join('\n');
const BIND=[
  '23-Nov-2026 10:02:03.123 queries: info: client @0x7f00 192.0.2.41#53122 (www.example.test): query: www.example.test IN A +E(0)K (192.0.2.53)',
  '23-Nov-2026 10:02:04.456 queries: info: client @0x7f01 192.0.2.42#53123 (mail.example.test): query: mail.example.test IN MX +E(0)K (192.0.2.53)',
].join('\n');
const SQUID_PATTERN=String.raw`^(?<time>\d+\.\d{3}) +(?<elapsed>\d+) (?<client>[0-9.]+) (?<code>[A-Z_]+)/(?<status>\d{3}) (?<bytes>\d+) (?<method>[A-Z]+) (?<url>\S+) (?<user>\S+) (?<hierarchy>[A-Z_]+)/(?<peer>\S+) (?<type>\S+)$`;
const BIND_PATTERN=String.raw`^(?<date>\d\d-[A-Z][a-z]{2}-\d{4}) (?<time>[0-9:.]{12}) (?<cat>[a-z]+): (?<sev>[a-z]+): client @(?<obj>0x[0-9a-f]+) (?<cip>[0-9.]+)#(?<cport>\d+) \((?<view>[^)]+)\): query: (?<qname>\S+) (?<class>[A-Z]+) (?<type>[A-Z]+) (?<flags>\S+) \((?<srv>[0-9.]+)\)$`;
type Map=[source:string,target:string,type:'string'|'ip'|'port',group:'top_fields'|'vendor_fields'];
function reply(source:string,draft:ParserDraft,pattern:string,maps:Map[]):string{
  const stages:unknown[]=[{op:'split_event',boundary:'single-line'},{op:'parse_regex',pattern}];
  for(const [from,to,type,group] of maps){
    stages.push({op:'map_field',source:from,target:to,data_type:type,group});
    if(type!=='string')stages.push({op:'cast_type',target:to,data_type:type});
  }
  stages.push({op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'});
  const recipe={contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId:'draft-'+draft.guided!.slug,sourceFormat:'regex',bodyFormat:'regex',
    sample:{sha256:createHash('sha256').update(source,'utf8').digest('hex'),events:splitEvents(source,'single-line').length},
    stages,nativeVerified:false,targetVerified:false};
  return 'Here is the parser recipe:\n```json\n'+JSON.stringify(recipe)+'\n```';
}
const vendor=(names:string[]):Map[]=>names.map(name=>[name,name,'string','vendor_fields']);
const SQUID_MAPS:Map[]=[['client','srcip','ip','top_fields'],['url','url','string','top_fields'],
  ...vendor(['time','elapsed','code','status','bytes','method','user','hierarchy','peer','type'])];
const BIND_MAPS:Map[]=[['cip','srcip','ip','top_fields'],['cport','srcport','port','top_fields'],['srv','dstip','ip','top_fields'],
  ...vendor(['date','time','cat','sev','obj','view','qname','class','type','flags'])];

async function assisted(source:string,pattern:string,maps:Map[]){
  const draft={...createDraft(),vendor:'Audit'};
  const suite=preview(source,draft);
  const text=extractRecipeJson(reply(source,draft,pattern,maps))!.text;
  const imported=await importRecoveryAIRecipe(text,source,draft,suite);
  if(!imported.ok)return {imported};
  const proposal=proposeV01RecoveryParserFromAI(imported,draft);
  if(!proposal.ok)return {imported,proposal};
  return {imported,proposal,replay:preview(source,proposal.candidate)};
}

describe('ChatGPT Assisted path for logs the automatic parser does not read',()=>{
  it('the automatic parser declines them and the prompt carries the original lines and the per-record result',()=>{
    for(const source of [SQUID,BIND]){
      const draft=createDraft();
      const suite=preview(source,draft);
      expect(suite.events.every(event=>event.parseStatus!=='FULL')).toBe(true);
      const prompt=composeChatGPTPrompt({goal:'Parse every field of these logs',source,
        sourceHash:createHash('sha256').update(source,'utf8').digest('hex'),sourceCount:2,projectId:'draft-'+draft.guided!.slug,
        baseline:{ok:false,reason:'COMPILER_UNSUPPORTED'},eventCoverageEvidence:buildEventCoverageEvidence(source,draft,suite).text});
      for(const line of source.split('\n'))expect(prompt).toContain(line);
      expect(prompt).toContain('Automatic parse result per original record');
      // The export rule for Stellar Cyber 7.0 (Ruby 2.4.9) is the static cost proof, not a ban on regex.
      expect(prompt).toContain('only when its pattern is anchored');
      expect(prompt).not.toContain('CANNOT generate supported Ruby/CONF');
    }
  });

  it('a correct reply becomes a parser that reads every line completely (Squid, BIND)',async()=>{
    const squid=await assisted(SQUID,SQUID_PATTERN,SQUID_MAPS);
    expect(squid.imported.ok&&squid.imported.report.mode).toBe('FULL_RECOVERY');
    expect(squid.replay!.events.map(event=>event.parseStatus)).toEqual(['FULL','FULL']);
    expect(squid.replay!.events[0]!.normalized).toMatchObject({srcip:'192.0.2.51',url:'http://www.example.test/index.html',
      Audit:{status:'200',type:'text/html',peer:'198.51.100.10'}});
    expect(toBackendProject(squid.proposal!.ok?squid.proposal!.candidate:createDraft()).ok).toBe(true);
    const bind=await assisted(BIND,BIND_PATTERN,BIND_MAPS);
    expect(bind.replay!.events.map(event=>event.normalized)).toMatchObject([
      {srcip:'192.0.2.41',srcport:53122,dstip:'192.0.2.53',Audit:{qname:'www.example.test',type:'A'}},
      {srcip:'192.0.2.42',srcport:53123,dstip:'192.0.2.53',Audit:{qname:'mail.example.test',type:'MX'}}]);
  });

  it('a reply whose pattern reads a value without keeping it is rejected, with a plain reason',async()=>{
    const drop=await assisted(SQUID,SQUID_PATTERN.replace(' (?<type>\\S+)$',' \\S+$'),
      SQUID_MAPS.filter(([source])=>source!=='type'));
    expect(drop.imported).toEqual({ok:false,reason:'UNCAPTURED_SOURCE_TEXT'});
    expect(describeRejectedReason('UNCAPTURED_SOURCE_TEXT')).toContain('without keeping it in a field');
  });

  it('a reply that does not match every line leaves those lines unparsed, never as parsed',async()=>{
    const partial=await assisted(SQUID,SQUID_PATTERN.replace('(?<url>\\S+)','(?<url>http://\\S+)'),SQUID_MAPS);
    expect(partial.replay!.events.map(event=>event.parseStatus)).toEqual(['FULL','UNKNOWN']);
    expect(partial.replay!.events[1]!.normalized).toEqual({});
  });
});

describe('regexReadsUncapturedText',()=>{
  it('accepts literal structure, white space and anchors outside captures',()=>{
    for(const pattern of [String.raw`^(?<a>\S+) (?<b>\d+)$`,String.raw`^(?<a>\S+) +\[(?<b>[^\]]+)\]$`,
      String.raw`^(?<a>\S+)\s(?<b>\S+)$`,String.raw`^query: (?<q>\S+) \((?<s>[0-9.]+)\)$`,
      String.raw`^(?<a>\S+)(?: (?<b>\S+))?$`,String.raw`^(?:(?<a>x\d+)|(?<b>y\d+))$`,String.raw`^\b(?<a>\w+)$`])
      expect(regexReadsUncapturedText(pattern),pattern).toBe(false);
  });
  it('rejects a class, a wildcard, a letter escape, a repeated literal or a literal choice outside captures',()=>{
    for(const pattern of [String.raw`^(?<a>\S+) \S+$`,String.raw`^(?<a>\S+) .*$`,String.raw`^(?<a>\S+) \d+$`,
      String.raw`^(?<a>\S+) [A-Z]$`,String.raw`^(?<a>\S+) -+$`,String.raw`^(?:GET|POST) (?<path>\S+)$`,
      String.raw`^(?:(?<a>x)|y)$`,String.raw`^(?<a>\S+ (`])
      expect(regexReadsUncapturedText(pattern),pattern).toBe(true);
  });
});
