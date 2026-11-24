import {describe,expect,it} from 'vitest';
import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {createDraft,type ParserDraft} from '../model';
import {preview,splitEvents} from '../parser';
import {composeChatGPTPrompt} from './chatGptPromptBuilder';
import {buildEventCoverageEvidence} from './chatGptEventCoverage';
import {importRecoveryAIRecipe,proposeV01RecoveryParserFromAI} from './aiRecipeExchange';
import {extractRecipeJson} from './aiReplyExtract';
import {toBackendProject} from './backendAdapter';

// Owner decision Q3-1 on the ChatGPT Assisted path: original log -> prompt -> a reply written by this test (no
// ChatGPT call) -> recipe validation -> parser -> preview, and with Q31_PROJ_DIR set the backend project for the
// Ruby 2.4.9 run. SYNTHETIC lines after the documented Squid native access.log format.
const SQUID=[
  '1763859723.123    245 192.0.2.51 TCP_MISS/200 5120 GET http://www.example.test/index.html - HIER_DIRECT/198.51.100.10 text/html',
  '1763859724.456     12 192.0.2.52 TCP_DENIED/403 3900 CONNECT blocked.example.test:443 alice HIER_NONE/- text/html',
].join('\n');
const RUNTIME=[
  '1763859725.789     77 192.0.2.53 TCP_HIT/200 777 GET http://cdn.example.test/a.js - HIER_NONE/- application/javascript',
  '1763859726.012      9 192.0.2.54 TCP_DENIED/407 3900 GET http://intranet.example.test/ 김민수 HIER_NONE/- text/html',
];
const PATTERN=String.raw`^(?<time>\d+\.\d{3}) +(?<elapsed>\d+) (?<client>[0-9.]+) (?<code>[A-Z_]+)/(?<status>\d{3}) (?<bytes>\d+) (?<method>[A-Z]+) (?<url>\S+) (?<user>\S+) (?<hierarchy>[A-Z_]+)/(?<peer>\S+) (?<type>\S+)$`;
type Map=[source:string,target:string,type:'string'|'ip',group:'top_fields'|'vendor_fields'];
function reply(draft:ParserDraft,pattern:string,maps:Map[]):string{
  const stages:unknown[]=[{op:'split_event',boundary:'single-line'},{op:'parse_regex',pattern}];
  for(const [from,to,type,group] of maps){
    stages.push({op:'map_field',source:from,target:to,data_type:type,group});
    if(type!=='string')stages.push({op:'cast_type',target:to,data_type:type});
  }
  stages.push({op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'});
  const recipe={contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId:'draft-'+draft.guided!.slug,sourceFormat:'regex',bodyFormat:'regex',
    sample:{sha256:createHash('sha256').update(SQUID,'utf8').digest('hex'),events:splitEvents(SQUID,'single-line').length},
    stages,nativeVerified:false,targetVerified:false};
  return 'Here is the parser recipe:\n```json\n'+JSON.stringify(recipe)+'\n```';
}
async function assisted(pattern:string,maps:Map[]){
  const draft={...createDraft(),vendor:'Audit'};
  const suite=preview(SQUID,draft);
  const imported=await importRecoveryAIRecipe(extractRecipeJson(reply(draft,pattern,maps))!.text,SQUID,draft,suite);
  if(!imported.ok)return {imported};
  const proposal=proposeV01RecoveryParserFromAI(imported,draft);
  return {imported,proposal};
}
// The reply maps only part of the captures: client and url officially, method as a vendor field.
const PARTIAL_MAPS:Map[]=[['client','srcip','ip','top_fields'],['url','url','string','top_fields'],['method','method','string','vendor_fields']];

describe('ChatGPT Assisted keeps every field its parser reads (Q3-1)',()=>{
  it('the prompt carries the original lines',()=>{
    const draft=createDraft();
    const suite=preview(SQUID,draft);
    const prompt=composeChatGPTPrompt({goal:'Parse every field of these logs',source:SQUID,
      sourceHash:createHash('sha256').update(SQUID,'utf8').digest('hex'),sourceCount:2,projectId:'draft-'+draft.guided!.slug,
      baseline:{ok:false,reason:'COMPILER_UNSUPPORTED'},eventCoverageEvidence:buildEventCoverageEvidence(SQUID,draft,suite).text});
    for(const line of SQUID.split('\n'))expect(prompt).toContain(line);
  });
  it('keeps the captures the reply left unmapped, in the sample and at run time, each event FULL',async()=>{
    const result=await assisted(PATTERN,PARTIAL_MAPS);
    expect(result.imported.ok,JSON.stringify(result.imported)).toBe(true);
    expect(result.proposal?.ok,JSON.stringify(result.proposal)).toBe(true);
    if(!result.proposal?.ok)return;
    const candidate=result.proposal.candidate;
    expect(candidate.preserveUnmapped).toBe(true);
    const events=preview([SQUID,...RUNTIME].join('\n'),candidate).events;
    expect(events.map(event=>event.parseStatus)).toEqual(['FULL','FULL','FULL','FULL']);
    const lines=[...SQUID.split('\n'),...RUNTIME];
    for(const [index,event] of events.entries()){
      const text=JSON.stringify(event.normalized);
      const groups=new RegExp(PATTERN,'u').exec(lines[index]!)!.groups!;
      // '-' is a missing value by the mapping contract (ignoreValues), mapped or not.
      for(const [name,value] of Object.entries(groups))if(value!=='-')
        expect(text,name+' of line '+index).toContain(JSON.stringify(value));
      // No value of another line.
      for(const [other,line] of lines.entries())if(other!==index){
        const time=new RegExp(PATTERN,'u').exec(line)!.groups!.time!;
        expect(text).not.toContain(JSON.stringify(time));
      }
    }
    expect(events[0]!.normalized.srcip).toBe('192.0.2.51');
    expect((events[0]!.normalized.Audit as Record<string,unknown>).code).toBe('TCP_MISS');
    const project=toBackendProject(candidate);
    expect(project.ok).toBe(true);
    if(project.ok&&process.env.Q31_PROJ_DIR){
      mkdirSync(process.env.Q31_PROJ_DIR,{recursive:true});
      writeFileSync(process.env.Q31_PROJ_DIR+'/squid_partial.json',JSON.stringify(project.project));
      writeFileSync(process.env.Q31_PROJ_DIR+'/squid_partial.lines',[SQUID,...RUNTIME].join('\n')+'\n');
    }
  });
  it.each([
    ['an optional literal outside a capture',PATTERN.replace(' (?<user>\\S+) ',' (?:- )?(?<user>\\S+) ')],
    ['a capture inside a repeated group',PATTERN.replace(' (?<type>\\S+)$','(?: (?<type>\\S+))+$')],
    ['text read without a capture',PATTERN.replace(' (?<type>\\S+)$',' \\S+$')],
  ])('rejects a reply with %s',async(_,pattern)=>{
    const result=await assisted(pattern,PARTIAL_MAPS);
    expect(result.imported.ok).toBe(false);
  });
});
