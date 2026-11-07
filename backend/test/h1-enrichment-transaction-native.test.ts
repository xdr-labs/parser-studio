import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {compilePair} from '../src/compiler.js';
import {validateProject} from '../src/validate.js';
import {sampleProject} from './fixture.js';
import {CANONICAL_OPERATOR_CONTRACT_V1} from '../src/canonical-operator-contract.js';
import type {ParserProject} from '../src/types.js';

const rubyAvailable=spawnSync('ruby',['-v'],{encoding:'utf8'}).status===0;
const required=process.env.PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED==='1';

function project(mode:'missing-source'|'pre-normalization-failure'|'invalid-official'|'success'):ParserProject{
 const p=sampleProject();
 p.vendor='Synthetic';
 p.normalization.topFields={
   user:{normalized_name:'username',data_type:'string'},
   action:{normalized_name:'action',data_type:'string'},
 };
 p.normalization.nsFields={};
 p.normalization.vendorFields={};
 p.classification={defaultIndex:'syslog',rules:[]};
 if(mode==='pre-normalization-failure'){
   p.normalization.topFields.port={normalized_name:'dstport',data_type:'port'};
 }
 if(mode==='invalid-official'){
   p.normalization.vendorFields.source={normalized_name:'source',data_type:'string'};
 }
 p.enrichment=[
   {operator:'set_const',target:'custom.site',value:'kr'},
   mode==='invalid-official'
     ?{operator:'copy',source:'Synthetic.source',target:'srcip'}
     :{operator:'copy',source:'action',target:'message'},
 ];
 const checked=validateProject(p);
 assert.equal(checked.ok,true,JSON.stringify(checked.issues));
 return p;
}

const GOLDENS=[
 {id:'missing-source',mode:'missing-source',input:{user:'한글-user',unmapped:'DO_NOT_ECHO_PRIVATE'},
  expected:{username:'한글-user',parser_err_stage:'enrichment',parser_err_field:'action'}},
 {id:'mapping-error-first',mode:'pre-normalization-failure',
  input:{user:'alice',action:'deny',port:65536},
  expected:{username:'alice',action:'deny',parser_err_stage:'normalization',parser_err_field:'port'}},
 {id:'invalid-official',mode:'invalid-official',
  input:{user:'alice',source:'not-an-ip'},
  expected:{username:'alice',Synthetic:{source:'not-an-ip'},
   parser_err_stage:'enrichment',parser_err_field:'Synthetic.source'}},
 {id:'success',mode:'success',input:{user:'alice',action:'allow'},
  expected:{username:'alice',action:'allow',custom:{site:'kr'},message:'allow'}},
] as const;

function native(projectIR:ParserProject,raw:string):Record<string,unknown>{
 const pair=compilePair(projectIR);
 assert.equal(pair.manifest.status,'DRAFT');
 const generated=pair.files.find(file=>!file.name.endsWith('.conf'));
 assert.ok(generated,'Ruby fragment must be generated');
 const script=[
   "require 'json'","require 'base64'","require 'time'","require 'date'",
   "require 'ipaddr'","require 'csv'",
   "source=Base64.strict_decode64(STDIN.gets.strip)",
   "line=STDIN.read",
   "parser_class=Class.new",
   "parser_class.class_eval(source,'h1-native',1)",
   "parser=parser_class.new",
   "rows=[]",
   "parser.parse(line){|_time,record|rows << record}",
   "STDOUT.write(JSON.generate(rows))",
 ].join('\n');
 const result=spawnSync('ruby',['-e',script],{
   encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
   input:Buffer.from(generated.content).toString('base64')+'\n'+raw,
 });
 assert.equal(result.status,0,result.stderr||String(result.error));
 const rows=JSON.parse(result.stdout) as Record<string,unknown>[];
 assert.equal(rows.length,1);
 return rows[0]!;
}

test('H1 error-stage and enrichment rollback contract is pinned to Native behavior',()=>{
 assert.deepEqual(CANONICAL_OPERATOR_CONTRACT_V1.enrichment,{
   application:'ordered-after-typed-normalization',
   skippedAfterPreviousError:true,
   failure:'rollback-entire-enrichment-transaction',
   failureStage:'enrichment',
   retainedOnFailure:'validated-pre-enrichment-fields-only',
 });
 for(const item of GOLDENS){
   assert.equal(validateProject(project(item.mode)).ok,true,item.id);
 }
 if(required)assert.equal(rubyAvailable,true,
   'Exact-head Native CI must not skip generated Ruby execution');
});

test('H1 generated Ruby matches independent typed, stage and rollback truth',
 {skip:!rubyAvailable},()=>{
 for(const item of GOLDENS){
   const raw=JSON.stringify(item.input);
   const checksum=createHash('sha256').update(raw,'utf8').digest('hex');
   assert.equal(checksum.length,64);
   if(item.id==='missing-source')assert.ok(Buffer.byteLength(raw)>raw.length,
     'Unicode bytes must be accounted independently from code points');
   const result=native(project(item.mode),raw);
   for(const [key,value] of Object.entries(item.expected)){
     assert.deepEqual(result[key],value,item.id+' '+key);
   }
   if(item.id==='success'){
     assert.ok(!('parser_err_stage' in result));
   }else{
     assert.equal(result.stellar_log_index,'syslog');
     assert.equal(result.parser_err_msg,'MappedFieldError');
     assert.ok(!('custom' in result),'Failed transaction must discard all earlier enrichment writes');
     assert.ok(!('message' in result),'Failed or skipped enrichment must never emit later writes');
     assert.ok(!('srcip' in result),'Invalid official IP cannot escape the transaction');
   }
   assert.ok(!JSON.stringify(result).includes('DO_NOT_ECHO_PRIVATE'));
   assert.ok(!JSON.stringify(result).includes(raw),
     'Original raw event must not leak through runtime diagnostics');
 }
});
