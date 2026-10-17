/** Independent original Unicode byte-span audit across three frozen source families.
 * No source/field/value/raw event is emitted, and no source result is promoted.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {conservativeKvLocatedFields} from '../../src/poc/conservativeKvUtf8Span';
import {judgeSourceKvSpans,type IndependentSourceSpan}
  from '../../src/poc/sourceKvSpanReviewGate';

type SourceRow={id:string;source:string;raw:string};
type SourceSpanRef={
  sourceSha256:string;sourceBytes?:number;status:string;family?:string;
  fields?:IndependentSourceSpan[];
};
type Oracle={schemaVersion:number;records:Record<string,SourceSpanRef>};
const root=path.join(os.homedir(),'.local/state');
const sha=(v:string|Buffer)=>crypto.createHash('sha256').update(v).digest('hex');
const oraclePath=path.join(root,'parserstudio-source-kv-byte-span-20261017',
  'additional-source-kv-utf8-byte-spans.json');
const stat=fs.statSync(oraclePath);
if(stat.mode&0o077)throw Error('Additional source oracle must be protected mode 0600');
const oracle=JSON.parse(fs.readFileSync(oraclePath,'utf8')) as Oracle;
if(oracle.schemaVersion!==1||Object.keys(oracle.records).length!==1214)
  throw Error('Independent additional span oracle cardinality changed');
const originals=new Map<string,{raw:string;family:string}>();
const add=(raw:string,family:string)=>{
  const hash=sha(raw);
  const prev=originals.get(hash);
  if(prev){
    if(prev.raw!==raw||prev.family!==family)throw Error('Original source identity collision');
    return;
  }
  originals.set(hash,{raw,family});
};
for(const file of ['fg.log','fg_long.log']){
  const bytes=fs.readFileSync(path.join(root,'parserstudio-fresh-kv-20261017',file));
  const expected=file==='fg.log'?
    'e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2':
    '53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440';
  if(sha(bytes)!==expected)throw Error('Fortinet source changed');
  for(const raw of bytes.toString('utf8').split(/\r\n|\n|\r/).filter(x=>x.trim()))
    add(raw,'fortinet');
}
const sonic=fs.readFileSync(path.join(root,
  'parserstudio-fresh-sonicwall-20261017','sonicwall.log.orig'));
if(sha(sonic)!=='949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9')
  throw Error('SonicWall source changed');
for(const raw of sonic.toString('utf8').split(/\r\n|\n|\r/).filter(x=>x.trim()))
  add(raw,'sonicwall');
const sophos=fs.readFileSync(path.join(root,
  'parserstudio-fresh-vendor-holdout-20261016','records.json'));
if(sha(sophos)!=='3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2')
  throw Error('Sophos source changed');
let sophosUnscored=0,sophosUnscoredGrammarOnly=0;
for(const row of JSON.parse(sophos.toString('utf8')) as SourceRow[]){
  if(!row.source.startsWith('sophos/xg/'))continue;
  add(row.raw,'sophos');
  if(!oracle.records[sha(row.raw)]){
    sophosUnscored++;
    if(conservativeKvLocatedFields(row.raw))sophosUnscoredGrammarOnly++;
  }
}
const byFamily:Record<string,{events:number;fields:number;exactEvents:number;
  exactFields:number;falsePositive:number;falseNegative:number;
  spanMismatch:number;valueMismatch:number;unscorable:number}>={};
let exactEvents=0,exactFields=0,fields=0,total=0,sourceUnscorable=0;
let fp=0,fn=0,spanMismatch=0,valueMismatch=0,candidateRejected=0;
for(const [hash,item] of Object.entries(oracle.records)){
  const original=originals.get(hash);
  if(!original)throw Error('Frozen independent reference without matching source');
  const expected=item.fields;
  const b=Buffer.from(original.raw,'utf8');
  const sourceShaMatches=sha(b)===hash&&item.sourceSha256===hash;
  const exactRawRetained=item.sourceBytes===b.length;
  const candidate=conservativeKvLocatedFields(original.raw);
  const checked=judgeSourceKvSpans({
    sourceShaMatches,exactRawRetained,expected:expected??null,
    actual:candidate?.spans??null,
  });
  if(checked.canAutoPromote)throw Error('Unapproved source result promoted');
  const group=byFamily[original.family]??={
    events:0,fields:0,exactEvents:0,exactFields:0,falsePositive:0,
    falseNegative:0,spanMismatch:0,valueMismatch:0,unscorable:0,
  };
  if(item.status==='SOURCE_UNSCORABLE'){
    if(checked.disposition!=='UNSCORABLE_SOURCE')
      throw Error('Previously unknown source became scored without authority');
    group.unscorable++;sourceUnscorable++;continue;
  }
  if(item.status!=='SOURCE_QUALIFIED'||!expected)
    throw Error('Original field/value source reference is incomplete');
  group.events++;total++;group.fields+=expected.length;fields+=expected.length;
  group.exactFields+=checked.exactOriginalFields;exactFields+=checked.exactOriginalFields;
  group.falsePositive+=checked.falsePositiveFields;fp+=checked.falsePositiveFields;
  group.falseNegative+=checked.falseNegativeFields;fn+=checked.falseNegativeFields;
  group.spanMismatch+=checked.spanMismatches;spanMismatch+=checked.spanMismatches;
  group.valueMismatch+=checked.valueMismatches;valueMismatch+=checked.valueMismatches;
  if(!candidate)candidateRejected++;
  if(checked.disposition==='REVIEW_ONLY_SOURCE_EXACT'){group.exactEvents++;exactEvents++;}
}
if(total!==1212||fields!==17563||sourceUnscorable!==2||sophosUnscored!==120||
   byFamily.fortinet?.events!==1002||byFamily.sonicwall?.events!==59||
   byFamily.sophos?.events!==151)throw Error('Independent cross-family source totals drift');
console.log('ADDITIONAL_SOURCE_KV_UTF8_SPAN_INDEPENDENT_AUDIT '+JSON.stringify({
  qualifiedOriginalEvents:total,qualifiedOriginalFields:fields,
  exactOriginalEvents:exactEvents,exactOriginalFields:exactFields,
  falsePositive:fp,falseNegative:fn,spanMismatch,valueMismatch,
  previouslyUnscorableOriginals:sourceUnscorable,
  sophosAdditionalWithoutIndependentOracle:sophosUnscored,
  sophosUnscoredGrammaticalMatches:sophosUnscoredGrammarOnly,
  candidateRejected,byFamily,privateOracleSha256:sha(fs.readFileSync(oraclePath)),
  manufacturerSemantics:'NOT_CERTIFIED',nativeParser:'NOT_VERIFIED',
  promotedFromUnscorable:0,sourceRawOrValuesEmitted:false,
  productParserModified:false,
}));
if(exactEvents!==total||exactFields!==fields||fp||fn||spanMismatch||
   valueMismatch||candidateRejected)process.exitCode=1;
