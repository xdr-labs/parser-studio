/** Development-only metamorphic source-structure controls.
 *
 * Mutants are synthetic perturbations of SHA-pinned originals and are NEVER
 * treated as independent vendor ground truth or part of blind scored recall.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {inspectBoundedSourceSpans} from '../../src/poc/boundedStructuralSourceSpans';
import {parseSecurityInput} from '../../src/securityInputPipeline';
type Row={split:string;oracle_status:string;raw:string;family:string};
const root=path.join(os.homedir(),'.local/state/parserstudio-generalization-blind-20261017');
const pin=JSON.parse(fs.readFileSync(path.join(root,'oracle-summary.pinned.json'),'utf8'));
const privateBytes=fs.readFileSync(path.join(root,'frozen-records-and-oracle.json'));
const sha=crypto.createHash('sha256').update(privateBytes).digest('hex');
if(sha!==pin.private_oracle_sha256)throw Error('Blind oracle identity changed');
const originals=(JSON.parse(privateBytes.toString('utf8')) as Row[]).filter(
  r=>r.split==='development'&&r.oracle_status==='INDEPENDENT_JSON_BYTE_TRUTH',
);
if(originals.length!==40)throw Error('Development-only source cohort drift');
const counts={sourceEvents:originals.length,syntheticVariants:0,
  duplicateAbstain:0,encodedAliasAbstain:0,precisionAbstain:0,
  truncationAbstain:0,baselineWronglyOkDuplicate:0,
  baselineWronglyOkPrecision:0,autoPromoted:0,failures:0};
function mutated(source:string,suffix:string):string{
  const last=source.lastIndexOf('}');
  if(last<0)throw Error('Expected independently qualified JSON object');
  return source.slice(0,last)+','+suffix+source.slice(last);
}
for(const row of originals){
  const variations=[
    ['duplicate',mutated(row.raw,'"__poc_structural_duplicate":1,"__poc_structural_duplicate":2')],
    ['alias',mutated(row.raw,'"__poc_structural_alias":1,"__poc_structural_\\u0061lias":2')],
    ['precision',mutated(row.raw,'"__poc_structural_integer":9007199254740993')],
    ['truncation',row.raw.slice(0,row.raw.lastIndexOf('}'))],
  ] as const;
  for(const [kind,raw] of variations){
    const candidate=inspectBoundedSourceSpans(raw);
    counts.syntheticVariants++;
    counts.autoPromoted+=Number(candidate.autoPromoted);
    if(candidate.disposition!=='ABSTAIN_UNSAFE'||candidate.fields.length)
      counts.failures++;
    else if(kind==='duplicate')counts.duplicateAbstain++;
    else if(kind==='alias')counts.encodedAliasAbstain++;
    else if(kind==='precision')counts.precisionAbstain++;
    else counts.truncationAbstain++;
    if(kind==='duplicate'&&parseSecurityInput(raw).ok)counts.baselineWronglyOkDuplicate++;
    if(kind==='precision'&&parseSecurityInput(raw).ok)counts.baselineWronglyOkPrecision++;
  }
}
console.log('STRUCTURAL_DEV_METAMORPHIC '+JSON.stringify({
  ...counts,scope:'SYNTHETIC_MUTATIONS_NOT_FRESH_VENDOR_HOLDOUT',
}));
if(counts.syntheticVariants!==160||counts.failures||counts.autoPromoted||
  counts.duplicateAbstain!==40||counts.encodedAliasAbstain!==40||
  counts.precisionAbstain!==40||counts.truncationAbstain!==40)
  process.exitCode=1;
