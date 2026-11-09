/**
 * Backend's emitted policy JSON is a generated packaging projection, not a
 * separately editable mapping source. Differences fail closed before build.
 * Run with --sync only when deliberately updating canonical policy in source.
 */
import {readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const canonical=fileURLToPath(new URL('../../runtime/multipass/semantic-policy.v1.json',import.meta.url));
const snapshot=fileURLToPath(new URL('../semantic-policy.v1.json',import.meta.url));
const source=readFileSync(canonical);
const copy=readFileSync(snapshot);
const mode=process.argv[2]??'--verify';
if(mode==='--sync'){
  writeFileSync(snapshot,source);
  console.log('BACKEND_SEMANTIC_POLICY_SYNCED');
}else if(mode==='--verify'){
  if(!source.equals(copy)){
    console.error('BACKEND_SEMANTIC_POLICY_DIVERGENCE');
    process.exitCode=1;
  }else console.log('BACKEND_SEMANTIC_POLICY_CANONICAL_MATCH');
}else{
  console.error('UNKNOWN_POLICY_MODE');
  process.exitCode=1;
}
