import {readdirSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {rubyRequirementProblem} from './ruby-requirement.mjs';

/**
 * Explicit product gate inventory. Do not mistake a selective acceptance
 * contract for a clean result on the complete historical backend suite.
 *
 * Target/legacy write authorization and external Drain3 workers are NOT
 * executed by the current downloaded-parser product. They remain separately
 * testable with npm test and may fail in a non-target environment.
 */
export const NON_PRODUCT_TEST_FILES = Object.freeze([
  'drain3-worker.test.ts',
  'stellar-legacy-client.test.ts',
  'stellar-legacy-http.test.ts',
  'stellar-legacy-plan.test.ts',
]);

const rubyProblem=rubyRequirementProblem(process.env);
if(rubyProblem){process.stderr.write(rubyProblem+'\n');process.exit(1);}

const root=resolve('test');
const all=readdirSync(root).filter(name=>name.endsWith('.test.ts')).sort();
const excluded=new Set(NON_PRODUCT_TEST_FILES);
for(const name of excluded){
  if(!all.includes(name))throw new Error('Explicit test scope changed: '+name);
}
const included=all.filter(name=>!excluded.has(name));
if(included.length<60)throw new Error('Unexpectedly small offline authoring test inventory');
process.stdout.write(
  'OFFLINE_AUTHORING_TEST_SCOPE: '+included.length+'/'+all.length+' files\n'+
  'NOT_IN_PRODUCT_GATE ('+excluded.size+'; preserved, not passed): '+
  [...excluded].join(', ')+'\n',
);
const runner=join(resolve('node_modules'),'tsx','dist','cli.mjs');
const result=spawnSync(process.execPath,[runner,'--test',...included.map(name=>join('test',name))],{
  cwd:resolve('.'),stdio:'inherit',
});
if(result.error)throw result.error;
process.exitCode=result.status??1;
