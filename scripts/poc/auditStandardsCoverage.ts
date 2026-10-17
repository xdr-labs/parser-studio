/** Static standard-to-implementation inventory integrity check.
 * Completeness is stated by scope, not guessed from code grep or CI success.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const project=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const ledgerPath=path.join(project,'scripts/poc/standardCoverageLedger.v1.json');
const manifestPath=path.join(project,'scripts/poc/normativeGrammarSources.pinned.json');
const casesPath=path.join(project,'scripts/poc/standardGrammarCases.v1.json');
const read=(p:string)=>JSON.parse(fs.readFileSync(p,'utf8')) as Record<string,unknown>;
const ledger=read(ledgerPath);
const manifest=read(manifestPath);
const fixtures=read(casesPath);
const entries=ledger.entries as Array<{
  id:string;sourceIds:string[];rule:string;
  implementationPaths:string[];status:string;risk:string;
  observation:string;next:string;
}>;
const references=manifest.sources as Array<{id:string;uri:string;sha256:string;bytes:number}>;
const validRefs=new Set(references.map(x=>x.id));
let referencedCode=0,missingFiles=0,missingRefs=0,unqualifiedStatements=0;
const statuses:Record<string,number>={};
const risks:Record<string,number>={};
const missing:{id:string;type:string}[]=[];
const names=new Set<string>();
for(const entry of entries){
 if(names.has(entry.id))throw Error('Duplicate audit ID: '+entry.id);
 names.add(entry.id);
 for(const src of entry.sourceIds){
  if(!validRefs.has(src)){missingRefs++;missing.push({id:entry.id,type:'UNPINNED_REFERENCE'});}
 }
 for(const file of entry.implementationPaths){
  const absolute=path.join(project,file);
  referencedCode++;
  if(!fs.existsSync(absolute)){missingFiles++;missing.push({id:entry.id,type:'MISSING_IMPLEMENTATION_PATH'});}
 }
 if(!entry.observation||!entry.next||!['HIGH','MEDIUM','LOW'].includes(entry.risk))
  unqualifiedStatements++;
 statuses[entry.status]=(statuses[entry.status]??0)+1;
 risks[entry.risk]=(risks[entry.risk]??0)+1;
}
const checksum=(file:string)=>crypto.createHash('sha256')
 .update(fs.readFileSync(file)).digest('hex');
const output={
 contract:'P0_STD_INITIAL_CODE_LINKED_AUDIT_NOT_COMPLETE_FORMAT_CERTIFICATION',
 sourceTree:ledger.sourceTree,
 authoritativeReferences:references.length,
 unavailableAuthoritativeReferences:(manifest.unavailable as unknown[]).length,
 standardsDerivedTests:(fixtures.cases as unknown[]).length,
 coverageRows:entries.length,implementationPathReferences:referencedCode,
 highRisk:risks.HIGH??0,mediumRisk:risks.MEDIUM??0,
 statusCounts:statuses,
 missingFiles,missingRefs,unqualifiedStatements,
 ledgerSha256:checksum(ledgerPath),
 referenceManifestSha256:checksum(manifestPath),
 syntheticCaseSha256:checksum(casesPath),
 standardsBytesRedistributed:false,fullComplianceClaimed:false,
 nativeParserCertified:false,unknownSourceSemanticsNotInvented:true,
 missing,
};
console.log('P0_STD_IMPLEMENTATION_COVERAGE '+JSON.stringify(output));
if(entries.length<16||missingFiles||missingRefs||unqualifiedStatements)process.exitCode=1;
