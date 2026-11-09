/**
 * Fixed-synthetic, source-linked artifact reproducibility receipt.
 * No customer source, compiled Ruby text, service credentials, target API
 * access, or parser installation. A source HEAD alone is NOT runtime proof.
 */
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {compilePair} from '../../backend/src/compiler';
import {buildArtifactPackage} from '../../backend/src/artifact-package';
import {sampleProject} from '../../backend/test/fixture';
const sha=(content:Buffer|string)=>createHash('sha256').update(content).digest('hex');
const git=(...args:string[])=>execFileSync('git',args,{encoding:'utf8',timeout:5000}).trim();
const head=git('rev-parse','HEAD');
const tree=git('rev-parse','HEAD^{tree}');
// CI-produced build outputs (dist, node_modules, browser reports) are not
// source drift. Newly added contract/compiler/test files still count as
// dirty until tracked, so a local uncommitted script cannot claim exact HEAD.
const relevantUntracked=git('ls-files','--others','--exclude-standard','--',
  'src','backend/src','backend/test','backend/scripts','scripts/verification',
  'contracts','runtime','docs','.github','tests');
const dirty=git('status','--porcelain','--untracked-files=no').length>0||
  relevantUntracked.length>0;
if(process.env.CI&&dirty)throw new Error('ARTIFACT_LINEAGE_DIRTY_WORKTREE');
// On pull_request, GITHUB_SHA refers to the synthetic merge commit. The
// expected source commit must be explicitly passed from PR head.sha.
const expectedSourceHead=process.env.PARSER_STUDIO_EXPECTED_SOURCE_HEAD??
  process.env.GITHUB_SHA;
if(expectedSourceHead&&expectedSourceHead!==head)
  throw new Error('ARTIFACT_LINEAGE_WRONG_HEAD');
const shared=readFileSync('runtime/multipass/semantic-policy.v1.json');
const packaged=readFileSync('backend/semantic-policy.v1.json');
assert.deepEqual(shared,packaged,'packaged backend policy must match canonical source bytes');
const templateFiles=[
  'backend/templates/canonical-operators.rb.tpl',
  'backend/templates/ruby-fragment.rb.tpl',
  'backend/templates/ruby-forwarder-family.rb.tpl',
  'backend/templates/generic-structural-helper.rb.tpl',
];
const sourceFiles=[
  'backend/src/compiler.ts','backend/src/validate.ts',
  'backend/src/portable-regex.ts','backend/src/canonical-operator-contract.ts',
  'runtime/multipass/semantic-policy.v1.json',
  'contracts/target-runtime-profiles.v1.json',
];
const digestOfFiles=(files:string[])=>sha(Buffer.concat(
  files.map(name=>Buffer.concat([Buffer.from(name+'\0'),readFileSync(name),Buffer.from('\0')]))));
const project=sampleProject();
const pair=compilePair(project);
const replay=compilePair(project);
assert.deepEqual(replay,pair,'two builds of the same synthetic project must be byte-identical');
assert.equal(pair.manifest.status,'DRAFT');
assert.equal(pair.manifest.engineVerified,false);
assert.equal(pair.manifest.targetImportVerified,false);
const packagedOnce=buildArtifactPackage(pair,'synthetic-1.0');
const packagedAgain=buildArtifactPackage(replay,'synthetic-1.0');
assert.deepEqual(packagedAgain.zip,packagedOnce.zip,'identical ZIP input must produce byte-identical ZIP');
assert.equal(sha(packagedOnce.zip),packagedOnce.zipSha256);
assert.equal(packagedOnce.manifest.artifactRevisionId,
  packagedAgain.manifest.artifactRevisionId);
assert.equal(packagedOnce.manifest.engineVerified,false);
assert.equal(packagedOnce.manifest.runtimeParsingVerified,false);
assert.equal(packagedOnce.manifest.targetImportVerified,false);
assert.equal(packagedOnce.manifest.deploymentPerformed,false);
for(const file of pair.files){
  assert.equal(sha(file.content),file.sha256);
  assert.equal(pair.manifest.fileHashes[file.name],file.sha256);
  assert.equal(packagedOnce.manifest.fileHashes[file.name],file.sha256);
}
const corrupted=structuredClone(pair);
corrupted.files[0]!.content+='X';
assert.throws(()=>buildArtifactPackage(corrupted,'synthetic-1.0'),
  'tampered artifact bytes must never retain a valid lineage receipt');

const receipt={
  contract:'parser-studio.executable-artifact-lineage.v1',
  sourceHead:head,
  sourceTree:tree,
  worktreeDirty:dirty,
  sourceContractHash:digestOfFiles(sourceFiles),
  runtimeProfileSha256:sha(readFileSync('contracts/target-runtime-profiles.v1.json')),
  sharedMappingPolicySha256:sha(shared),
  compilerTemplateSha256:digestOfFiles(templateFiles),
  artifactSource:'fixed-public-synthetic',
  fileHashes:Object.fromEntries(pair.files.map(f=>[f.name,f.sha256])),
  artifactRevisionId:packagedOnce.manifest.artifactRevisionId,
  packageSha256:packagedOnce.zipSha256,
  outputStatus:'DRAFT',
  reproducibleWithinBuild:true,
  nativeRubyExecuted:false,
  stellarTargetImportVerified:false,
  indexedEventVerified:false,
  userParserVerified:false,
  deploymentPerformed:false,
};
assert.equal(receipt.stellarTargetImportVerified,false);
assert.equal(receipt.userParserVerified,false);
console.log(JSON.stringify(receipt));
