/**
 * Compare separately produced fixed-synthetic Native and Web CI artifact
 * attestations. This rejects drift between jobs; it does NOT establish
 * build-once distribution, Stellar import or customer-log correctness.
 *
 * Intentionally outputs only status and the verified Git source SHA.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

const SHA=/^[a-f0-9]{64}$/;
const GIT_SHA=/^[a-f0-9]{40}$/;
const fields=[
  'sourceHead','sourceTree','sourceContractHash','runtimeProfileSha256',
  'sharedMappingPolicySha256','compilerTemplateSha256',
  'artifactRevisionId','packageSha256',
];
const keys=[
  'contract','sourceHead','sourceTree','worktreeDirty',
  'sourceContractHash','runtimeProfileSha256','sharedMappingPolicySha256',
  'compilerTemplateSha256','artifactSource','fileHashes',
  'artifactRevisionId','packageSha256','outputStatus',
  'reproducibleWithinBuild','nativeRubyExecuted',
  'stellarTargetImportVerified','indexedEventVerified',
  'userParserVerified','deploymentPerformed',
];
const expectedFiles=['customized_sample_firewall','customized_sample_firewall.conf'];

function verifyReceipt(receipt,expectedHead){
  assert.ok(receipt&&typeof receipt==='object'&&!Array.isArray(receipt),'BAD_LINEAGE_RECEIPT');
  assert.deepEqual(Object.keys(receipt).sort(),[...keys].sort(),'UNEXPECTED_LINEAGE_FIELDS');
  assert.equal(receipt.contract,'parser-studio.executable-artifact-lineage.v1');
  assert.equal(receipt.sourceHead,expectedHead,'SOURCE_HEAD_MISMATCH');
  assert.ok(GIT_SHA.test(receipt.sourceTree),'INVALID_GIT_TREE');
  for(const key of fields.filter(x=>!['sourceHead','sourceTree'].includes(x))){
    assert.ok(SHA.test(receipt[key]),'INVALID_SHA256_'+key);
  }
  assert.equal(receipt.worktreeDirty,false,'DIRTY_SOURCE');
  assert.equal(receipt.artifactSource,'fixed-public-synthetic');
  assert.equal(receipt.outputStatus,'DRAFT');
  assert.equal(receipt.reproducibleWithinBuild,true);
  assert.equal(receipt.nativeRubyExecuted,false);
  for(const flag of [
    'stellarTargetImportVerified','indexedEventVerified',
    'userParserVerified','deploymentPerformed',
  ])assert.equal(receipt[flag],false,'FALSE_TARGET_PROOF_'+flag);
  assert.deepEqual(Object.keys(receipt.fileHashes).sort(),expectedFiles,
    'SYNTHETIC_PAIR_FILE_COUNT');
  for(const [name,hash] of Object.entries(receipt.fileHashes)){
    assert.ok(expectedFiles.includes(name));
    assert.ok(SHA.test(hash),'INVALID_ARTIFACT_HASH');
  }
}
export function verifyCrossJobLineage(native,web,expectedHead){
  assert.ok(GIT_SHA.test(expectedHead),'INVALID_EXPECTED_SOURCE_HEAD');
  verifyReceipt(native,expectedHead);
  verifyReceipt(web,expectedHead);
  assert.deepEqual(web,native,'CROSS_JOB_LINEAGE_MISMATCH');
  return Object.freeze({
    contract:'parser-studio.cross-job-artifact-lineage.v1',
    result:'PASS',
    sourceHead:expectedHead,
    evidenceSources:2,
    sameExactOutputHashes:true,
    independentTargetRuntimeVerified:false,
    buildOnceDistributionVerified:false,
    stellarIndexedEventVerified:false,
  });
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  if(process.argv.length!==4)throw Error('EXACT_TWO_JOB_RECEIPTS_REQUIRED');
  const head=process.env.PARSER_STUDIO_EXPECTED_SOURCE_HEAD;
  if(!head)throw Error('MISSING_VERIFIED_SOURCE_HEAD');
  const inputs=process.argv.slice(2).map(filename=>{
    const raw=readFileSync(filename);
    if(raw.byteLength>8192)throw Error('UNBOUNDED_LINEAGE_RECEIPT');
    return JSON.parse(raw.toString('utf8'));
  });
  const verified=verifyCrossJobLineage(inputs[0],inputs[1],head);
  console.log('CROSS_JOB_ARTIFACT_LINEAGE_PASS source_head='+verified.sourceHead+
    ' sources=2 match=true target_indexed=false build_once=false');
}
