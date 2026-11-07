/** Verify the quarantined Fluentd process receipt; emit hashes/counts only. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyNativeProjectReport}
  from '../../backend/src/native-project-verification';
import {prepareH2Synthetic} from '../../backend/test/h2-isolated-native-fixture';

if(process.argv.length!==3)throw Error('H2_RECEIPT_ARGUMENT');
const reportPath=process.argv[2]!;
const raw=readFileSync(reportPath,'utf8');
if(raw.length>65536)throw Error('H2_RECEIPT_SIZE');
const receipt=verifyNativeProjectReport(JSON.parse(raw),prepareH2Synthetic());
assert.equal(receipt.nativeUserParserVerified,true);
assert.equal(receipt.eventCount,2);
assert.equal(receipt.eventsPassed,2);
assert.equal(receipt.recordHashMatches,2);
assert.equal(receipt.eventTimeMatches,2);
assert.equal(receipt.targetImportVerified,false);
assert.equal(receipt.sensorTrafficSent,false);
assert.equal(receipt.rawValuesReturned,false);
const safe={
  contract:'parser-studio.h2-isolated-ci-evidence.v1',
  sourceSha256:receipt.sourceSha256,
  parserSha256:receipt.parserSha256,
  confSha256:receipt.confSha256,
  verifiedEvents:receipt.eventsPassed,
  ruby:receipt.ruby,fluentd:receipt.fluentd,
  networkDisabled:true,readonlyRoot:true,nonroot:true,capabilitiesDropped:true,
  resourceLimitsEnforced:true,
  publicNativeServiceEnabled:false,targetVerified:false,rawValuesReturned:false,
};
process.stdout.write(JSON.stringify(safe)+'\n');
