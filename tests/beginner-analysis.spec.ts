import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const first='{"action":"allow","srcip":"192.0.2.1"}';
const second='Oct 15 10:00:00 edge fw: Built inbound TCP connection 42 for outside:192.0.2.5/443';
const raw=first+'\n'+second;
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const firstBytes=Buffer.byteLength(first);
const secondBytes=Buffer.byteLength(second);
const response={
 contract:'parser-studio.multipass-source-batch-preview.v0.1',
 sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),eventCount:2,
 events:[
  {index:0,startByte:0,endByte:firstBytes,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',syntax:'JSON',
   sourceSha256:sha(first),sourceBytes:firstBytes,fields:{action:'allow',srcip:'192.0.2.1'},
   spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
  }},
  {index:1,startByte:firstBytes+1,endByte:firstBytes+1+secondBytes,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',syntax:'BSD_SYSLOG+UNKNOWN',
   sourceSha256:sha(second),sourceBytes:secondBytes,fields:{syslog_host:'edge'},
   spans:[],residuals:[{startByte:27,endByte:secondBytes}],
   issues:['UNSUPPORTED_BSD_BODY'],nativeVerified:false,targetVerified:false,
  }},
 ],
 separators:[{startByte:firstBytes,endByte:firstBytes+1,kind:'WHITESPACE'}],
 nativeVerified:false,targetVerified:false,
};

test('first-time user gets one Analyze action, plain failure location and a ready ChatGPT prompt',async({page})=>{
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(response)}));
 await page.goto('/');
 await expect(page.getByRole('heading',{name:'Paste security logs. Parser Studio will show what works and what needs fixing.'})).toBeVisible();
 await expect(page.getByRole('button',{name:'Analyze Logs'})).toBeDisabled();
 await expect(page.getByLabel('Local Multi-Pass source engine')).toBeHidden();
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('1 of 2 log events parsed completely');
 await expect(summary).toContainText('1 event needs attention');
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Part of this event still needs parsing');
 await expect(problem).toContainText('The Syslog header was recognized but the message body still needs an extraction rule.');
 await expect(problem).toContainText('Recommended fix · Create a rule for the remaining message text');
 await expect(problem).toContainText('Built inbound TCP connection');
 await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
 const prompt=page.getByLabel('Generated ChatGPT repair prompt');
 await expect(prompt).toContainText('Detected syntax: BSD_SYSLOG+UNKNOWN');
 await expect(prompt).toContainText('Original problem event:');
 await expect(prompt).toContainText('unique named captures (?<field>...)');
 await expect(prompt).toContainText('Return only one ParserRecipe v0.2 JSON object');
 await expect(prompt).toContainText('parse_regex');
 await expect(page.getByLabel('AI result verification')).toBeVisible();
 await expect(page.getByLabel('Local Multi-Pass source engine')).toBeHidden();
 await expect(page.getByLabel('Existing parser review and import')).toBeHidden();
 await expect(page.getByLabel('Local logical boundary review')).toBeHidden();
 await expect(page.getByLabel('Optional isolated Drain3 mining')).toBeHidden();
 await expect(page.getByLabel('Public synthetic parser fingerprints')).toBeHidden();
 await expect(page.getByLabel('Authorized Test Lab session recovery')).toHaveCount(0);
 await page.getByRole('button',{name:'Advanced'}).click();
 await expect(page.getByLabel('Local Multi-Pass source engine')).toBeVisible();
 await expect(page.getByLabel('Existing parser review and import')).toBeVisible();
 await expect(page.getByLabel('Authorized Test Lab session recovery')).toBeVisible();
});

test('complete structured logs get a simple success result without technical status language',async({page})=>{
 const one=first+'\n'+first.replace('192.0.2.1','192.0.2.2');
 const a=first,b=first.replace('192.0.2.1','192.0.2.2');
 const ab=Buffer.byteLength(a);
 const ok={...response,sourceSha256:sha(one),sourceBytes:Buffer.byteLength(one),eventCount:2,
  events:[
   {index:0,startByte:0,endByte:ab,preview:{...response.events[0].preview,sourceSha256:sha(a),sourceBytes:Buffer.byteLength(a)}},
   {index:1,startByte:ab+1,endByte:Buffer.byteLength(one),preview:{...response.events[0].preview,sourceSha256:sha(b),sourceBytes:Buffer.byteLength(b),fields:{action:'allow',srcip:'192.0.2.2'}}},
  ],
  separators:[{startByte:ab,endByte:ab+1,kind:'WHITESPACE'}],
 };
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(ok)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(one);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('2 of 2 log events parsed completely');
 await expect(page.getByLabel('Parse problem inspector')).toHaveCount(0);
 await expect(page.getByText('SOURCE_PARSED',{exact:true})).toHaveCount(0);
});


test('structured partial result exposes strict ParserRecipe paste and rejects an invalid AI result',async({page})=>{
 const jsonRaw='{"action":"allow","detail":{"user":"alice"}}';
 const bytes=Buffer.byteLength(jsonRaw);
 const userStart=Buffer.byteLength('{"action":"allow","detail":{"user":"');
 const userEnd=userStart+Buffer.byteLength('alice');
 const structured={
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'PARTIAL',syntax:'JSON',sourceSha256:sha(jsonRaw),sourceBytes:bytes,
  fields:{action:'allow'},spans:[{path:'action',startByte:11,endByte:16}],
  residuals:[{startByte:userStart,endByte:userEnd}],issues:['JSON_PATH_REVIEW_REQUIRED'],
  nativeVerified:false,targetVerified:false,
 };
 await page.route('**/api/v1/multipass/preview',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(structured)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(jsonRaw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Recommended fix · Map the remaining JSON fields');
 await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
 const prompt=page.getByLabel('Generated ChatGPT repair prompt');
 await expect(prompt).toContainText('Grok, JSONata execution, scripting and executable Ruby are not ParserRecipe stages.');
 await expect(prompt).toContainText('Return only one ParserRecipe v0.2 JSON object');
 const aiReview=page.getByLabel('AI result verification');
 await expect(aiReview).toBeVisible();
 await aiReview.getByLabel('ChatGPT JSON result').fill('{}');
 await aiReview.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(aiReview).toContainText('ChatGPT result rejected');
});


test('Cisco FTD recovery completes the user + ChatGPT + holdout + explicit approval loop',async({page})=>{
 const training=[
  '<134>May 5 17:51:17 dev01 %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500 (81.2.69.144/53500) to fw111:192.168.2.2/53500 (81.2.69.144/53500)',
  '<134>May 5 17:51:18 dev01 %FTD-6-302015: Built inbound UDP connection 112 for net:10.10.10.11/53501 (81.2.69.145/53501) to fw111:192.168.2.3/53501 (81.2.69.145/53501)',
 ].join('\n');
 const holdout=[
  '<134>May 5 17:52:17 dev02 %FTD-6-302013: Built outbound TCP connection 211 for dmz:10.20.10.10/44400 (81.2.69.146/44400) to inside:192.168.3.2/8443 (81.2.69.146/8443)',
  '<134>May 5 17:52:18 dev02 %FTD-6-302015: Built outbound UDP connection 212 for dmz:10.20.10.11/44401 (81.2.69.147/44401) to inside:192.168.3.3/53 (81.2.69.147/53)',
 ].join('\n');
 const pattern='^%FTD-\\d-\\d+: Built \\w+ \\w+ connection (?<connection_id>\\d+) for [^:]+:(?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<src_port>\\d+).{0,80} to [^:]+:(?<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)/(?<dst_port>\\d+).{0,80}$';
 const trainingRows=training.split('\n');
 const fullBytes=Buffer.byteLength(training);
 let cursor=0;
 const events=trainingRows.map((event,index)=>{
  const start=cursor,end=start+Buffer.byteLength(event);cursor=end+(index<trainingRows.length-1?1:0);
  const messageStart=Buffer.byteLength(event.slice(0,event.indexOf('%FTD')));
  return {index,startByte:start,endByte:end,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',syntax:'BSD_SYSLOG+UNKNOWN',
   sourceSha256:sha(event),sourceBytes:Buffer.byteLength(event),fields:{syslog_hostname:index?'dev01':'dev01'},
   spans:[],residuals:[{startByte:messageStart,endByte:Buffer.byteLength(event)}],
   issues:['UNSUPPORTED_BSD_BODY'],nativeVerified:false,targetVerified:false,
  }};
 });
 const batch={contract:'parser-studio.multipass-source-batch-preview.v0.1',
  sourceSha256:sha(training),sourceBytes:fullBytes,eventCount:2,events,
  separators:[{startByte:events[0]!.endByte,endByte:events[0]!.endByte+1,kind:'WHITESPACE'}],
  nativeVerified:false,targetVerified:false};
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(batch)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(training);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Recommended fix · Create a rule for the remaining message text');
 await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'syslog_rfc3164',bodyFormat:'regex',
  sample:{sha256:sha(training),events:2},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'unwrap_syslog',version:3164,mode:'strict_header'},
   {op:'parse_regex',pattern},
   {op:'map_field',source:'body.connection_id',target:'custom.connection_id',data_type:'integer',group:'top_fields'},
   {op:'cast_type',target:'custom.connection_id',data_type:'integer'},
   {op:'map_field',source:'body.src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
   {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
   {op:'map_field',source:'body.src_port',target:'custom.source_port',data_type:'port',group:'top_fields'},
   {op:'cast_type',target:'custom.source_port',data_type:'port'},
   {op:'map_field',source:'body.dst_ip',target:'custom.destination_ip',data_type:'ip',group:'top_fields'},
   {op:'cast_type',target:'custom.destination_ip',data_type:'ip'},
   {op:'map_field',source:'body.dst_port',target:'custom.destination_port',data_type:'port',group:'top_fields'},
   {op:'cast_type',target:'custom.destination_port',data_type:'port'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 const ai=page.getByLabel('AI result verification');
 await ai.getByLabel('ChatGPT JSON result').fill(JSON.stringify(recipe));
 await ai.getByLabel('Additional test logs').fill(holdout);
 await ai.getByLabel('Confirm different test examples').check();
 await ai.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(ai).toContainText('Fix passed: full parser recovery');
 await ai.getByLabel('Approve tested fix').check();
 await ai.getByRole('button',{name:'Apply Verified Fix'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('2 of 2 log events parsed completely');
 await expect(summary).toContainText('reviewed parser fix passes the current sample');
 await expect(page.getByLabel('Parse problem inspector')).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
});


test('ChatGPT recovery cannot discard values already extracted by Multi-Pass',async({page})=>{
 const source='ALLOW 192.0.2.1 alice';
 const holdout='DENY 192.0.2.2 bob\nALLOW 192.0.2.3 carol';
 const startIp=Buffer.byteLength('ALLOW '),endIp=startIp+Buffer.byteLength('192.0.2.1');
 const startUser=endIp+1,endUser=startUser+Buffer.byteLength('alice');
 const preview={
  contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
  syntax:'GENERIC_STRUCTURAL+POSITIONAL',sourceSha256:sha(source),sourceBytes:Buffer.byteLength(source),
  fields:{generic:{action:'ALLOW',src:'192.0.2.1',user:'alice'}},
  spans:[
   {path:'generic.action',startByte:0,endByte:5},
   {path:'generic.src',startByte:startIp,endByte:endIp},
   {path:'generic.user',startByte:startUser,endByte:endUser},
  ],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
 };
 await page.route('**/api/v1/multipass/preview',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(preview)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Fields found — one more rule is needed');
 await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
 const recipe={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
  sample:{sha256:sha(source),events:1},
  stages:[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_regex',pattern:'^(?<action>\\w+) (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+) \\w+$'},
   {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
   {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
   {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
 const ai=page.getByLabel('AI result verification');
 await ai.getByLabel('ChatGPT JSON result').fill(JSON.stringify(recipe));
 await ai.getByLabel('Additional test logs').fill(holdout);
 await ai.getByLabel('Confirm different test examples').check();
 await ai.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(ai).toContainText('would drop 1 of 3 source value occurrences already extracted by Parser Studio');
 await expect(ai.getByLabel('Approve tested fix')).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
});

test('metadata-only source anomaly explains that no bytes were dropped and does not invent an extraction fix',async({page})=>{
 const raw='<85>1 2023-01-13T10:10:16--5:00 gw CP-GW - Log [Fields@1 src="192.0.2.1" src="192.0.2.2" ]';
 const response={
  contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',
  syntax:'SYSLOG_SOURCE_ANOMALIES_PRESERVED',sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),
  fields:{syslog:{structured_data:{src:['192.0.2.1','192.0.2.2']}}},spans:[],residuals:[],
  issues:['RFC5424_TIMESTAMP_INVALID','RFC5424_DUPLICATE_SD_KEY','RFC5424_SD_TRAILING_SPACE_NONSTANDARD'],
  nativeVerified:false,targetVerified:false,
 };
 await page.route('**/api/v1/multipass/preview',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(response)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Fields were extracted, but source metadata needs review');
 await expect(problem).toContainText('source metadata warning · no source bytes dropped');
 await expect(problem).toContainText('Recommended fix · Review source metadata');
 await expect(problem.locator('mark')).toHaveCount(0);
 await problem.getByRole('button',{name:'Review with ChatGPT'}).click();
 const prompt=page.getByLabel('Generated ChatGPT repair prompt');
 await expect(prompt).toContainText('parser-studio.source-metadata-review.v0.1');
 await expect(prompt).toContainText('Do not propose a Regex merely to hide malformed source metadata.');
 await expect(page.getByLabel('AI result verification')).toHaveCount(0);
});


test('unknown non-Syslog text recommends a bounded text pattern without inventing Syslog context',async({page})=>{
 const raw='ALERT#A17#192.0.2.5#198.51.100.4#udp#53#deny';
 const response={
  contract:'parser-studio.multipass-source-preview.v0.1',status:'RAW_ONLY',syntax:'UNKNOWN',
  sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),fields:{},spans:[],
  residuals:[{startByte:0,endByte:Buffer.byteLength(raw)}],issues:['NO_SUPPORTED_GRAMMAR'],
  nativeVerified:false,targetVerified:false,
 };
 await page.route('**/api/v1/multipass/preview',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(response)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Recommended fix · Create a rule for this text format');
 await expect(problem).toContainText('could not identify a standard format');
 await expect(problem).not.toContainText('Keep the detected Syslog context');
 await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
 const prompt=page.getByLabel('Generated ChatGPT repair prompt');
 await expect(prompt).toContainText('Recommended repair method: Create a rule for this text format');
 await expect(prompt).toContainText('could not identify a standard format');
});


test('beginner sees a clear UI/backend version mismatch instead of a vague backend unavailable error',async({page})=>{
 const source=first;
 const bytes=Buffer.byteLength(source);
 const preview={
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'SOURCE_PARSED',syntax:'JSON',sourceSha256:sha(source),sourceBytes:bytes,
  fields:{action:'allow',srcip:'192.0.2.1'},spans:[],residuals:[],issues:[],
  nativeVerified:false,targetVerified:false,
 };
 await page.route('**/api/v1/multipass/preview',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(preview)}));
 await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
  status:200,contentType:'application/json',body:JSON.stringify({
   contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
   authoring:{
    receiverProtocols:['udp','tcp'],extractionFormats:['json'],
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,
    multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false,
    boundedRegexNamedCaptureSubset:true,boundedRegexMaxPatternChars:256,
    boundedRegexRuntimeTimeoutMs:50,
   },
   import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
   verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
   limits:{maxProjectBodyBytes:65536,maxInspectBodyBytes:65536},
  }),
 }));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 await expect(page.getByLabel('Beginner analysis summary')).toContainText('1 of 1 log event parsed completely');
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(review).toBeEnabled();
 await review.click();
 const alert=page.getByRole('alert');
 await expect(alert).toContainText('Parser Studio components are out of sync');
 await expect(alert).toContainText('Log analysis succeeded');
 await expect(alert).toContainText('Update or restart the development backend');
 await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
});
