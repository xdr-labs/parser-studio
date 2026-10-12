import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

const sha=(v:string|Uint8Array)=>createHash('sha256').update(v).digest('hex');
const parser='customized_demo_firewall',projectId='draft-demo_firewall';
const config='# Synthetic config\n<source>\n @type udp\n</source>\n';
const ruby='# Synthetic parser\n';
const fileHashes={[parser+'.conf']:sha(config),[parser]:sha(ruby)};
const pair={contract:'host-customized-pair.v0.1',files:[
  {name:parser+'.conf',content:config,sha256:sha(config),bytes:Buffer.byteLength(config)},
  {name:parser,content:ruby,sha256:sha(ruby),bytes:Buffer.byteLength(ruby)},
],manifest:{contract:'host-customized-pair.v0.1',status:'DRAFT',schemaRevision:'0.1',
  projectId,projectRevision:1,engineVerified:false,targetImportVerified:false,
  warnings:[],fileHashes}};
const zip=new Uint8Array([0x50,0x4b,0x03,0x04,0x08,0x09,0x09,0x08,
  0x50,0x4b,0x05,0x06,...Array(18).fill(0)]);
const first={artifactRevisionId:'a'.repeat(64),parserName:parser,projectId,
  projectRevision:1,version:'1.0.0',selectedParserPort:7501,
  receiverProtocols:['udp','tcp'],fileHashes,zipSha256:sha(zip),
  createdAt:'2026-10-12T10:00:00.000Z',targetImportVerified:false,deploymentPerformed:false};
const second={...first,artifactRevisionId:'b'.repeat(64),version:'2.0.0',
  createdAt:'2026-10-12T11:00:00.000Z'};
const capabilities={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],
    extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    httpReceiver:false,multipleDistinctReceiverPorts:false,
    formatCoverage:'reviewed-bounded-subset',multiline:false,arbitraryRuby:false},
  downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const sample='{"action":"allow","src_ip":"198.51.100.10","dst_port":443}\n'+
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}';
async function ready(page:Page){
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(capabilities)}));
  await page.route('**/api/v1/parser-pairs/validate',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify({ok:true,issues:[]})}));
  await page.route('**/api/v1/parser-pairs/generate',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(pair)}));
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(sample);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await page.getByRole('button',{name:'Run Full Browser Test'}).click();
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.getByRole('button',{name:'Validate Backend Input'}).click();
  await expect(page.getByText('Schema PASS · Engine Unverified')).toBeVisible();
  await page.getByRole('button',{name:'Generate 2 Parser Files (DRAFT)'}).click();
  await expect(page.getByLabel('Generated draft parser pair')).toContainText('SHA-256 Verified');
  await page.locator('.guided-revision-history summary').click();
}
const history=(revisions:unknown[])=>({
  contract:'offline-revision-history.v0.1',revisions,persistent:false,deploymentPerformed:false,
});
const diff={contract:'offline-artifact-diff.v0.1',
  fromRevisionId:first.artifactRevisionId,toRevisionId:second.artifactRevisionId,
  projectId,version:{from:'1.0.0',to:'2.0.0',changed:true},
  selectedParserPort:{from:7501,to:7501,changed:false},
  files:[{name:parser,fromSha256:sha(ruby),toSha256:sha(ruby),changed:false},
    {name:parser+'.conf',fromSha256:sha(config),toSha256:sha(config),changed:false}],
  realTargetVerified:false,appliesToDp:false};
function replyZip(route:Parameters<Parameters<Page['route']>[1]>[0],
  snapshot=first,preview=false,tamper=false){
  return route.fulfill({status:200,headers:{
    'content-type':'application/zip','content-length':String(zip.byteLength),
    'content-disposition':'attachment; filename="'+parser+'-r1.zip"',
    'x-parser-zip-sha256':tamper?'0'.repeat(64):snapshot.zipSha256,
    'x-parser-artifact-revision':snapshot.artifactRevisionId,
    ...(preview?{'x-parser-restore-status':'OFFLINE_RESTORE_PREVIEW'}:{}),
  },body:Buffer.from(zip)});
}

test('explicit owner-scoped register/list/hash comparison/immutable ZIP/restore preview works without target traffic',async({page})=>{
  const requests:string[]=[];
  await page.route('**/api/v1/parser-pairs/revisions/**',route=>{
    const request=route.request(),url=new URL(request.url());
    const action=url.pathname.split('/').at(-1)!;
    requests.push(action);
    expect(request.headers()).not.toHaveProperty('authorization');
    expect(request.url()).not.toContain('apiKey');
    if(action==='register'){
      expect(request.method()).toBe('POST');
      const body=request.postDataJSON();
      expect(body).toEqual({pair,version:'1.0.0'});
      expect(JSON.stringify(body)).not.toContain('198.51.100.10');
      expect(JSON.stringify(body)).not.toContain('203.0.113.5');
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(first)});
    }
    if(action==='list'){
      expect(request.method()).toBe('GET');
      expect(url.searchParams.get('projectId')).toBe(projectId);
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(history([first,second]))});
    }
    if(action==='diff'){
      expect(request.postDataJSON()).toEqual({
        fromRevisionId:first.artifactRevisionId,toRevisionId:second.artifactRevisionId});
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(diff)});
    }
    if(action==='download'){
      expect(url.searchParams.get('artifactRevisionId')).toBe(first.artifactRevisionId);
      return replyZip(route);
    }
    if(action==='restore-preview'){
      expect(request.postDataJSON()).toEqual({
        previousRevisionId:first.artifactRevisionId,expectedCurrentRevisionId:second.artifactRevisionId});
      return replyZip(route,first,true);
    }
    throw Error('Unexpected revision operation '+action);
  });
  await ready(page);
  expect(requests).toEqual([]);
  await page.getByRole('button',{name:'Register Current DRAFT (Opt In)'}).click();
  await expect(page.getByLabel('Verified offline revision list')).toContainText('1.0.0');
  await page.getByRole('button',{name:'Load My Revision List'}).click();
  await expect(page.getByLabel('Verified offline revision list')).toContainText('2.0.0');
  await page.getByRole('button',{name:'Compare SHA-256 Only'}).click();
  await expect(page.getByLabel('Offline SHA revision comparison')).toContainText('Listener port changed: No');
  await expect(page.getByLabel('Offline SHA revision comparison')).toContainText('Unchanged');
  const zipEvent=page.waitForEvent('download');
  await page.getByRole('button',{name:'Re-download Verified ZIP'}).click();
  const downloaded=await zipEvent;
  expect(downloaded.suggestedFilename()).toBe(parser+'-r1.zip');
  expect(sha(await readFile(await downloaded.path()))).toBe(first.zipSha256);
  await page.getByRole('button',{name:'Preview Previous ZIP (No Restore)'}).click();
  await expect(page.getByLabel('Verified offline restore preview')).toContainText('No Mutation');
  const previewEvent=page.waitForEvent('download');
  await page.getByRole('button',{name:'Download Verified Preview ZIP'}).click();
  expect(sha(await readFile(await (await previewEvent).path()))).toBe(first.zipSha256);
  expect(requests).toEqual(['register','list','diff','download','restore-preview']);
  const body=await page.locator('.guided-revision-history').innerText();
  expect(body).not.toContain('198.51.100.10');
  expect(body).not.toContain('203.0.113.5');
  expect(body).not.toContain('apiKey=');
  await expect(page.getByText('Native Fluentd and Stellar target ingestion remain unverified.').first()).toBeVisible();
});

test('server default 403 and foreign owner history fail closed, with no download or preview',async({page})=>{
  let mode:'deny'|'foreign'='deny',calls=0;
  await page.route('**/api/v1/parser-pairs/revisions/**',route=>{
    calls++;
    if(mode==='deny')return route.fulfill({status:403,contentType:'application/json',
      body:JSON.stringify({error:'REVISION_HISTORY_DISABLED'})});
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify(history([{...first,projectId:'foreign-tenant',rawLog:'HIGHLY_SENSITIVE_RAW'}]))});
  });
  await ready(page);
  expect(calls).toBe(0);
  await page.getByRole('button',{name:'Load My Revision List'}).click();
  await expect(page.locator('.guided-revision-history [role="alert"]')).toContainText('access denied or unavailable');
  await expect(page.getByLabel('Verified offline revision list')).toHaveCount(0);
  mode='foreign';
  await page.getByRole('button',{name:'Load My Revision List'}).click();
  await expect(page.locator('.guided-revision-history [role="alert"]')).toContainText('Unexpected offline revision response fields.');
  await expect(page.getByLabel('Verified offline revision list')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Re-download Verified ZIP'})).toHaveCount(0);
  expect(await page.locator('.guided-revision-history').innerText()).not.toContain('HIGHLY_SENSITIVE_RAW');
});
test('tampered ZIP SHA never produces a browser download or unverified restore claim',async({page})=>{
  await page.route('**/api/v1/parser-pairs/revisions/**',route=>{
    const action=new URL(route.request().url()).pathname.split('/').at(-1)!;
    if(action==='list')return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify(history([first,second]))});
    if(action==='download')return replyZip(route,first,false,true);
    throw Error('Unexpected request '+action);
  });
  await ready(page);
  await page.getByRole('button',{name:'Load My Revision List'}).click();
  let downloads=0;
  page.on('download',()=>downloads++);
  await page.getByRole('button',{name:'Re-download Verified ZIP'}).click();
  await expect(page.locator('.guided-revision-history [role="alert"]')).toContainText('integrity checks');
  expect(downloads).toBe(0);
  await expect(page.getByLabel('Verified offline restore preview')).toHaveCount(0);
});

test('Mock-only Apply status and explicit approved simulation never become real DP Apply',async({page})=>{
  let statusCalls=0,applyCalls=0;
  await page.route('**/api/v1/parser-pairs/revisions/**',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(history([first]))}));
  await page.route('**/api/v1/parser-pairs/target/apply**',route=>{
    if(route.request().method()==='GET'){
      statusCalls++;
      expect(new URL(route.request().url()).searchParams.get('artifactRevisionId')).toBe(first.artifactRevisionId);
      return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
        contract:'target-apply-mock.v0.1',mode:'MOCK_ONLY',artifactRevisionId:first.artifactRevisionId,
        status:'NOT_ATTEMPTED',ephemeral:true,realTargetVerified:false,
        sensorReadyVerified:false,targetImportVerified:false,realRuntimeParsingVerified:false,
      })});
    }
    applyCalls++;
    expect(route.request().method()).toBe('POST');
    expect(route.request().postDataJSON()).toEqual({
      artifactRevisionId:first.artifactRevisionId,expectedName:parser,
      expectedVersion:'1.0.0',approvalId:'MOCK-OWNER-APPROVAL-123',confirmed:true,
    });
    expect(route.request().postData()).not.toContain('apiKey');
    expect(route.request().postData()).not.toContain('198.51.100.10');
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
      artifactRevisionId:first.artifactRevisionId,
      fileHashes,name:parser,version:'1.0.0',selectedParserPort:7501,
      tenant:'mock-tenant',origin:'https://mock-target.invalid',
      registration:{status:'API_REGISTERED_READBACK',apiReadbackVerified:true,
        realRuntimeParsingVerified:false,sensorReadyVerified:false,targetImportVerified:false},
      mode:'MOCK_ONLY',status:'MOCK_READBACK_VERIFIED',realTargetVerified:false,
    })});
  });
  await ready(page);
  expect(statusCalls+applyCalls).toBe(0);
  await page.getByRole('button',{name:'Load My Revision List'}).click();
  await page.locator('.guided-mock-target summary').click();
  await expect(page.getByRole('button',{name:'Run Approved Mock-only Apply'})).toBeDisabled();
  await page.getByRole('button',{name:'Check My Mock Apply Status'}).click();
  await expect(page.locator('.guided-mock-target [role="status"]')).toContainText('NOT_ATTEMPTED');
  await page.getByLabel('Mock Apply approval ID').fill('MOCK-OWNER-APPROVAL-123');
  await expect(page.getByRole('button',{name:'Run Approved Mock-only Apply'})).toBeDisabled();
  await page.getByLabel('Acknowledge mock-only Apply').check();
  await page.getByRole('button',{name:'Run Approved Mock-only Apply'}).click();
  await expect(page.getByLabel('Verified mock-only Apply result')).toContainText('MOCK_READBACK_VERIFIED');
  await expect(page.getByLabel('Verified mock-only Apply result')).toContainText('No Real Deployment');
  await expect(page.getByLabel('Mock Apply approval ID')).toHaveValue('');
  const storage=await page.evaluate(()=>JSON.stringify(localStorage));
  expect(storage).not.toContain('MOCK-OWNER-APPROVAL-123');
  expect(statusCalls).toBe(1);
  expect(applyCalls).toBe(1);
});

test('default 403 refuses Mock-only Apply without storing approval or showing success',async({page})=>{
  let applyCalls=0;
  await page.route('**/api/v1/parser-pairs/revisions/**',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(history([first]))}));
  await page.route('**/api/v1/parser-pairs/target/apply**',route=>{
    applyCalls++;
    return route.fulfill({status:403,contentType:'application/json',
      body:JSON.stringify({error:'TARGET_APPLY_DISABLED'})});
  });
  await ready(page);
  await page.getByRole('button',{name:'Load My Revision List'}).click();
  await page.locator('.guided-mock-target summary').click();
  await page.getByRole('button',{name:'Check My Mock Apply Status'}).click();
  await expect(page.locator('.guided-mock-target [role="alert"]')).toContainText('access denied or unavailable');
  await expect(page.getByLabel('Verified mock-only Apply result')).toHaveCount(0);
  expect(applyCalls).toBe(1);
});
