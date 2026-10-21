import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';

const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const parserName='customized_demo_firewall';
const conf='<source>\n @type udp\n port 6801\n</source>\n';
const parser='# synthetic parser data\n';
const pair={
  contract:'host-customized-pair.v0.1',
  files:[
    {name:parserName+'.conf',content:conf,sha256:sha(conf),bytes:Buffer.byteLength(conf)},
    {name:parserName,content:parser,sha256:sha(parser),bytes:Buffer.byteLength(parser)},
  ],
  manifest:{
    contract:'host-customized-pair.v0.1',schemaRevision:'0.1',status:'DRAFT',
    engineVerified:false,targetImportVerified:false,
    projectId:'demo-firewall',projectRevision:1,
    fileHashes:{[parserName+'.conf']:sha(conf),[parserName]:sha(parser)},
    warnings:['native compatibility not verified'],
  },
};
const caps={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const tenant='synthetic-tenant';
const prepared={
  contract:'stellar-legacy-poc.v0.1',name:parserName,tenant,version:'1.0.0',port:6801,
  filenames:[parserName,parserName+'.conf'],
  proof:{parserSha256:sha(parser),confSha256:sha(conf),status:'DRAFT',
    targetImportVerified:false,runtimeParsingVerified:false},
  testOnlyWriteEligible:false,apiRegistrationVerified:false,
  runtimeParsingVerified:false,targetImportVerified:false,
};
const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

async function ready(page:Page){
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/parser-pairs/validate',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify({ok:true,issues:[]}),
  }));
  await page.route('**/api/v1/parser-pairs/generate',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(pair),
  }));
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
  await page.locator('.guided-legacy-preflight summary').click();
}

test('read-only Legacy upload-file contract plan never submits credentials or invokes create/update/delete',async({page})=>{
  let calls=0,forbidden=0;
  page.on('request',request=>{
    if(/\/api\/v1\/stellar\/legacy\/(?:create|update|delete)/.test(request.url()))forbidden++;
  });
  await page.route('**/api/v1/stellar/legacy/prepare',route=>{
    calls++;
    expect(route.request().method()).toBe('POST');
    const submitted=route.request().postDataJSON();
    expect(submitted).toEqual({pair,tenant,version:'1.0.0'});
    for(const raw of ['198.51.100.10','203.0.113.5','apiKey','approvalId','confirmed']) {
      expect(JSON.stringify(submitted)).not.toContain(raw);
    }
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(prepared)});
  });
  await ready(page);
  expect(calls).toBe(0);
  const button=page.getByRole('button',{name:'Check Legacy Upload Contract Only'});
  await expect(button).toBeDisabled();
  await page.getByLabel('Legacy dry-run tenant').fill(tenant);
  await expect(button).toBeEnabled();
  await button.click();
  const proof=page.getByLabel('Legacy preflight proof');
  await expect(proof).toContainText('Parser Pair Integrity Verified');
  await expect(proof).toContainText('No Upload');
  await expect(proof).toContainText('Tenant synthetic-tenant');
  await expect(proof).toContainText('Parser listener port 6801');
  await expect(proof).toContainText('unverified');
  expect(calls).toBe(1);
  expect(forbidden).toBe(0);
  await page.getByLabel('Legacy dry-run tenant').fill('tenant-other');
  await expect(proof).toHaveCount(0);
});

test('Legacy preflight rejects forged target verification metadata instead of showing readiness',async({page})=>{
  await page.route('**/api/v1/stellar/legacy/prepare',route=>route.fulfill({
    status:200,contentType:'application/json',
    body:JSON.stringify({...prepared,targetImportVerified:true}),
  }));
  await ready(page);
  await page.getByLabel('Legacy dry-run tenant').fill(tenant);
  await page.getByRole('button',{name:'Check Legacy Upload Contract Only'}).click();
  await expect(page.locator('.guided-legacy-preflight [role="alert"]')).toContainText('Read-only Legacy preflight was denied');
  await expect(page.getByLabel('Legacy preflight proof')).toHaveCount(0);
});

test('invalid tenant identifier is blocked before any backend preflight request',async({page})=>{
  let sent=0;
  await page.route('**/api/v1/stellar/legacy/prepare',route=>{sent++;return route.abort();});
  await ready(page);
  await page.getByLabel('Legacy dry-run tenant').fill('../bad');
  await expect(page.getByRole('button',{name:'Check Legacy Upload Contract Only'})).toBeDisabled();
  expect(sent).toBe(0);
});
