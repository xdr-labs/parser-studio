import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const sha=(bytes:string|Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const config='# Synthetic Fluentd config\n<source>\n @type udp\n</source>\n';
const fragment='# Synthetic parser fragment\n';
const parserName='customized_demo_firewall';
const pair={
  contract:'host-customized-pair.v0.1',
  files:[
    {name:parserName+'.conf',content:config,sha256:sha(config),bytes:Buffer.byteLength(config)},
    {name:parserName,content:fragment,sha256:sha(fragment),bytes:Buffer.byteLength(fragment)},
  ],
  manifest:{
    contract:'host-customized-pair.v0.1',status:'DRAFT',schemaRevision:'0.1',
    projectId:'demo-firewall',projectRevision:1,
    engineVerified:false,targetImportVerified:false,
    fileHashes:{[parserName+'.conf']:sha(config),[parserName]:sha(fragment)},
    warnings:['Native engine and target import have not been verified'],
  },
};
const capabilities={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{
    receiverProtocols:['udp','tcp'],
    extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    httpReceiver:false,multipleDistinctReceiverPorts:false,
    formatCoverage:'reviewed-bounded-subset',multiline:false,arbitraryRuby:false,
  },
  downloads:{
    individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true,
  },
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const zipped=new Uint8Array([0x50,0x4b,0x03,0x04,0x10,0x20,0x30,0x40,0x50,0x4b,0x05,0x06,...Array(18).fill(0)]);
const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

async function readyForPackage(page:Page, caps:unknown=capabilities){
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/parser-pairs/validate',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify({ok:true,issues:[]}),
  }));
  await page.route('**/api/v1/parser-pairs/generate',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(pair),
  }));
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(sample);
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/5\. 검사·수정/}).click();
  await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.getByRole('button',{name:'백엔드 입력 검사'}).click();
  await expect(page.getByText('Schema PASS · 엔진 미검증')).toBeVisible();
  await page.getByRole('button',{name:'파서 초안 2개 파일 생성 (DRAFT)'}).click();
  await expect(page.getByLabel('Generated draft parser pair')).toContainText('SHA-256 무결성 확인');
}

test('checks approved same-origin packaged ZIP, version/sha/port and downloads without customer sample or key',async({page})=>{
  let packages=0;
  await page.route('**/api/v1/parser-pairs/package',route=>{
    packages++;
    const body=route.request().postDataJSON();
    expect(body).toEqual({pair,version:'1.0.0'});
    expect(JSON.stringify(body)).not.toContain('198.51.100.10');
    expect(JSON.stringify(body)).not.toContain('203.0.113.5');
    expect(JSON.stringify(body)).not.toContain('apiKey');
    return route.fulfill({status:200,headers:{
      'content-type':'application/zip',
      'content-disposition':'attachment; filename="'+parserName+'-r1.zip"',
      'content-length':String(zipped.byteLength),
      'x-parser-artifact-revision':'a'.repeat(64),
      'x-parser-zip-sha256':sha(zipped),
      'x-parser-listener-port':'7501',
    },body:Buffer.from(zipped)});
  });
  await readyForPackage(page);
  expect(packages).toBe(0);
  const version=page.getByLabel('Draft ZIP package version');
  await expect(version).toHaveValue('1.0.0');
  const promised=page.waitForEvent('download');
  await page.getByRole('button',{name:'DRAFT ZIP 패키지 다운로드'}).click();
  const file=await promised;
  expect(file.suggestedFilename()).toBe(parserName+'-r1.zip');
  expect(sha(await readFile(await file.path()))).toBe(sha(zipped));
  await expect(page.getByLabel('Draft ZIP integrity receipt')).toContainText('수신 포트 7501');
  await expect(page.getByLabel('Draft ZIP integrity receipt')).toContainText('미검증');
  expect(packages).toBe(1);
});

test('older backend without exact packaging capability cannot receive a ZIP POST',async({page})=>{
  let sent=0;
  await page.route('**/api/v1/parser-pairs/package',route=>{sent++;return route.abort();});
  const {downloads:_skip,...withoutDownloads}=capabilities;
  await readyForPackage(page,withoutDownloads);
  await page.getByRole('button',{name:'DRAFT ZIP 패키지 다운로드'}).click();
  await expect(page.locator('.guided-package-download [role="alert"]')).toContainText('지원되지 않거나');
  expect(sent).toBe(0);
});

test('tampered ZIP hash blocks download and never displays verified revision',async({page})=>{
  await page.route('**/api/v1/parser-pairs/package',route=>route.fulfill({
    status:200,headers:{
      'content-type':'application/zip',
      'content-disposition':'attachment; filename="'+parserName+'-r1.zip"',
      'content-length':String(zipped.byteLength),
      'x-parser-artifact-revision':'a'.repeat(64),
      'x-parser-zip-sha256':'0'.repeat(64),
      'x-parser-listener-port':'7501',
    },body:Buffer.from(zipped),
  }));
  await readyForPackage(page);
  await page.getByRole('button',{name:'DRAFT ZIP 패키지 다운로드'}).click();
  await expect(page.locator('.guided-package-download [role="alert"]')).toBeVisible();
  await expect(page.getByLabel('Draft ZIP integrity receipt')).toHaveCount(0);
});
