import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

async function goToMapFields(page:import('@playwright/test').Page,raw:string){
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced'}).click();
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
  await page.getByRole('button',{name:'Review Detected Results'}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  await expect(map).toContainText('Stellar field dictionary 7.0.xs');
  return map;
}

test('fixed Stellar 7.0 Dictionary: conflicting address aliases cannot be bulk-approved',async({page})=>{
  const raw=[
    {src_ip:'192.0.2.11',source_ip:'203.0.113.20',request_status:200},
    {src_ip:'192.0.2.12',source_ip:'203.0.113.21',request_status:403},
  ].map(item=>JSON.stringify(item)).join('\n');
  const map=await goToMapFields(page,raw);
  const suggested=map.getByLabel('Recommended field matches');
  await expect(suggested.getByRole('button',{name:'Apply 0 recommended matches'})).toBeDisabled();
  await expect(suggested.getByText(/multiple source fields map to the same/i)).toHaveCount(2);
  await expect(suggested.getByRole('button',{name:'Apply official mapping src_ip'})).toBeVisible();
  await expect(suggested.getByRole('button',{name:'Apply official mapping source_ip'})).toBeVisible();
  await expect(suggested.getByRole('button',{name:'Apply official mapping request_status'})).toHaveCount(0);
  await suggested.getByRole('button',{name:'Apply official mapping src_ip'}).click();
  await expect(suggested.getByRole('button',{name:'Apply official mapping source_ip'})).toHaveCount(0);
  await expect(map.getByLabel('Field mapping checks')).toContainText('No mapping problems found');
  await expect(map.getByLabel('Field changes only')).toContainText('srcip');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveCount(0);
});

test('fixed Stellar 7.0 Dictionary: official nested process, file, host and user fields require proper types',async({page})=>{
  const row=(pid:number,ip:string)=>({
    process:{name:'powershell.exe',pid},file:{hash:{sha256:'a'.repeat(64)}},
    host:{ip},user:{name:'test.user'},
  });
  const raw=[row(151,'192.0.2.10'),row(152,'192.0.2.11')]
    .map(item=>JSON.stringify(item)).join('\n');
  const map=await goToMapFields(page,raw);
  const suggested=map.getByLabel('Recommended field matches');
  // Auto Parser has already adopted all five unambiguous official names
  // before opening Map Fields; no redundant review suggestion should remain.
  await expect(map.getByLabel('Field mapping summary')).toContainText('Matched to Stellar5');
  await expect(suggested.getByRole('button',{name:'Apply 0 recommended matches'})).toBeDisabled();
  const approvedPaths=await map.locator('input[aria-label^="Stellar field "]')
    .evaluateAll(inputs=>inputs.map(input=>(input as HTMLInputElement).value));
  expect(approvedPaths.sort()).toEqual(
    ['process.name','process.pid','file.hash.sha256','host.ip','user.name'].sort());
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
  await expect(map.getByLabel('Field changes only')).toContainText('process.name');
  await expect(map.getByLabel('Field changes only')).toContainText('host.ip');
  await map.getByRole('button',{name:'Back to Review Fields'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Back to Logs'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
});


test('7.0 nested field mappings generate real backend DRAFT files with checked digests',async({page})=>{
  const raw=[
    {process:{name:'safe.exe',pid:100},file:{hash:{sha256:'a'.repeat(64)}},host:{ip:'192.0.2.11'},user:{name:'synthetic_a'}},
    {process:{name:'safe2.exe',pid:101},file:{hash:{sha256:'b'.repeat(64)}},host:{ip:'192.0.2.12'},user:{name:'synthetic_b'}},
  ].map(item=>JSON.stringify(item)).join('\n');
  const requests:string[]=[];
  page.on('request',req=>{
    if(req.method()==='POST'&&req.url().includes('/api/v1/parser-pairs/')){
      requests.push(req.url());
      expect(req.postData()??'').not.toContain('synthetic_a');
      expect(req.postData()??'').not.toContain('192.0.2.11');
    }
  });
  const map=await goToMapFields(page,raw);
  await expect(map.getByLabel('Field mapping summary')).toContainText('Matched to Stellar5');
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
  await map.getByRole('button',{name:'Create Parser',exact:true}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const response=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const result=await response;
  expect(result.status()).toBe(200);
  const pair=await result.json() as {
    manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean;fileHashes:Record<string,string>};
    files:Array<{name:string;content:string;sha256:string}>;
  };
  expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
  expect(pair.files).toHaveLength(2);
  const ruby=pair.files.find(item=>!item.name.endsWith('.conf'));
  expect(ruby).toBeDefined();
  // The production DRAFT Ruby holds a base64-encoded checked project, not
  // plaintext normalization rules. Decode that project and verify the actual
  // Backend compiler input that was embedded in the downloaded artifact.
  const encoded=ruby!.content.match(/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/)?.[1];
  expect(encoded).toBeTruthy();
  const embedded=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8')) as {
    normalization:{nsFields:Record<string,{normalized_name:string;data_type:string}>};
  };
  for(const [field,type] of [
    ['process.name','string'],['process.pid','integer'],
    ['file.hash.sha256','string'],['host.ip','ip'],['user.name','string'],
  ]){
    expect(embedded.normalization.nsFields[field]).toMatchObject({
      normalized_name:field,data_type:type,
    });
  }
  expect(ruby!.content).not.toContain('synthetic_a');
  const sha=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');
  for(const file of pair.files){
    expect(sha(file.content)).toBe(file.sha256);
    expect(pair.manifest.fileHashes[file.name]).toBe(file.sha256);
    const pendingDownload=page.waitForEvent('download');
    await page.getByLabel('Generated parser files').getByRole('button',{name:file.name,exact:true}).click();
    const downloaded=await pendingDownload;
    expect(sha(await readFile(await downloaded.path()))).toBe(file.sha256);
  }
  expect(requests.some(url=>url.endsWith('/parser-pairs/generate'))).toBe(true);
  await expect(page.getByLabel('Generated parser files')).toContainText('The files have not been installed in a live Stellar system.');
});
