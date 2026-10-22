import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

const threatHash='a'.repeat(64);
const records=[
  {event_type:'threat',src_ip:'192.0.2.11',action:'deny',sha256:threatHash,request_status:403},
  {event_type:'threat',src_ip:'192.0.2.12',action:'block',sha256:threatHash,request_status:404},
  {event_type:'user',username:'김민수',login_result:'failure',host:{ip:'198.51.100.5'}},
  {event_type:'user',username:'山田',login_result:'success',host:{ip:'198.51.100.6'}},
  {event_type:'asset',host:{name:'asset-01'},process:{name:'agent.exe'}},
  {event_type:'asset',host:{name:'asset-02'},process:{name:'agent2.exe'}},
];
const raw=records.map(value=>JSON.stringify(value)).join('\n');
const digest=(data:Buffer|string)=>createHash('sha256').update(data).digest('hex');

test('novice reviews three Stellar 7.0 event families and downloads one scoped DRAFT parser',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the exact-head offline authoring Backend and Python Multi-Pass.');
  test.setTimeout(90_000);
  const pageErrors:string[]=[];
  const requestErrors:number[]=[];
  const requests:string[]=[];
  page.on('pageerror',error=>pageErrors.push(error.message));
  page.on('response',response=>{
    if(response.url().includes('/api/')&&response.status()>=500)
      requestErrors.push(response.status());
  });
  page.on('request',request=>{
    if(request.method()!=='POST'||!request.url().includes('/parser-pairs/'))return;
    requests.push(request.url());
    for(const privateValue of ['김민수','山田','192.0.2.11'])
      expect(request.postData()??'').not.toContain(privateValue);
  });
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('6/6 events analyzed locally',{timeout:20000});
  const reviewButton=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(reviewButton).toBeEnabled({timeout:20000});
  await reviewButton.click();
  const stage=page.getByLabel('Review Fields stage');
  await expect(stage).toBeVisible();
  const panel=page.locator('details[aria-label="Configure one parser for event types"]');
  await panel.locator('summary').first().click();
  await expect(panel.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await expect(panel.getByLabel('Proposed event type rules')).not.toContainText('김민수');
  for(const family of ['threat','user','asset']){
    const detail=panel.locator('details[aria-label="Type-specific mappings for '+family+'"]');
    await detail.locator('summary').click();
  }
  for(const [family,field] of [
    ['threat','src_ip'],['threat','action'],['threat','sha256'],
    ['user','username'],['user','login_result'],['user','host.ip'],
    ['asset','host.name'],['asset','process.name'],
  ]){
    const button=panel.getByRole('button',{name:'Use Stellar 7.0 '+family+' '+field});
    await expect(button).toBeEnabled();
    await button.click();
    await expect(panel).toContainText('The 7.0 mapping is selected for '+family+' only.');
  }
  await panel.getByLabel('Approve explicit family routing changes').check();
  const apply=panel.getByRole('button',{name:'Apply reviewed event types to this parser'});
  await expect(apply).toBeEnabled();
  await apply.click();
  await expect(panel.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await stage.getByRole('button',{name:'Map Fields'}).click();
  const mappings=page.getByLabel('Map Fields stage');
  await expect(mappings).toBeVisible();
  await mappings.getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const generator=page.waitForResponse(response=>
    response.url().endsWith('/parser-pairs/generate')&&response.request().method()==='POST');
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const response=await generator;
  expect(response.status()).toBe(200);
  const pair=await response.json() as {
    manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean;fileHashes:Record<string,string>};
    files:Array<{name:string;content:string;sha256:string}>;
  };
  expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
  expect(pair.files).toHaveLength(2);
  const ruby=pair.files.find(item=>!item.name.endsWith('.conf'));
  expect(ruby).toBeDefined();
  const encoded=/Base64\.strict_decode64\('([A-Za-z0-9+/=]+)'\)/.exec(ruby!.content)?.[1];
  expect(encoded).toBeTruthy();
  const embedded=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8')) as {
    normalization:{eventProfiles:{unknown:string;variants:Array<{
      name:string;
      topFields:Record<string,{normalized_name:string;data_type:string}>;
      nsFields:Record<string,{normalized_name:string;data_type:string}>;
    }>}}
  };
  const variants=embedded.normalization.eventProfiles.variants;
  expect(embedded.normalization.eventProfiles.unknown).toBe('reject');
  expect(variants.map(item=>item.name)).toEqual(['threat','user','asset']);
  expect(variants.find(item=>item.name==='threat')?.topFields.src_ip)
    .toMatchObject({normalized_name:'srcip',data_type:'ip'});
  expect(variants.find(item=>item.name==='threat')?.topFields.sha256)
    .toMatchObject({normalized_name:'sha256',data_type:'string'});
  expect(variants.find(item=>item.name==='user')?.nsFields['host.ip'])
    .toMatchObject({normalized_name:'host.ip',data_type:'ip'});
  expect(variants.find(item=>item.name==='asset')?.nsFields['process.name'])
    .toMatchObject({normalized_name:'process.name',data_type:'string'});
  expect(JSON.stringify(embedded)).not.toContain('김민수');
  expect(JSON.stringify(embedded)).not.toContain('192.0.2.11');
  for(const file of pair.files){
    expect(digest(file.content)).toBe(file.sha256);
    expect(pair.manifest.fileHashes[file.name]).toBe(file.sha256);
    const downloaded=page.waitForEvent('download');
    await page.getByLabel('Generated parser files').getByRole('button',{name:file.name,exact:true}).click();
    expect(digest(await readFile(await (await downloaded).path()))).toBe(file.sha256);
  }
  await expect(page.getByLabel('Generated parser files')).toContainText(
    'The files have not been installed in a live Stellar system.');
  expect(requests.some(item=>item.endsWith('/parser-pairs/generate'))).toBe(true);
  expect(pageErrors).toEqual([]);
  expect(requestErrors).toEqual([]);
  await page.getByRole('button',{name:/Add Logs/}).first().click();
  await expect(input).toHaveValue(raw);
});
