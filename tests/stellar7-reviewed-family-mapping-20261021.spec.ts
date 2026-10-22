import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const source=[
  {event_type:'threat',src_ip:'192.0.2.50',action:'block',sha256:'a'.repeat(32)},
  {event_type:'threat',src_ip:'192.0.2.51',action:'deny',sha256:'b'.repeat(32)},
  {event_type:'user',username:'김민수',login_result:'failure'},
  {event_type:'user',username:'山田',login_result:'success'},
  {event_type:'asset',host:{name:'asset-01'},process:{name:'sensor.exe'}},
  {event_type:'asset',host:{name:'asset-02'},process:{name:'sensor2.exe'}},
].map(value=>JSON.stringify(value)).join('\n');

test('novice explicitly reviews 7.0 type-specific suggestions and downloads one conditional DRAFT',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the actual isolated offline current-source Backend and Multi-Pass.');
  test.setTimeout(90_000);
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  const raw=page.getByLabel('Auto Parser raw logs');
  await raw.fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('6/6 events analyzed locally',{timeout:20000});
  const reviewButton=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(reviewButton).toBeEnabled({timeout:20000});
  await reviewButton.click();
  const review=page.getByLabel('Review Fields stage');
  await expect(review).toBeVisible();
  const panel=page.locator('details[aria-label="Configure one parser for event types"]');
  await panel.locator('summary').first().click();
  await expect(panel.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  const threat=panel.locator('details[aria-label="Type-specific mappings for threat"]');
  await threat.locator('summary').click();
  // Auto Parser may preserve its first vendor-only field as src_ip
  // instead of custom.src_ip; neither is yet an official 7.0 srcip.
  expect(await threat.getByLabel('threat output for src_ip').inputValue()).not.toBe('srcip');
  await expect(threat.getByRole('button',{name:'Use Stellar 7.0 threat sha256'})).toHaveCount(0);
  await expect(threat).toContainText('Review only');
  await threat.getByRole('button',{name:'Use Stellar 7.0 threat src_ip'}).click();
  await expect(threat.getByLabel('threat output for src_ip')).toHaveValue('srcip');
  await threat.getByRole('button',{name:'Use Stellar 7.0 threat action'}).click();
  const user=panel.locator('details[aria-label="Type-specific mappings for user"]');
  await user.locator('summary').click();
  await user.getByRole('button',{name:'Use Stellar 7.0 user username'}).click();
  const asset=panel.locator('details[aria-label="Type-specific mappings for asset"]');
  await asset.locator('summary').click();
  await asset.getByRole('button',{name:'Use Stellar 7.0 asset host.name'}).click();
  await panel.getByLabel('Approve explicit family routing changes').check();
  await panel.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(panel.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  // The original raw-log textarea belongs to Add Logs, not Review Fields.
  // Validate exact source preservation after navigating back at the end.
  await review.getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const generate=page.waitForResponse(response=>
    response.request().method()==='POST'&&response.url().endsWith('/parser-pairs/generate'));
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const result=await generate;
  expect(result.status()).toBe(200);
  const pair=await result.json();
  expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
  const ruby=pair.files.find((file:{name:string})=>!file.name.endsWith('.conf'));
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby.content)?.[1];
  expect(encoded).toBeTruthy();
  const project=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8'));
  const variants=project.normalization.eventProfiles.variants;
  const find=(name:string)=>variants.find((x:{name:string})=>x.name===name);
  expect(find('threat').topFields.src_ip)
    .toMatchObject({normalized_name:'srcip',data_type:'ip'});
  expect(find('threat').topFields.action)
    .toMatchObject({normalized_name:'action',data_type:'string'});
  expect(find('user').topFields.username)
    .toMatchObject({normalized_name:'username',data_type:'string'});
  expect(find('asset').nsFields['host.name'])
    .toMatchObject({normalized_name:'host.name',data_type:'string'});
  expect(find('threat').topFields.sha256).toBeUndefined();
  expect(project.normalization.eventProfiles.unknown).toBe('reject');
  expect(JSON.stringify(project)).not.toContain('김민수');
  expect(JSON.stringify(project)).not.toContain('山田');
  const sha=(text:string|Buffer)=>createHash('sha256').update(text).digest('hex');
  expect(sha(ruby.content)).toBe(ruby.sha256);
  const downloaded=page.waitForEvent('download');
  await page.getByLabel('Generated parser files')
    .getByRole('button',{name:ruby.name,exact:true}).click();
  const receipt=await downloaded;
  const stream=await receipt.createReadStream();
  const chunks:Buffer[]=[];
  for await(const chunk of stream)chunks.push(Buffer.from(chunk));
  expect(sha(Buffer.concat(chunks))).toBe(ruby.sha256);
  expect(errors).toEqual([]);
  await page.getByRole('button',{name:/Add Logs/}).first().click();
  await expect(raw).toHaveValue(source);
});
