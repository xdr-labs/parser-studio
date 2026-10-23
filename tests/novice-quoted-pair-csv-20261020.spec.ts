import {expect,test} from '@playwright/test';

const quoted='"allow","198.51.100.10"\n"deny","203.0.113.4"\n"allow","192.0.2.8"';

test('novice reviews strongly quoted two-column CSV without inventing column names',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires exact-HEAD localhost authoring backend and Python Multi-Pass.');
  test.setTimeout(90_000);
  const pageErrors:string[]=[];
  const httpFailures:number[]=[];
  page.on('pageerror',e=>pageErrors.push(e.message));
  page.on('response',r=>{if(r.url().includes('/api/')&&r.status()>=500)httpFailures.push(r.status());});
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(quoted);
  const census=page.getByLabel('Automatic event accounting');
  await expect(census).toContainText('3/3 events checked');
  await expect(census).toContainText('0 events unrecognized in the initial format scan');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(source).toHaveValue(quoted);
  const csv=page.getByLabel('Review CSV column names');
  await expect(csv).toBeVisible();
  await expect(csv).toContainText('2 consistent columns detected');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  await csv.getByLabel('Reviewed CSV column names').fill('action,src_ip');
  const approval=csv.getByRole('button',{name:'I Confirm These CSV Column Names'});
  await expect(approval).toBeEnabled();
  await approval.click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled();
  await review.click();
  const reviewStage=page.getByLabel('Review Fields stage');
  await expect(reviewStage).toBeVisible();
  const map=reviewStage.getByRole('button',{name:'Map Fields',exact:true});
  await expect(map).toBeEnabled();
  await map.click();
  const mappings=page.getByLabel('Map Fields stage');
  await expect(mappings.getByLabel('Field mapping summary')).toContainText('2');
  await expect(mappings.getByRole('button',{name:'Create Parser',exact:true})).toBeEnabled();
  await mappings.getByRole('button',{name:'Create Parser',exact:true}).click();
  await page.getByLabel('Create Parser Files').click();
  const result=page.getByLabel('Generated parser files');
  await expect(result).toContainText('Parser files created successfully',{timeout:30000});
  const promise=page.waitForEvent('download');
  await result.getByRole('button',{name:/customized_demo_firewall$/}).click();
  const download=await promise;
  const stream=await download.createReadStream();const chunks:Buffer[]=[];
  for await(const chunk of stream)chunks.push(Buffer.from(chunk));
  const ruby=Buffer.concat(chunks).toString('utf8');
  const payload=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  expect(payload).toBeTruthy();
  const config=JSON.parse(Buffer.from(payload!,'base64').toString('utf8'));
  expect(config.extraction).toMatchObject({format:'csv',csvColumns:['action','src_ip'],csvDelimiter:','});
  await page.getByRole('navigation',{name:'Auto Parser steps'})
    .getByRole('button',{name:/Add Logs/}).click();
  await expect(source).toHaveValue(quoted);
  expect(pageErrors).toEqual([]);expect(httpFailures).toEqual([]);
});

test('neutral names for two quoted fields remain user-approved and reset on changed source',async({page})=>{
  test.setTimeout(75_000);
  const sample='"허용","김민수"\n"차단","홍길동"';
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(sample);
  await expect(page.getByLabel('Automatic event accounting')).toContainText('0 events unrecognized in the initial format scan');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const csv=page.getByLabel('Review CSV column names');
  await expect(csv).toContainText('2 consistent columns detected');
  await csv.getByRole('button',{name:'Keep all 2 values with temporary names'}).click();
  await expect(csv.getByLabel('Reviewed CSV column names')).toHaveValue('field_001,field_002');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
  await source.fill('"허용"junk,"김민수"');
  await expect(page.getByLabel('Automatic event accounting')).toContainText('1 event unrecognized in the initial format scan');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
});
