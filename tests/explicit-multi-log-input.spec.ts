import {test,expect} from './support/downloadSink';

const threat='{"event_type":"threat","src_ip":"192.0.2.20","action":"deny","message":"탐지"}';
const user='{"event_type":"user","username":"김민수","action":"login"}';
const asset='{"event_type":"asset","hostname":"fw01","action":"discovered"}';

async function enterNamed(page:import('@playwright/test').Page){
  await page.goto('/');
  await page.getByRole('button',{name:'Add Another Log Type'}).click();
  await page.getByLabel('Log type name 1').fill('Threat');
  await page.getByLabel('Log type sample 1').fill(threat);
  await page.getByLabel('Log type name 2').fill('User');
  await page.getByLabel('Log type sample 2').fill(user);
  await page.getByLabel('Named log type samples').getByRole('button',{name:'Add Another Log Type'}).click();
  await page.getByLabel('Log type name 3').fill('Asset');
  await page.getByLabel('Log type sample 3').fill(asset);
}

test('novice adds three named types and creates one reviewed conditional DRAFT',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires a pinned, compiled offline authoring backend and isolated Multi-Pass server.');
  await enterNamed(page);
  await expect(page.getByLabel('Named log type samples')).toContainText('3 types');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Named log type samples')).toContainText('Threat: 1 event · 1 parsed');
  await expect(page.getByLabel('Named log type samples')).toContainText('User: 1 event · 1 parsed');
  await expect(page.getByLabel('Named log type samples')).toContainText('Asset: 1 event · 1 parsed');
  const next=page.getByLabel('Add Logs stage').getByRole('button',{name:'Review Fields',exact:true});
  await expect(next).toBeEnabled();
  await next.click();
  const review=page.getByLabel('Review Fields stage');
  await expect(review).toBeVisible();
  const named=review.getByLabel('Review named log types');
  await expect(named).toContainText('Threat');
  await expect(named).toContainText('src_ip');
  await expect(named).toContainText('username');
  await expect(named).toContainText('hostname');
  const router=review.getByLabel('Configure one parser for event types');
  if(!(await router.evaluate(element=>(element as HTMLDetailsElement).open)))
    await router.locator('summary').first().click();
  await expect(router.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await router.getByLabel('Approve explicit family routing changes').check();
  await expect(router.getByRole('button',{name:'Apply reviewed event types to this parser'})).toBeEnabled();
  await router.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await expect(router.getByLabel('Configured event profiles')).toContainText('3 explicit event types');
  await review.getByRole('button',{name:'Map Fields'}).click();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await page.getByLabel('Create Parser Files').click();
  const files=page.getByLabel('Generated parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:25000});
  const downloadPromise=page.waitForEvent('download');
  await files.getByRole('button',{name:/customized_demo_firewall$/}).click();
  const download=await downloadPromise;
  const stream=await download.createReadStream();
  const chunks:Buffer[]=[];
  for await(const item of stream)chunks.push(Buffer.from(item));
  const ruby=Buffer.concat(chunks).toString('utf8');
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  expect(encoded).toBeTruthy();
  const project=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8'));
  expect(project.normalization.eventProfiles.variants.map((x:{name:string})=>x.name))
    .toEqual(['threat','user','asset']);
  expect(JSON.stringify(project)).not.toContain('김민수');
  expect(JSON.stringify(project)).not.toContain('192.0.2.20');
  await page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button',{name:/Add Logs/}).click();
  await expect(page.getByLabel('Log type sample 1')).toHaveValue(threat);
  await expect(page.getByLabel('Log type sample 2')).toHaveValue(user);
  await expect(page.getByLabel('Log type sample 3')).toHaveValue(asset);
});

test('invalid, empty or duplicate named groups fail closed and preserve source',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(threat);
  await page.getByRole('button',{name:'Add Another Log Type'}).click();
  await expect(page.getByLabel('Log type sample 1')).toHaveValue(threat);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  await expect(page.getByLabel('Named log type samples')).toContainText('paste or upload at least one sample');
  await page.getByLabel('Log type name 1').fill('Threat');
  await page.getByLabel('Log type name 2').fill('THREAT');
  await page.getByLabel('Log type sample 2').fill(user);
  await expect(page.getByLabel('Named log type samples')).toContainText('choose a unique log type name');
  await page.getByLabel('Log type name 2').fill('User');
  await expect(page.getByLabel('Named log type samples')).not.toContainText('choose a unique log type name');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Named log type samples')).toContainText('Threat: 1 event');
  await page.getByLabel('Remove log type 2').click();
  await expect(page.getByLabel('Named log type samples')).toContainText('1 type');
  await expect(page.getByLabel('Log type sample 1')).toHaveValue(threat);
  page.on('dialog',dialog=>dialog.accept());
  await page.getByRole('button',{name:'Use one combined text box'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(threat);
});

test('named type uploads replace only selected type and local versions restore labels',async({page})=>{
  await enterNamed(page);
  await page.getByLabel('Upload log type 2').setInputFiles({
    name:'user.log',mimeType:'text/plain',buffer:Buffer.from(user+'\n'+user),
  });
  await expect(page.getByLabel('Log type sample 1')).toHaveValue(threat);
  await expect(page.getByLabel('Log type sample 2')).toHaveValue(user+'\n'+user);
  await expect(page.getByLabel('Log type sample 3')).toHaveValue(asset);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Three source types');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history).toContainText('Three source types');
  await page.getByLabel('Log type name 2').fill('Renamed User');
  await history.getByLabel('Local version name').fill('Renamed type');
  await history.getByRole('button',{name:'Save Version'}).click();
  await history.getByLabel('Compare version A').selectOption({label:'Three source types'});
  await history.getByLabel('Compare version B').selectOption({label:'Renamed type'});
  await expect(history.getByLabel('Local version differences')).toContainText('Named log type samples / labels');
  page.on('dialog',dialog=>dialog.accept());
  await history.getByText('Three source types',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Log type name 2')).toHaveValue('User');
  await expect(page.getByLabel('Log type sample 2')).toHaveValue(user+'\n'+user);
  await expect(page.getByLabel('Log type sample 3')).toHaveValue(asset);
});

test('named log input stays inside narrow viewport',async({page})=>{
  await page.setViewportSize({width:375,height:812});
  await enterNamed(page);
  await expect(page.getByLabel('Log type entry 3')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(377);
});
