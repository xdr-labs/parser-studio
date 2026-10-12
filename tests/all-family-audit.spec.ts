import {expect,test} from '@playwright/test';

const mixed=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"secret":"CUSTOMER_SECRET_A"}',
  'action=deny src_ip=203.0.113.10 dst_port=22 username=PRIVATE_USER',
  '{"action":"deny","src_ip":"192.0.2.15","dst_port":80,"secret":"CUSTOMER_SECRET_B"}',
  'raw unrecognized log message with PRIVATE_UNSUPPORTED_CONTENT',
].join('\n');

test('one explicit browser-only audit accounts for every mixed-family event and reports unsupported lines',async({page})=>{
  let apiCalls=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/'))apiCalls++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}).click();
  const workspace=page.getByLabel('Local family isolation workspace');
  await workspace.locator('summary').click();
  const audit=page.getByLabel('All detected families local audit workspace');
  const button=audit.getByRole('button',{name:'Audit All Detected Families Locally'});
  await expect(button).toBeEnabled();
  await expect(page.getByLabel('All-family browser audit result')).toHaveCount(0);
  await button.click();
  const report=page.getByLabel('All-family browser audit result');
  await expect(report).toContainText('4 original events accounted for');
  await expect(report).toContainText('3 reviewed in supported format families');
  await expect(report).toContainText('1 unsupported or unknown');
  await expect(report).toContainText('JSON');
  await expect(report).toContainText('Key / Value');
  await expect(report).toContainText('2 source events');
  await expect(report).toContainText('1 source events');
  await expect(report.getByRole('note')).toContainText('line 4 (Unrecognized)');
  await expect(report).toContainText('not validate a single mixed-format Ruby/CONF parser');
  for(const secret of ['CUSTOMER_SECRET_A','CUSTOMER_SECRET_B','PRIVATE_USER','PRIVATE_UNSUPPORTED_CONTENT']){
    await expect(report).not.toContainText(secret);
  }
  expect(apiCalls).toBe(0);
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}))
    .toHaveAttribute('aria-pressed','true');
  const local=await page.evaluate(()=>JSON.stringify(localStorage));
  expect(local).not.toContain('CUSTOMER_SECRET_A');
  expect(local).not.toContain('PRIVATE_UNSUPPORTED_CONTENT');
});

test('all-family coverage is invalidated immediately after a source event edit',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByLabel('Local family isolation workspace').locator('summary').click();
  await page.getByRole('button',{name:'Audit All Detected Families Locally'}).click();
  await expect(page.getByLabel('All-family browser audit result')).toBeVisible();
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await page.getByLabel('Guided raw sample logs').fill(mixed.replace('CUSTOMER_SECRET_A','CHANGED_SECRET'));
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByLabel('All-family browser audit result')).toHaveCount(0);
});

test('unknown-only source cannot be presented as a supported all-family audit',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    'first unrecognized event\nsecond unrecognized event',
  );
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByLabel('Sample format distribution')).toContainText('Unrecognized');
  await expect(page.getByLabel('All detected families local audit workspace')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Audit All Detected Families Locally'})).toHaveCount(0);
});

test('all-family audit supports keyboard activation without storing or uploading samples',async({page})=>{
  let requests=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/'))requests++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  const workspace=page.getByLabel('Local family isolation workspace');
  await workspace.locator('summary').focus();
  await page.keyboard.press('Enter');
  const button=page.getByRole('button',{name:'Audit All Detected Families Locally'});
  await button.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByLabel('All-family browser audit result')).toContainText('4 original events accounted for');
  expect(requests).toBe(0);
});


test('user-downloadable family audit evidence contains only SHA-256 provenance and redacted counts',async({page})=>{
  let backendCalls=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/'))backendCalls++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(mixed);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByLabel('Local family isolation workspace').locator('summary').click();
  await page.getByRole('button',{name:'Audit All Detected Families Locally'}).click();
  const report=page.getByLabel('All-family browser audit result');
  await expect(report).toContainText('4 original events accounted for');
  const downloadPromise=page.waitForEvent('download');
  await report.getByRole('button',{name:'Download Redacted Family Audit JSON'}).click();
  const download=await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^parser_studio_[a-z0-9_]+_family_audit\.json$/);
  const {readFile}=await import('node:fs/promises');
  const body=JSON.parse(await readFile(await download.path(),'utf8'));
  expect(body).toMatchObject({
    reportSchema:'parser-studio.browser-family-audit-evidence.v0.1',
    engine:'browser-preview',status:'DRAFT_ONLY',
    compatibility:{
      nativeFluentdVerified:false,stellarTargetVerified:false,
      singleMixedFormatParserVerified:false,
    },
    privacy:{
      rawLogsIncluded:false,normalizedValuesIncluded:false,
      diagnosticMessagesIncluded:false,
    },
    overview:{sourceEvents:4,reviewedEvents:3,unreviewableEvents:1},
    families:[{format:'json',sourceEvents:2},{format:'kv',sourceEvents:1}],
    unreviewable:[{originalLine:4,format:'unknown'}],
  });
  expect(body.source.sampleSha256).toMatch(/^[0-9a-f]{64}$/);
  expect(body.source.draftSha256).toMatch(/^[0-9a-f]{64}$/);
  const serialized=JSON.stringify(body);
  for(const privateValue of [
    'CUSTOMER_SECRET_A','CUSTOMER_SECRET_B','PRIVATE_USER',
    'PRIVATE_UNSUPPORTED_CONTENT','198.51.100.10','203.0.113.10',
  ]) expect(serialized).not.toContain(privateValue);
  expect(backendCalls).toBe(0);
});
