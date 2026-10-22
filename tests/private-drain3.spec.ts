import {test,expect} from '@playwright/test';

const source=[
  'ERROR LOGIN from 192.0.2.11 user demo-alice',
  'ERROR LOGIN from 192.0.2.12 user demo-bob',
].join('\n');

test('unavailable private text grouping and redundant fingerprint tools are absent from beginner UI',async({page})=>{
  const drainRequests:string[]=[];
  page.on('request',request=>{
    if(request.url().includes('/patterns/drain3'))drainRequests.push(request.method()+' '+request.url());
  });
  await page.goto('/');
  const optional=page.getByLabel('Optional actions for special sources');
  await expect(optional).toBeVisible();
  await expect(optional).toContainText('skip these for ordinary logs');
  await expect(page.getByLabel('Private text grouping tool')).toHaveCount(0);
  await expect(page.getByLabel('Known log shape matcher')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Group Similar Logs'})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Find Similar Known Shapes'})).toHaveCount(0);
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:25000});
  expect(drainRequests).toEqual([]);
});

test('source-preserving optional capabilities remain discoverable after the main analysis step',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  const optional=page.getByLabel('Optional actions for special sources');
  await expect(optional.locator('summary')).toHaveCount(4);
  await expect(optional).toContainText('not replace Analyze Logs');
  await expect(optional.getByLabel('Existing parser review and import')).toBeVisible();
  await expect(optional.getByLabel('Existing parser review and import').locator('summary')).toContainText('Open or inspect an existing parser');
  await expect(optional.locator('summary')).toContainText(['Optional: mark a forwarded prefix or trailing suffix',
    'Optional: declare Syslog forwarder hostnames','Generate a Python Test Sender','Open or inspect an existing parser']);
});
