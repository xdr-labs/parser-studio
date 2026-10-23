import {test,expect} from '@playwright/test';

test('the retired existing-parser import entry stays absent across both creation paths',async({page})=>{
  const inspectRequests:string[]=[];
  page.on('request',request=>{
    if(new URL(request.url()).pathname.endsWith('/parser-pairs/inspect'))
      inspectRequests.push(request.url());
  });

  await page.goto('/');
  await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
  await expect(page.getByText('Open or inspect an existing parser')).toHaveCount(0);
  await expect(page.getByLabel('Existing parser review and import')).toHaveCount(0);
  await expect(page.getByLabel('Existing Parser Project JSON')).toHaveCount(0);
  await expect(page.getByLabel('Existing parser logic file')).toHaveCount(0);

  const sample='{"event_type":"alert","action":"deny","src_ip":"192.0.2.19","dst_port":443}';
  await page.getByLabel('Auto Parser raw logs').fill(sample);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('1 of 1 log event parsed completely',{timeout:20000});
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await expect(page.getByText('Open or inspect an existing parser')).toHaveCount(0);

  const nav=page.getByRole('complementary',{name:'Parser Studio navigation'});
  await nav.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
  await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
  await expect(page.getByText('Open or inspect an existing parser')).toHaveCount(0);
  await expect(page.getByLabel('Existing Parser Project JSON')).toHaveCount(0);
  expect(inspectRequests).toEqual([]);
});
