import {test,expect} from '@playwright/test';
const cases=[
 {id:'Repeated KV occurrences',raw:'<134>Oct 19 09:25:01 fw action=allow action=deny src=192.0.2.3 dst=198.51.100.2'},
 {id:'Wrapped pfSense positional CSV',raw:'<134>Oct 19 08:12:00 pfsense filterlog: 24,,,1000000103,em0,match,block,in,4,0x0,,64,40021,0,none,6,tcp,60,192.0.2.10,198.51.100.2,50100,443,0,S,1234,,65535,,'},
 {id:'Wrapped OPNsense positional CSV',raw:'<134>Oct 19 08:12:01 opnsense filterlog: 32,,,1000000104,vtnet0,match,pass,in,4,0x0,,64,33333,0,none,17,udp,90,192.0.2.10,198.51.100.53,49000,53,0'}
];
for(const item of cases){
 test(item.id+' honest source-only compilation block',async({page})=>{
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(item.raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:15000});
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  const alert=page.getByLabel('Parser draft not ready');
  await expect(alert).toBeVisible({timeout:18000});
  await expect(alert).toContainText('No source value was discarded',{ignoreCase:true});
  await expect(alert.getByRole('button',{name:'Use ChatGPT Assisted Parser'})).toBeVisible();
  await expect(alert.getByText('Inspect extracted source fields')).toBeVisible();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('downloadable parser not ready');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
  await expect(source).toHaveValue(item.raw);
  expect(errors).toEqual([]);
 });
}
test('qualified JSON normal workflow still reaches field mapping',async({page})=>{
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill('{"action":"deny","src_ip":"192.0.2.10","username":"tester"}');
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
 await page.getByRole('button',{name:'Review Fields',exact:true}).click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible({timeout:18000});
 const next=page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields',exact:true});
 await next.click();
 await expect(page.getByLabel('Map Fields stage')).toBeVisible();
});
