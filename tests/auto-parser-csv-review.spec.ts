import {test,expect} from '@playwright/test';

const sample=[
 '{"src_ip":"192.0.2.10","action":"deny","dst_port":443}',
 'src_ip=198.51.100.8 action=allow dst_port=443',
 '192.0.2.17;deny;22',
 '"203.0.113.19";allow;8443',
].join('\n');

test('Auto Parser reviews the CSV subset of a mixed structured sample without treating JSON or KV as CSV',async({page})=>{
 const unsafePosts:string[]=[];
 page.on('request',req=>{
   if(req.method()==='POST'&&/\/api\/v1\/parser-pairs\/.*(generate|apply)/.test(req.url()))
     unsafePosts.push(req.url());
 });
 await page.goto('/');
 await expect(page.getByRole('complementary',{name:'Parser creation methods'}))
   .toHaveCount(1);
 await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
 await expect(page.getByRole('button',{name:/Wizard|Workbench|Expert Mode|Edit Details/i}))
   .toHaveCount(0);
 await page.getByLabel('Auto Parser raw logs').fill(sample);
 await expect(page.getByLabel('Automatic event accounting'))
   .toContainText('4/4 events analyzed locally');
 const csv=page.getByLabel('Review CSV column names');
 await expect(csv).toBeVisible();
 if(await page.getByRole('button',{name:'Advanced'}).count())
  await page.getByRole('button',{name:'Advanced'}).click();
 const review=page.getByRole('button',{name:'Review Detected Results'});
 await expect(review).toBeDisabled();
 await page.getByLabel('Reviewed CSV column names').fill('src_ip,action,dst_port');
 await page.getByLabel('Reviewed CSV data separator').selectOption(';');
 await expect(csv).toContainText('CSV column review applies only to event 3–4');
 await expect(csv).toContainText('other 2 recognized events keep their own detected parser families');
 const confirm=page.getByRole('button',{name:'I Confirm These CSV Column Names'});
 await expect(confirm).toBeEnabled();
 await confirm.click();
 await expect(csv).toContainText('Field names are ready. Continue to Review Fields.');
 await expect(review).toBeEnabled();
 expect(unsafePosts).toEqual([]);
});
