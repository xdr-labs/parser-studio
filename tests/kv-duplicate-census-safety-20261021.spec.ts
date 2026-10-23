import {test,expect} from '@playwright/test';

const malformed=[
  'action=allow action=deny',
  'src_ip=192.0.2.10 src_ip=198.51.100.10',
  'msg="action=deny" action=allow action=block',
  '<34>1 2026-10-21T00:00:00Z gw app 1 EV01 - action=allow action=deny',
  '<134>Jan 16 15:19:05 gw app: action=allow action=deny',
];
const valid=[
  'msg="action=deny" action=allow',
  'Action=allow action=deny',
  'src_ip=192.0.2.10 action=deny',
  '<34>1 2026-10-21T00:00:00Z gw app 1 EV01 - src_ip=192.0.2.10 action=deny',
];

test('novice event accounting refuses duplicate KV sources before generating a DRAFT',async({page})=>{
  test.setTimeout(85_000);
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  for(const raw of malformed){
    await page.goto('/');
    const source=page.getByLabel('Auto Parser raw logs');
    await source.fill(raw);
    await expect(page.getByLabel('Automatic event accounting')).toContainText('1/1 events checked');
    await expect(page.getByLabel('Automatic event accounting')).toContainText('1 event unrecognized in the initial format scan');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    // A separately reviewed Multi-Pass source recovery may become available
    // *after* analysis. Only the lexical pre-analysis census is changed here;
    // do not block an independently proved source-recovery path on purpose.
    await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
    await expect(source).toHaveValue(raw);
    await expect(page.getByRole('button',{name:'Create Parser Files'})).toHaveCount(0);
  }
  expect(errors).toEqual([]);
});

test('quotes, distinct case-sensitive names and legitimate KV events do not trigger duplicate warning',async({page})=>{
  for(const raw of valid){
    await page.goto('/');
    const source=page.getByLabel('Auto Parser raw logs');
    await source.fill(raw);
    await expect(page.getByLabel('Automatic event accounting')).toContainText('1/1 events checked');
    await expect(page.getByLabel('Automatic event accounting')).toContainText('0 events unrecognized in the initial format scan');
    await expect(source).toHaveValue(raw);
  }
});
