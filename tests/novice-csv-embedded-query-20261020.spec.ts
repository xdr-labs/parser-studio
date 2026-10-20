import {test,expect} from '@playwright/test';

const samples:[string,','|';'|'\t'][]=[
  ['allow,gw01,https://example.test/log?request_id=42&result=ok',','],
  ['gw01;허용;https://example.test/path?q=사용자&action=allow',';'],
  ['host\tallow\thttps://example.test/?user=sample&status=ok','\t'],
  ['node,"https://example.test/?q=a,b&result=ok",allow',','],
];

test('unquoted CSV URL query equals survives real novice source accounting and delimiter review',async({page})=>{
  test.setTimeout(120_000);
  const errors:string[]=[];
  const serverFailures:number[]=[];
  page.on('pageerror',err=>errors.push(err.message));
  page.on('response',response=>{
    if(response.url().includes('/api/')&&response.status()>=500)
      serverFailures.push(response.status());
  });
  for(const [text,separator] of samples){
    await page.goto('/');
    const source=page.getByLabel('Auto Parser raw logs');
    await source.fill(text);
    const ledger=page.getByLabel('Automatic event accounting');
    await expect(ledger).toContainText('1/1 events checked');
    await expect(ledger).toContainText('0 events need attention');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(source).toHaveValue(text);
    const csv=page.getByLabel('Review CSV column names');
    await expect(csv).toBeVisible();
    await csv.getByLabel('Reviewed CSV data separator').selectOption(separator);
    await expect(csv).toContainText('3 consistent columns detected');
    // The lexer can identify columns but never supplies guessed field names.
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  }
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill('action=allow bogus token,second,third');
  await expect(page.getByLabel('Automatic event accounting')).toContainText('1 event needs attention');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  expect(errors).toEqual([]);
  expect(serverFailures).toEqual([]);
});
