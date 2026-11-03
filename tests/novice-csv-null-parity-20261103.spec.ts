import {test,expect} from '@playwright/test';

// Synthetic source only: browser source accounting and the ordinary novice
// review journey must not turn an empty cell into a parser readiness claim.
test('novice preserves reviewed CSV empty and whitespace-only source across comma and TAB',async({page})=>{
  test.setTimeout(90_000);
  const pageErrors:string[]=[];
  const unexpectedPosts:string[]=[];
  page.on('pageerror',error=>pageErrors.push(error.message));
  page.on('request',request=>{
    const path=new URL(request.url()).pathname;
    if(request.method()==='POST'&&/\/api\/v1\/parser-pairs\/.*(?:generate|apply)/.test(path))
      unexpectedPosts.push(path);
  });
  const samples=[
    {raw:'192.0.2.10,,443',delimiter:','},
    {raw:'192.0.2.10,"",443',delimiter:','},
    {raw:'192.0.2.10\t  \t443',delimiter:'\t'},
  ] as const;

  for(const sample of samples){
    await page.goto('/');
    const input=page.getByLabel('Auto Parser raw logs');
    await input.fill(sample.raw);
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('0 events unrecognized in the initial format scan');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const review=page.getByLabel('Review CSV column names');
    await review.getByLabel('Reviewed CSV data separator').selectOption(sample.delimiter);
    await expect(review).toContainText('3 consistent columns detected');
    await review.getByLabel('Reviewed CSV column names').fill('src_ip,detail,dst_port');
    await review.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
    const next=page.getByRole('button',{name:'Review Fields',exact:true});
    await expect(next).toBeEnabled();
    await next.click();
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    const inspector=page.getByLabel('Browser-only event inspector');
    await expect(inspector).toContainText('192.0.2.10');
    await expect(inspector).toContainText('443');
    await page.getByLabel('Review Fields stage')
      .getByRole('button',{name:'Back to Logs'}).click();
    await expect(input).toHaveValue(sample.raw);
  }
  expect(pageErrors).toEqual([]);
  expect(unexpectedPosts).toEqual([]);
});
