import {test,expect} from '@playwright/test';

// No manufacturer originals: strictly synthetic RFC4180-style lexical cases.
// A CSV-shaped record with an illegal quote transition must not receive a
// "0 events need attention" browser envelope status before compiler review.
const malformed=[
  'left"inside",right,third',
  '"first"junk,second,third',
  'first,second,"third"junk',
  'first;second;"third"junk',
  'first\tsecond\t"third"junk',
];
const valid:[string,','|';'|'\t'][]=[
  ['"https://example.test/?key=a,b&value=c","allow","node"',','],
  ['"quoted ""text""","allowed","node"',','],
  ['"quoted;cell";"second";"third"',';'],
  ['"first\tpart"\t"second"\t"third"','\t'],
];

test('strict source accounting rejects illegal CSV quote transitions but accepts valid quoted delimiters',async({page})=>{
  test.setTimeout(100_000);
  const errors:string[]=[];
  const failedResponses:number[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('response',response=>{
    if(response.url().includes('/api/')&&response.status()>=500)
      failedResponses.push(response.status());
  });
  for(const text of malformed){
    await page.goto('/');
    const source=page.getByLabel('Auto Parser raw logs');
    await source.fill(text);
    const census=page.getByLabel('Automatic event accounting');
    await expect(census).toContainText('1/1 events checked');
    await expect(census).toContainText('1 event needs attention');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(source).toHaveValue(text);
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  }
  for(const [text,delimiter] of valid){
    await page.goto('/');
    const source=page.getByLabel('Auto Parser raw logs');
    await source.fill(text);
    const census=page.getByLabel('Automatic event accounting');
    await expect(census).toContainText('1/1 events checked');
    await expect(census).toContainText('0 events need attention');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(source).toHaveValue(text);
    const csv=page.getByLabel('Review CSV column names');
    await expect(csv).toBeVisible();
    // The UI initially selects comma. A user must select the source's actual
    // delimiter before inferring a safe positional schema for ; or TAB rows.
    await csv.getByLabel('Reviewed CSV data separator').selectOption(delimiter);
    await expect(csv).toContainText('3 consistent columns detected');
    // No schema was supplied; do not manufacture trustworthy CSV field names.
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  }
  expect(errors).toEqual([]);
  expect(failedResponses).toEqual([]);
});
