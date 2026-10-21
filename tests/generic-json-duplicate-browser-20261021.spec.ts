import {test,expect} from '@playwright/test';

// Authored synthetic source, not manufacturer firmware/wire-capture evidence.
const negative=[
  'vendor_test {"src_ip":"192.0.2.11","src_ip":"198.51.100.9"}',
  'vendor_test {"user":{"name":"one","name":"two"}}',
  'vendor_test {"\\u0061":1,"a":2}',
  '<134>1 2026-10-21T00:01:02Z gateway {"a":1,"a":2}',
  '<134>1 2026-10-21T00:01:02Z gateway {"outer":{"name":"one","name":"two"}}',
];
const positive=[
  'vendor_test {"left":{"k":"one"},"right":{"k":"two"}}',
  'vendor_test {"arr":[{"k":1},{"k":2}]}',
  '<134>1 2026-10-21T00:01:02Z gateway {"left":{"k":"one"},"right":{"k":"two"}}',
];

test('real browser Generic Structural decoder does not lose duplicate JSON members in wrapped records',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Run with the exact-head offline source and browser suite.');
  const pageErrors:string[]=[];
  const serverErrors:number[]=[];
  page.on('pageerror',error=>pageErrors.push(error.message));
  page.on('response',response=>{
    if(response.url().includes('/api/')&&response.status()>=500)serverErrors.push(response.status());
  });
  await page.goto('/');
  const results=await page.evaluate(async payload=>{
    const module=await import('/src/genericStructural.ts');
    return {
      negatives:payload.negative.map(source=>module.extractGenericStructural(source)),
      positives:payload.positive.map(source=>module.extractGenericStructural(source)),
    };
  },{negative,positive});
  expect(results.negatives).toHaveLength(negative.length);
  for(const item of results.negatives){
    expect(item.fields).toEqual({});
    expect(item.errors.length).toBeGreaterThan(0);
  }
  expect(results.positives).toHaveLength(positive.length);
  for(const item of results.positives){
    expect(item.errors).toEqual([]);
    expect(item.fields).not.toEqual({});
  }
  // The novice still receives the exact unaltered record after requesting
  // source analysis. Source or output is never posted to an outside origin.
  const sample=negative[0]!;
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(sample);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(input).toHaveValue(sample);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  expect(pageErrors).toEqual([]);
  expect(serverErrors).toEqual([]);
});
