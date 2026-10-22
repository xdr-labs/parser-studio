import {test,expect} from '@playwright/test';

// The owner removed duplicate redaction/edit panels. The product must warn
// that a manually copied ChatGPT prompt contains exactly the original source;
// it must not reconstruct masked values or send source to an AI endpoint.
test('visible masked values are not reconstructed and original log copy requires user action',async({page,context})=>{
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  const raw='src=REDACTED secret=*** custom=PRIVATE_VISIBLE';
  const outbound:string[]=[];
  page.on('request',request=>{
    if(/api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com/.test(request.url()))
      outbound.push(request.url());
  });
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(raw);
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
  await expect(page.getByRole('alert').filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  await expect(page.getByLabel('ChatGPT copyable prompt')).toHaveCount(0);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  const source=await prompt.inputValue();
  expect(source).toContain(raw);
  expect(source).not.toContain('RECONSTRUCTED_PRIVATE_SECRET');
  await page.getByRole('button',{name:'Copy Prompt',exact:true}).click();
  expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe(source);
  expect(outbound).toEqual([]);
});
