import {test,expect} from '@playwright/test';

test('existing visible masks are preserved and ChatGPT only receives logs after manual copy',async({page})=>{
  const raw='src=REDACTED secret=*** custom=PRIVATE_VISIBLE';
  const posts:string[]=[];
  page.on('request',request=>{
    if(request.method()==='POST')posts.push(new URL(request.url()).pathname);
  });
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
  await expect(source).toHaveValue(raw);
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Browser-only event inspector')).toContainText('REDACTED');
  await expect(page.getByLabel('Browser-only event inspector')).toContainText('PRIVATE_VISIBLE');
  await page.getByRole('button',{name:'ChatGPT Assisted Parser'}).click();
  await expect(page.getByLabel('ChatGPT local sample logs')).toHaveValue(raw);
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
  await expect(page.getByRole('alert')
    .filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  await expect(page.getByLabel('ChatGPT copyable prompt')).toHaveCount(0);
  expect(posts.every(path=>path.startsWith('/api/v1/multipass/')||
    path.startsWith('/api/v1/parser-pairs/'))).toBe(true);
  expect(posts.some(path=>path.includes('/sessions/start')||
    path.includes('/target/apply'))).toBe(false);
});
