import {test,expect} from '@playwright/test';

// The retired Advanced/mobile diagnostic controls are not the user recovery path.
// This exercises the same source-backed partial Snort event through the desktop
// Analyze Logs workflow, without a separate local-analysis mode.
const raw='07/16-09:23:39.153899 [**] [1:1000000:0] "SERVER-WEBAPP Apache Log4j arbitrary code execution attempt" [**] [Classification: Attempted User Privilege Gain] [Priority: 1] [AppID: HTTP] {TCP} 192.168.1.2:50284 -> 192.168.2.3:80';

test('partial security event retains original source and opens a manually reviewed ChatGPT recovery prompt',async({page})=>{
  const outbound:string[]=[];
  page.on('request',request=>{
    if(/api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com/.test(request.url()))
      outbound.push(request.url());
  });
  await page.goto('/');
  await expect(page.getByRole('button',{name:'Tools & Diagnostics'})).toHaveCount(0);
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const analysis=page.getByLabel('Beginner analysis summary');
  await expect(analysis).toContainText('1 event needs attention',{timeout:20000});
  const problem=page.getByLabel('Parse problem inspector');
  await expect(problem).toContainText('Attempted User Privilege Gain');
  await expect(problem).toContainText('Text not yet assigned to fields');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
  const prompt=page.getByLabel('Generated ChatGPT repair prompt');
  await expect(prompt).toContainText('Detected syntax:');
  await expect(prompt).toContainText('Original problem event:');
  await expect(prompt).toContainText('192.168.1.2:50284');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  expect(outbound).toEqual([]);
});
