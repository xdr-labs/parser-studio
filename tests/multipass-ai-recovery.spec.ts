import {test,expect} from '@playwright/test';

const raw='07/16-09:23:39.153899 [**] [1:1000000:0] "SERVER-WEBAPP Apache Log4j arbitrary code execution attempt" [**] [Classification: Attempted User Privilege Gain] [Priority: 1] [AppID: HTTP] {TCP} 192.168.1.2:50284 -> 192.168.2.3:80';

test('default Multi-Pass partial Snort source offers a manual exact-log ChatGPT recovery prompt',async({page})=>{
  const outgoing:string[]=[];
  page.on('request',request=>{
    if(request.method()==='POST'){
      const path=new URL(request.url()).pathname;
      outgoing.push(path);
    }
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
  const problem=page.getByLabel('Parse problem inspector');
  await expect(problem).toBeVisible();
  await expect(problem).toContainText('Log4j');
  await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
  const prompt=page.getByLabel('Generated ChatGPT repair prompt');
  await expect(prompt).toContainText('Original problem event');
  await expect(prompt).toContainText('Log4j');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  expect(outgoing.every(path=>path.startsWith('/api/v1/multipass/')||
    path.startsWith('/api/v1/parser-pairs/'))).toBe(true);
  expect(outgoing.some(path=>path.includes('/target/apply')||
    path.includes('/sessions/start')||path.includes('/interflow'))).toBe(false);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
});
