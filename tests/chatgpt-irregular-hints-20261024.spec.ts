import {test,expect} from '@playwright/test';

test('irregular HDFS-like logs produce bounded value-free ChatGPT review hints',async({page})=>{
 const source=[
  '081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_76543212345 terminating',
  '081110 014601 592 WARN dfs.FSNamesystem: Unable to delete block blk_2222 due to I/O exception',
 ].join('\n');
 const escaped='blk_76543212345';
 const providerRequests:string[]=[];
 page.on('request',req=>{
  if(/api\.openai\.com|chatgpt\.com|api\.anthropic\.com/.test(req.url()))
   providerRequests.push(req.url());
 });
 await page.goto('/?workspace=chatgpt');
 await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
 const log=page.getByLabel('ChatGPT local sample logs');
 await log.fill(source);
 await page.getByLabel('ChatGPT desired fields').fill('timestamp if known, pid, severity, component, message');
 const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
 await expect(prepare).toBeEnabled({timeout:25000});
 await prepare.click();
 await expect(page.getByLabel('ChatGPT prepared prompt')).toBeVisible();
 const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
 expect(prompt).toContain('SIX_DIGIT_DATE_TIME_SEVERITY_COMPONENT');
 expect(prompt).toContain('distinct holdout');
 expect(prompt).toContain('Do not guess a missing year or timezone');
 expect(prompt).toContain(escaped);
 expect(prompt).toContain(source);
 // Raw sample appears only inside the original-source block, not in the
 // conservative metadata hints; a user still must copy explicitly.
 const before=prompt.split('----- BEGIN ORIGINAL LOG SOURCE -----')[0]!;
 expect(before).not.toContain(escaped);
 expect(await log.inputValue()).toBe(source);
 expect(providerRequests).toEqual([]);
});

test('Logcat prompt carries producer-grammar hints without inventing year, action or values',async({page})=>{
 const raw=[
  '03-17 16:13:38.811  1702  2395 D WindowManager: token=LOCAL_SECRET_MARKER',
  '03-17 16:13:38.819  1702  8671 W ActivityManager: Unable to open',
 ].join('\n');
 await page.goto('/?workspace=chatgpt');
 await page.getByLabel('ChatGPT local sample logs').fill(raw);
 await page.getByLabel('ChatGPT desired fields').fill('known pid, tid, priority and tag; leave unverified roles alone');
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
 expect(prompt).toContain('ANDROID_LOGCAT_THREADTIME');
 expect(prompt).toContain('Do not guess a missing year or timezone');
 expect(prompt).toContain('REVIEW_REQUIRED');
 expect(prompt).toContain(raw);
 const before=prompt.split('----- BEGIN ORIGINAL LOG SOURCE -----')[0]!;
 expect(before).not.toContain('LOCAL_SECRET_MARKER');
 expect(await page.getByLabel('ChatGPT local sample logs').inputValue()).toBe(raw);
});

test('unsupported free prose does not gain imaginary parser grammar',async({page})=>{
 await page.goto('/?workspace=chatgpt');
 await page.getByLabel('ChatGPT local sample logs').fill('Failure for unknown identity at host unknown.example:443');
 await page.getByLabel('ChatGPT desired fields').fill('user, action, timestamp');
 const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
 await expect(prepare).toBeEnabled({timeout:25000});
 await prepare.click();
 const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
 expect(prompt).toContain('FULL_RECOVERY');
 expect(prompt).not.toContain('BRACKET_MONTH_DAY_PROCESS_TARGET');
 expect(prompt).not.toContain('SIX_DIGIT_DATE_TIME_SEVERITY_COMPONENT');
});
