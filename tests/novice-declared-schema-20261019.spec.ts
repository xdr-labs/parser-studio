import {test,expect} from '@playwright/test';

// Authored synthetic standards cases only; genuine Chromium + live local engine.
const w3c='#Version: 1.0\r\n#Fields: date time cs-method cs-uri-stem sc-status cs(User-Agent)\r\n2026-10-19 08:22:00 GET /login 200 "봇 ""agent"""\r\n2026-10-19 08:22:01 POST /api 403 "safe agent"\r\n';
const zeek='#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.resp_h\n#types\ttime\tstring\taddr\taddr\n1760870000.0\tCk1\t192.0.2.10\t198.51.100.2\n1760870001.0\tCk2\t192.0.2.11\t198.51.100.3\n#close\t2026-10-19\n';
for(const item of [{id:'W3C',source:w3c,syntax:'W3C_EFL_DECLARED',field:'cs(User-Agent)'},{id:'Zeek',source:zeek,syntax:'ZEEK_TSV_DECLARED',field:'id.orig_h'}]){
 test(item.id+' original schema source to novice guidance',async({page})=>{
  const pageErrors:string[]=[];
  const apiBodies:unknown[]=[];
  page.on('pageerror',e=>pageErrors.push(e.message));
  page.on('response',async r=>{if(r.url().includes('/api/v1/multipass/preview-batch')&&r.ok())apiBodies.push(await r.json());});
  await page.goto('/');
  await expect(page.getByRole('heading',{name:/Paste security logs/})).toBeVisible();
  const source=page.getByLabel('Auto Parser raw logs');
  if(item.id==='W3C'){
   await page.getByLabel('Auto Parser file upload').setInputFiles({
    name:'sample-w3c.log',mimeType:'text/plain',buffer:Buffer.from(item.source,'utf8')
   });
  }else await source.fill(item.source);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
  await expect.poll(()=>apiBodies.length,{timeout:15000}).toBeGreaterThan(0);
  const result=apiBodies[0] as any;
  expect(result.eventCount).toBe(2);
  expect(result.events.every((e:any)=>e.preview.syntax===item.syntax)).toBeTruthy();
  expect(result.events.every((e:any)=>e.preview.status==='PARTIAL')).toBeTruthy();
  expect(result.separators.some((s:any)=>s.kind==='SOURCE_METADATA')).toBeTruthy();
  expect(result.events[0].preview.fields[item.field]).toBeDefined();
  // DOM textarea values normalize CRLF even when the file-upload state is lossless.
  await expect(source).toHaveValue(item.source.replace(/\r\n/g,'\n'));
  expect(result.sourceBytes).toBe(Buffer.byteLength(item.source,'utf8'));
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2');
  await expect(page.getByLabel('Parse problem inspector')).toContainText('Review the recognized columns');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  await page.screenshot({path:'/tmp/parser-schema-candidate-'+item.id.toLowerCase()+'.png',fullPage:true});
  expect(pageErrors).toEqual([]);
 });
}
test('pasted CRLF text is browser-normalized, not misrepresented as original bytes',async({page})=>{
 await page.goto('/');
 const source=page.getByLabel('Auto Parser raw logs');
 await source.fill(w3c);
 await expect(source).toHaveValue(w3c.replace(/\r\n/g,'\n'));
 await expect(page.getByText('For exact original line endings')).toBeVisible();
});
test('adversarial declared columns remain review-only',async({page})=>{
 await page.goto('/');
 const source=page.getByLabel('Auto Parser raw logs');
 await source.fill('#Fields: date cs-method\n2026-10-19 GET EXTRA\n');
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
 await expect(source).toHaveValue('#Fields: date cs-method\n2026-10-19 GET EXTRA\n');
});
