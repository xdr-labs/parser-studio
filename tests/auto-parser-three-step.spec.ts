import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';

const input=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');
const sha=(text:string)=>createHash('sha256').update(text).digest('hex');
const ruby='# synthetic test Ruby fragment\n';
const conf='# synthetic test CONF for port 6801\n';
const files=[{name:'customized_demo_firewall.conf',content:conf,bytes:Buffer.byteLength(conf),sha256:sha(conf)},
{name:'customized_demo_firewall',content:ruby,bytes:Buffer.byteLength(ruby),sha256:sha(ruby)}];
async function begin(page:Page){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(input);
  await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
}

test('new visitor sees only the two supported creation methods and a four-step Auto Parser',async({page})=>{
 await page.goto('/');
 await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
 await expect(page.getByRole('heading',{name:/Paste security logs/})).toBeVisible();
 await expect(page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button')).toHaveCount(4);
 const methods=page.getByRole('complementary',{name:'Parser Studio navigation'});
 await expect(methods.getByRole('button',{name:'Auto Parser',exact:true})).toBeVisible();
 await expect(methods.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
 await expect(page.getByLabel('Auto Parser raw logs')).toBeEmpty();
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
 await expect(page.getByRole('main',{name:'No-code Parser Guided Builder'})).toHaveCount(0);
 await expect(page.getByRole('region',{name:'Parser pipeline rules'})).toHaveCount(0);
 await page.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
 await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
 await page.getByRole('button',{name:'Auto Parser',exact:true}).click();
 await expect(page.getByLabel('Add Logs stage')).toBeVisible();
});
test('novice reviews original/extracted/normalized samples, keeps source, and sees safe mapping provenance',async({page})=>{
 let generatedPosts=0;
 page.on('request',req=>{
   if(req.method()==='POST'&&new URL(req.url()).pathname.endsWith('/generate'))
     generatedPosts++;
 });
 await begin(page);
 await expect(page.getByLabel('Browser-only event inspector')).toContainText('198.51.100.10');
 await expect(page.getByLabel('Browser-only event inspector')).toContainText('srcip');
 await expect(page.getByLabel('Normalization mapping handoff')).toContainText('choose where each value belongs in Stellar Cyber');
 await page.getByLabel('Auto Parser review event').selectOption('event-2');
 await expect(page.getByLabel('Browser-only event inspector')).toContainText('203.0.113.5');
 await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
 const map=page.getByLabel('Map Fields stage');
 await expect(map).toBeVisible();
 await expect(map).toContainText('Stellar field dictionary 7.0.xs');
 await expect(map.getByLabel('Field mapping summary')).toContainText('Matched to Stellar3');
 await expect(map.getByLabel('Recommended field matches')).toContainText('Apply 0 recommended matches');
 await map.getByRole('button',{name:'Create Parser'}).click();
 await expect(page.getByLabel('Create Parser stage')).toBeVisible();
 await expect(page.getByRole('button',{name:'Create Parser Files'})).toBeEnabled();
 await page.getByLabel('Create Parser stage').getByRole('button',{name:'Map Fields',exact:true}).click();
 await page.getByLabel('Map Fields stage').getByRole('button',{name:'Back to Review Fields'}).click();
 await page.getByLabel('Review Fields stage').getByRole('button',{name:'Back to Logs'}).click();
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(input);
 expect(generatedPosts).toBe(0);
});
test('mixed families and unknown logs are not dropped or transmitted to validation',async({page})=>{
 const generated:string[]=[];
 page.on('request',req=>{
   const path=new URL(req.url()).pathname;
   if(req.method()==='POST'&&path.includes('/parser-pairs/')&&path.endsWith('/generate'))generated.push(path);
 });
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(input+'\naction=allow src_ip=192.0.2.10\nMALFORMED_SECRET');
 await expect(page.getByLabel('Automatic event accounting')).toContainText('4/4 events analyzed locally');
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 await expect(page.getByLabel('Add Logs stage')).toBeVisible();
 await expect(page.getByLabel('Automatic event accounting')).toContainText('1 event needs attention');
 // Wait for the asynchronous, byte-preserving Multi-Pass result before checking recovery.
 await expect(page.getByLabel('Parse problem inspector')).toContainText('MALFORMED_SECRET',{timeout:20000});
 await expect(page.getByLabel('Auto Parser raw logs')).toContainText('MALFORMED_SECRET');
 const createStep=page.getByRole('navigation',{name:'Auto Parser steps'})
   .getByRole('button',{name:/Create Parser/});
 await expect(createStep).toHaveClass(/locked/);
 await createStep.click();
 await expect(page.getByLabel('Add Logs stage')).toBeVisible();
 await expect(page.locator('.beginner-navigation-hint')).toContainText('Start with Add Logs');
 expect(generated).toEqual([]);
});
test('denied backend metadata cannot release parser files or leak the source',async({page})=>{
 const sent:string[]=[];
 page.on('request',req=>{
   const path=new URL(req.url()).pathname;
   if(req.method()==='POST'&&path.includes('/parser-pairs/'))
     sent.push(path);
 });
 await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({status:403,
   contentType:'application/json',body:JSON.stringify({error:'CAPABILITY_DISABLED'})}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(input);
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(review).toBeEnabled({timeout:20000});
 await review.click();
 await expect(page.getByRole('alert')).toContainText(
   'The parser creation service is unavailable or access was denied.');
 await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
 await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(input);
 expect(sent.some(path=>path.endsWith('/generate')||path.includes('/target/apply'))).toBe(false);
});
test('desktop keyboard controls keep source local and enter Reviewed Fields without extra mode',async({page})=>{
 await page.setViewportSize({width:1440,height:900});
 await page.goto('/');
 await expect(page.getByLabel('Auto Parser raw logs')).toBeVisible();
 await page.getByLabel('Auto Parser raw logs').fill(input);
 await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2');
 await expect(page.evaluate(()=>document.documentElement.scrollWidth)).resolves.toBeLessThanOrEqual(1442);
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(review).toBeEnabled({timeout:20000});
 await review.focus();
 await expect(review).toBeFocused();
 await page.keyboard.press('Enter');
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
});
