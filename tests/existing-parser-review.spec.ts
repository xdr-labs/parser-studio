import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
import {createDraft} from '../src/model';
import {toBackendProject} from '../src/guided/backendAdapter';

function project(){
 const draft=createDraft();draft.format='json';draft.name='Imported Synthetic Parser';
 const result=toBackendProject(draft);if(!result.ok)throw new Error('fixture project invalid');
 return result.project;
}
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const ruby='# STELLAR_INIT_BEGIN\n# STELLAR_PARSE_BEGIN\ndef parse(text)\nend\n# STELLAR_PARSE_END\n';
const conf='<source>\n  @type udp\n  port 6801\n  tag customized_demo_firewall\n  <parse>\n    @type customized_demo_firewall\n  </parse>\n</source>\n';

test('Advanced local Project JSON review restores exact draft and clears raw samples without network',async({page})=>{
 let requests=0;page.on('request',r=>{if(r.url().includes('/api/v1/parser-pairs/inspect'))requests++;});
 await page.goto('/');
 await page.getByRole('button',{name:'Advanced'}).click();
 await expect(page.getByRole('button',{name:'Return to Beginner Mode'})).toBeVisible();
 await page.getByLabel('Auto Parser raw logs').fill('{"action":"deny"}');
 const panel=page.getByLabel('Existing parser review and import');await expect(panel).toBeVisible();await panel.locator('summary').click();
 await page.getByLabel('Existing Parser Project JSON').setInputFiles({
  name:'parser-project.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(project())),
 });
 const local=page.getByLabel('Offline Project JSON review');
 await expect(local).toContainText('Project file checked · Ready to reopen');
 await expect(local).toContainText('Imported Synthetic Parser');
 await local.getByRole('button',{name:'Restore Reviewed Project into Auto Parser'}).click();
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue('');
 await expect(page.getByText('Imported Project JSON · samples cleared',{exact:false})).toBeVisible();
 expect(requests).toBe(0);
});

test('opaque Ruby CONF pair stays read-only and never echoes source code',async({page})=>{
 let posts=0;
 await page.route('**/api/v1/parser-pairs/inspect',async route=>{
  posts++;const input=route.request().postDataJSON();
  expect(input.name).toBe('customized_demo_firewall');
  expect(input.fragmentContent).toBe(ruby);expect(input.confContent).toBe(conf);
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
   format:'host-customized-pair',name:input.name,
   originalHashes:{conf:sha(conf),fragment:sha(ruby)},
   receiver:{protocols:['udp'],ports:[6801],sourceCount:1},
   fragment:{markersComplete:true,hasParseEntry:true,opaqueRuby:true},
   importStatus:'OPAQUE_READ_ONLY',roundTripVerified:false,portableProject:null,
   diagnostics:[{code:'PAIR_NOT_REPRODUCIBLE',severity:'warning',message:'PRIVATE_BACKEND_TEXT'}],warnings:[],
  })});
 });
 await page.goto('/');await page.getByRole('button',{name:'Advanced'}).click();await expect(page.getByRole('button',{name:'Return to Beginner Mode'})).toBeVisible();const panel=page.getByLabel('Existing parser review and import');await expect(panel).toBeVisible();await panel.locator('summary').click();
 await page.getByLabel('Existing parser logic file').setInputFiles({name:'customized_demo_firewall',mimeType:'text/plain',buffer:Buffer.from(ruby)});
 await page.getByLabel('Existing parser listener configuration').setInputFiles({name:'customized_demo_firewall.conf',mimeType:'text/plain',buffer:Buffer.from(conf)});
 expect(posts).toBe(0);
 await page.getByRole('button',{name:'Inspect Pair Read-only'}).click();
 const review=page.getByLabel('Existing parser pair review');
 await expect(review).toContainText('Existing parser is available for inspection only');
 await expect(review).toContainText('Exact byte reproduction from a supported backend project was not established');
 await expect(review).not.toContainText('PRIVATE_BACKEND_TEXT');
 await expect(review).not.toContainText('STELLAR_PARSE_BEGIN');
 await expect(review.getByRole('button',{name:'Restore Exact Pair into Auto Parser'})).toHaveCount(0);
 expect(posts).toBe(1);
});

test('exact inspected pair requires explicit restore and clears current sample',async({page})=>{
 const portable=project();let posts=0;
 await page.route('**/api/v1/parser-pairs/inspect',async route=>{
  posts++;await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
   format:'host-customized-pair',name:'customized_demo_firewall',
   originalHashes:{conf:sha(conf),fragment:sha(ruby)},
   receiver:{protocols:['udp','tcp'],ports:[6801],sourceCount:2},
   fragment:{markersComplete:true,hasParseEntry:true,opaqueRuby:false},
   importStatus:'EDITABLE_EXACT',roundTripVerified:true,portableProject:portable,diagnostics:[],warnings:[],
  })});
 });
 await page.goto('/');await page.getByRole('button',{name:'Advanced'}).click();await expect(page.getByRole('button',{name:'Return to Beginner Mode'})).toBeVisible();await page.getByLabel('Auto Parser raw logs').fill('{"private":"sample"}');
 const panel=page.getByLabel('Existing parser review and import');await expect(panel).toBeVisible();await panel.locator('summary').click();
 await page.getByLabel('Existing parser logic file').setInputFiles({name:'customized_demo_firewall',mimeType:'text/plain',buffer:Buffer.from(ruby)});
 await page.getByLabel('Existing parser listener configuration').setInputFiles({name:'customized_demo_firewall.conf',mimeType:'text/plain',buffer:Buffer.from(conf)});
 await page.getByRole('button',{name:'Inspect Pair Read-only'}).click();
 const review=page.getByLabel('Existing parser pair review');
 await expect(review).toContainText('Existing parser can be reopened safely');
 await expect(review).toContainText('Technical file checks');
 await review.getByRole('button',{name:'Restore Exact Pair into Auto Parser'}).click();
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue('');
 await expect(page.getByText('Imported exact Ruby/CONF project · samples cleared',{exact:false})).toBeVisible();
 expect(posts).toBe(1);
});
