import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const source='allow,198.51.100.10\ndeny,203.0.113.4';
const holdout='allow,192.0.2.10\ndeny,192.0.2.11';
const recipe=()=>({
 contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
 projectId:'draft-demo_firewall',sourceFormat:'csv',bodyFormat:'csv',
 sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
 stages:[
  {op:'split_event',boundary:'single-line'},
  {op:'parse_csv',columns:['action','src_ip'],delimiter:','},
  {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
  {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
  {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
  {op:'classify',defaultIndex:'syslog',rules:[]},
  {op:'fallback_unparsed',mode:'retain_unparsed'},
 ],nativeVerified:false,targetVerified:false,
});

test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1','Requires the exact pinned loopback backend integration job.');
test('RAW_ONLY ChatGPT recovery reaches verified DRAFT Ruby and CONF through the real backend',async({page})=>{
 await page.goto('/?workspace=chatgpt');
 await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
 await page.getByLabel('ChatGPT local sample logs').fill(source);
 await page.getByLabel('ChatGPT redacted examples').fill('allow,REDACTED_IP\ndeny,REDACTED_IP');
 await page.getByLabel('Confirm redacted example review').check();
 const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
 await expect(prepare).toBeEnabled();
 await prepare.click();
 const prompt=page.getByLabel('ChatGPT copyable prompt');
 await expect(prompt).toContainText('FULL_RECOVERY');
 await expect(prompt).toContainText('draft-demo_firewall');
 await page.getByLabel('ChatGPT pasted recipe').fill(JSON.stringify(recipe()));
 await page.getByRole('button',{name:'Validate AI Result'}).click();
 await expect(page.getByLabel('ChatGPT validated recipe')).toContainText('Full parser recovery');
 await page.getByLabel('ChatGPT independent holdout logs').fill(holdout);
 await page.getByLabel('Confirm ChatGPT holdout independence').check();
 await page.getByRole('button',{name:'Test Full Recovery Candidate'}).click();
 await expect(page.getByText('Full source + holdout qualification: PASS')).toBeVisible();
 await page.getByLabel('Approve verified ChatGPT parser candidate').check();
 await page.getByRole('button',{name:/Approve & Generate Ruby \+ CONF DRAFT Files/}).click();
 const generated=page.getByLabel('ChatGPT generated DRAFT pair');
 await expect(generated).toContainText('Two SHA-verified DRAFT files · Native and target NOT VERIFIED');
 await expect(generated.getByRole('button',{name:'Download customized_demo_firewall.conf'})).toBeVisible();
 await expect(generated.getByRole('button',{name:'Download customized_demo_firewall',exact:true})).toBeVisible();
 const downloadPromise=page.waitForEvent('download');
 await generated.getByRole('button',{name:'Download customized_demo_firewall.conf'}).click();
 const download=await downloadPromise;
 expect(download.suggestedFilename()).toBe('customized_demo_firewall.conf');
 await generated.getByRole('button',{name:'Review in Auto Parser'}).click();
 await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
});
