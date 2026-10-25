import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
const record={rawSample:'2026-10-23 12:11:13,192.0.2.10,evil.example.test,Blocked,Malware,Internal Networks'};
const hash=createHash('sha256').update(record.rawSample).digest('hex');
const one='2026-10-23 12:11:14,192.0.2.11,benign.example.test,Allowed,Benign,Internal Networks';
const other='2026-10-23 12:11:15,192.0.2.12,investigate.example.test,Blocked,Phishing,Internal Networks';
test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Requires explicit same-version local authoring backend and Multi-Pass.');
test('novice ChatGPT holdout minimum gives actionable guidance before comparison',async({page})=>{
 await page.goto('/?workspace=chatgpt');
 await page.getByLabel('ChatGPT local sample logs').fill(record.rawSample);
 await page.getByLabel('ChatGPT solution vendor').fill('Cisco');
 await page.getByLabel('ChatGPT solution product').fill('Umbrella DNS');
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
 const projectId=prompt.match(/"projectId":"([^"]+)"/)?.[1];expect(projectId).toBeTruthy();
 const stages:any[]=[{op:'split_event',boundary:'single-line'},
   {op:'parse_csv',columns:['time_text','srcip','domain','action','category','source_group'],delimiter:','}];
 for(const [source,kind] of [['srcip','ip'],['domain','string'],['action','string'],['category','string']]){
   stages.push({op:'map_field',source,target:source,data_type:kind,group:'vendor_fields'});
   if(kind==='ip')stages.push({op:'cast_type',target:source,data_type:'ip'});
 }
 stages.push({op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'});
 const recipe={contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId,sourceFormat:'csv',bodyFormat:'csv',sample:{sha256:hash,events:1},
  stages,nativeVerified:false,targetVerified:false};
 await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe));
 await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
 await expect(page.getByLabel('ChatGPT result ready for testing')).toBeVisible();
 await expect(page.getByText('For a broader test, supply at least two different complete log events',{exact:false})).toBeVisible();
 const additional=page.getByLabel('Additional ChatGPT test logs');
 await additional.fill(one);
 await page.getByLabel('Confirm test examples are different').check();
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(page.getByText('Add at least 2 different additional log events; 1 provided.',{exact:false})).toBeVisible();
 await expect(page.getByLabel('ChatGPT fix test result')).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Apply Fix & Create Parser Files'})).toBeDisabled();
 await additional.fill(one+'\n'+other);
 await page.getByLabel('Confirm test examples are different').check();
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(page.getByLabel('ChatGPT fix test result')).toContainText('Overall test: PASS',{timeout:20000});
 await expect(page.getByText('Add at least 2 different additional log events; 1 provided.',{exact:false})).toHaveCount(0);
});
