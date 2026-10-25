import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
 'Requires explicitly pinned local authoring backend and multipass.');

async function propose(page:import('@playwright/test').Page,raw:string,holdout:string,columns:string[],delimiter:','|'\t'){
 await page.goto('/?workspace=chatgpt');
 await page.getByLabel('ChatGPT local sample logs').fill(raw);
 await page.getByLabel('ChatGPT solution vendor').fill('Generic');
 await page.getByLabel('ChatGPT solution product').fill('Security CSV');
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
 const m=prompt.match(/"projectId":"(draft-[a-z][a-z0-9_]+)","sourceHash":"([a-f0-9]{64})","sourceCount":(\d+)/);
 expect(m?.[2]).toBe(sha(raw));
 const stages:Array<Record<string,unknown>>=[
  {op:'split_event',boundary:'single-line'},{op:'parse_csv',columns,delimiter},
  ...columns.map(n=>({op:'map_field',source:n,target:n,data_type:'string',group:'vendor_fields'})),
  {op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'}
 ];
 const proposal={
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:m![1],sourceFormat:'csv',bodyFormat:'csv',
  sample:{sha256:sha(raw),events:Number(m![3])},stages,nativeVerified:false,targetVerified:false
 };
 await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(proposal));
 await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
 await expect(page.getByLabel('ChatGPT result ready for testing')).toContainText('accepted for testing');
 await page.getByLabel('Additional ChatGPT test logs').fill(holdout);
 await page.getByLabel('Confirm test examples are different').check();
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 const report=page.getByLabel('ChatGPT fix test result');
 await expect(report).toBeVisible({timeout:25000});
 return report;
}

test('a novice sees exact field-loss reason instead of generic failed status',async({page})=>{
 const raw='2026-10-19T09:15:22Z,192.0.2.10,"deny,malware",443';
 const hold=[
 '2026-10-19T09:15:23Z,192.0.2.20,"allow,web",8443',
 '2026-10-20T09:15:25Z,192.0.2.21,"deny,phishing",22'
 ].join('\n');
 const report=await propose(page,raw,hold,['column_1','column_2','column_3','column_4'],',');
 await expect(report).toContainText('Overall test: FAILED');
 const explanation=report.getByLabel('ChatGPT fix rejection details');
 await expect(explanation).toContainText('would remove 2 previously extracted original field path(s)');
 await expect(explanation).not.toContainText('192.0.2.10');
 await expect(page.getByRole('button',{name:'Apply Fix & Create Parser Files'})).toBeDisabled();
 await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
});
test('a novice sees why header-dependent source is unsupported without generating files',async({page})=>{
 const raw='#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-19 08:44:01 192.0.2.10 GET /login 403';
 const hold='#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-20 08:44:02 192.0.2.11 POST /submit 401\n2026-10-20 08:44:03 192.0.2.12 GET /health 200';
 const report=await propose(page,raw,hold,['date','time','cip','method','path','code'],'\t');
 await expect(report).toContainText('Overall test: FAILED');
 await expect(report.getByLabel('ChatGPT fix rejection details')).toContainText('Blocked:');
 await expect(page.getByRole('button',{name:'Apply Fix & Create Parser Files'})).toBeDisabled();
 await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
});
