import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const source='May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111 for net:10.10.10.10/53500 to inside:192.168.2.2/443';
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');

test('source extraction success is not falsely called parser-ready when the DRAFT compiler still needs a rule',async({page})=>{
 const response={
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'SOURCE_PARSED',syntax:'CISCO_ASA_MESSAGE',
  sourceSha256:sha(source),sourceBytes:Buffer.byteLength(source),
  fields:{event_id:'302013',protocol:'TCP',srcip:'10.10.10.10',srcport:53500,dstip:'192.168.2.2',dstport:443},
  spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
 };
 await page.route('**/api/v1/multipass/preview',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(response)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs'}).click();

 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('1 of 1 source event extracted');
 await expect(summary).toContainText('compiler-safe parser rule');
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Source fields were extracted, but parser generation needs one more rule');
 await expect(problem).toContainText('No source bytes are missing');
 await expect(problem).toContainText('Recommended fix · Message-body pattern');
 await expect(page.getByRole('button',{name:'Review Parsed Fields'})).toBeDisabled();

 await problem.getByRole('button',{name:'Ask ChatGPT'}).click();
 const prompt=page.getByLabel('Generated ChatGPT repair prompt');
 await expect(prompt).toContainText('ParserRecipe safety contract');
 await expect(prompt).toContainText('bounded parse_regex');
 await expect(prompt).toContainText('Return only one ParserRecipe v0.2 JSON object');
});
