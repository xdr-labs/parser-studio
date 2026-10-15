import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const source=[
 'May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111111111 for net:10.10.10.10/53500 (81.2.69.144/53500) to fw111:192.168.2.2/53500 (81.2.69.144/53500)',
 'May  5 17:51:18 dev01: %FTD-6-302015: Built inbound UDP connection 111111112 for net:10.10.10.11/53501 (81.2.69.144/53501) to fw111:192.168.2.3/53 (81.2.69.144/53)',
].join('\n');
const holdout=[
 'May  6 18:11:01 dev02: %FTD-6-302013: Built inbound TCP connection 222222221 for outside:10.20.30.40/60123 (81.2.69.145/60123) to inside:172.16.1.10/443 (81.2.69.145/443)',
 'May  6 18:11:02 dev02: %FTD-6-302015: Built inbound UDP connection 222222222 for outside:10.20.30.41/60124 (81.2.69.145/60124) to inside:172.16.1.11/53 (81.2.69.145/53)',
].join('\n');
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const pattern=String.raw`^.*%FTD-\d-(?<event_id>\d+): Built inbound (?<protocol>TCP|UDP) connection \d+ for \w+:(?<srcip>[0-9.]+)/(?<srcport>\d+) .* to \w+:(?<dstip>[0-9.]+)/(?<dstport>\d+).*$`;

function batch(raw:string){
 const lines=raw.split('\n');
 let cursor=0;
 const events=lines.map((line,index)=>{
  const startByte=cursor,endByte=startByte+Buffer.byteLength(line);
  cursor=endByte+(index<lines.length-1?1:0);
  const marker=line.indexOf('Built inbound');
  const startResidual=Buffer.byteLength(line.slice(0,marker));
  return {index,startByte,endByte,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',
   status:'PARTIAL',syntax:'BSD_SYSLOG+UNKNOWN',
   sourceSha256:sha(line),sourceBytes:Buffer.byteLength(line),
   fields:{syslog_message_id:line.match(/%FTD-\d-(\d+)/)?.[1]??''},
   spans:[],residuals:[{startByte:startResidual,endByte:Buffer.byteLength(line)}],
   issues:['NO_SUPPORTED_GRAMMAR'],nativeVerified:false,targetVerified:false,
  }};
 });
 const separators=lines.slice(0,-1).map((line,index)=>{
  const end=events[index]!.endByte;return {startByte:end,endByte:end+1,kind:'WHITESPACE'};
 });
 return {contract:'parser-studio.multipass-source-batch-preview.v0.1',
  sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),eventCount:events.length,
  events,separators,nativeVerified:false,targetVerified:false};
}

const recipe={
 contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
 projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
 sample:{sha256:sha(source),events:2},
 stages:[
  {op:'split_event',boundary:'single-line'},
  {op:'parse_regex',pattern},
  {op:'map_field',source:'event_id',target:'custom.event_id',data_type:'integer',group:'ns_fields'},
  {op:'cast_type',target:'custom.event_id',data_type:'integer'},
  {op:'map_field',source:'protocol',target:'custom.protocol',data_type:'string',group:'top_fields'},
  {op:'map_field',source:'srcip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
  {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
  {op:'map_field',source:'srcport',target:'custom.source_port',data_type:'port',group:'ns_fields'},
  {op:'cast_type',target:'custom.source_port',data_type:'port'},
  {op:'map_field',source:'dstip',target:'custom.destination_ip',data_type:'ip',group:'top_fields'},
  {op:'cast_type',target:'custom.destination_ip',data_type:'ip'},
  {op:'map_field',source:'dstport',target:'custom.destination_port',data_type:'port',group:'ns_fields'},
  {op:'cast_type',target:'custom.destination_port',data_type:'port'},
  {op:'classify',defaultIndex:'syslog',rules:[]},
  {op:'fallback_unparsed',mode:'retain_unparsed'},
 ],
 nativeVerified:false,targetVerified:false,
};

test('beginner can recover Cisco FTD with a ChatGPT bounded Regex recipe, independent holdout and explicit approval',async({page})=>{
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(batch(source))}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('0 of 2 log events parsed completely');
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Recommended fix · Create a rule for the remaining message text');
 await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
 const prompt=page.getByLabel('Generated ChatGPT repair prompt');
 await expect(prompt).toContainText('parse_regex');
 await expect(prompt).toContainText('Return only one ParserRecipe v0.2 JSON object');

 const ai=page.getByLabel('AI result verification');
 await expect(ai).toBeVisible();
 await ai.getByLabel('ChatGPT JSON result').fill(JSON.stringify(recipe));
 await ai.getByLabel('Additional test logs').fill(holdout);
 await ai.getByLabel('Confirm different test examples').check();
 await ai.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(ai).toContainText('Fix passed: full parser recovery');
 await expect(ai).toContainText('2 additional test logs checked');
 await ai.getByLabel('Approve tested fix').check();
 await ai.getByRole('button',{name:'Apply Verified Fix'}).click();
 await expect(summary).toContainText('2 of 2 log events parsed completely',{timeout:10000});
 await expect(summary).toContainText('reviewed parser fix passes the current sample');
 await expect(page.getByLabel('Parse problem inspector')).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
 if(process.env.PARSER_STUDIO_LIVE_BACKEND==='1'){
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:/Create Parser/}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const generated=page.getByLabel('Generated Auto Parser DRAFT pair');
  await expect(generated).toContainText('Parser files created successfully');
  await expect(generated.getByLabel('Parser file verification details'))
    .toContainText('Two DRAFT files verified');
 }
});
