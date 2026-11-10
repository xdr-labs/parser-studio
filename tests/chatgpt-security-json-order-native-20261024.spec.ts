import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';

test('a security parser from an unedited valid first reply compiles despite JSON property ordering',async({page,context})=>{
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  const source=[
    '2026-10-24 12:11:13,192.0.2.30,attack.example.test,Blocked,Malware,Policy_A',
    '2026-10-24 12:11:14,192.0.2.31,benign.example.test,Allowed,Safe,Policy_B',
  ].join('\n');
  const holdout=[
    '2026-10-24 12:11:15,192.0.2.32,malicious.example.test,Blocked,Malware,Policy_C',
    '2026-10-24 12:11:16,192.0.2.33,normal.example.test,Allowed,Safe,Policy_D',
  ].join('\n');
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await page.getByLabel('Parser manufacturer').fill('Cisco');
  await page.getByLabel('Parser product',{exact:true}).fill('Umbrella DNS');
  await page.getByLabel('ChatGPT desired fields').fill('Extract DNS domain, source IP, action and category without guessing new columns.');
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const copied=page.getByLabel('ChatGPT copyable prompt');
  await expect(copied).toBeVisible({timeout:20000});
  const prompt=await copied.inputValue();
  expect(prompt).toContain(source);
  expect(prompt).toContain('FULL_RECOVERY');
  await page.getByRole('button',{name:'Copy Prompt'}).click();
  expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe(prompt);
  const hash=createHash('sha256').update(source).digest('hex');
  const identity=prompt.match(/\{"projectId":"([^"]+)","sourceHash":"([a-f0-9]{64})","sourceCount":(\d+)\}/);
  expect(identity).toBeTruthy();
  expect(identity![2]).toBe(hash);
  expect(Number(identity![3])).toBe(2);
  const maps=[
    {source:'source_ip',target:'custom.source_ip',type:'ip'},
    {source:'domain',target:'custom.domain',type:'string'},
    {source:'action',target:'custom.action',type:'string'},
    {source:'category',target:'custom.category',type:'string'},
  ] as const;
  // This is a strict and valid model reply with intentionally noncanonical
  // JSON key order: an ordinary ChatGPT user must never be required to sort keys.
  const answer={
    nativeVerified:false,targetVerified:false,
    compilerMode:'REVIEW_ONLY',schemaRevision:'0.2',contract:'parser-studio.recipe.v0.2',
    stages:[
      {boundary:'single-line',op:'split_event' as const},
      {columns:['datetime','source_ip','domain','action','category','policy'],delimiter:',',op:'parse_csv' as const},
      ...maps.flatMap(m=>[
        {group:'top_fields',data_type:m.type,source:m.source,target:m.target,op:'map_field' as const},
        ...(m.type==='string'?[]:[{data_type:m.type,target:m.target,op:'cast_type' as const}]),
      ]),
      {rules:[],defaultIndex:'syslog',op:'classify' as const},
      {mode:'retain_unparsed',op:'fallback_unparsed' as const},
    ],
    sample:{events:2,sha256:hash},bodyFormat:'csv',sourceFormat:'csv',
    projectId:identity![1],
  };
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(answer));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing')).toBeVisible({timeout:12000});
  await page.getByLabel('Additional ChatGPT test logs').fill(holdout);
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  await expect(page.getByLabel('ChatGPT fix test result')).toContainText('Overall test: PASS',{timeout:15000});
  await page.getByLabel('Approve tested ChatGPT fix').check();
  await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
  const files=page.getByLabel('ChatGPT created parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:22000});
  const download=page.waitForEvent('download',{timeout:9000});
  await files.getByRole('button',{name:/Download .*\.conf$/}).click();
  const conf=await download;
  expect(conf.suggestedFilename()).toMatch(/\.conf$/);
});
