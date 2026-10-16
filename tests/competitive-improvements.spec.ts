import {test,expect} from '@playwright/test';

const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy';

test('Review Fields explains the actual parsing path in beginner language',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(PAN);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('1 of 1 log event parsed completely',{timeout:15_000});
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:10_000});
  await review.click();

  const explain=page.getByLabel('How Parser Studio parsed this event');
  await expect(explain).toBeVisible();
  await expect(explain).toContainText('1. Event boundary');
  await expect(explain).toContainText('Syslog envelope fields were separated before the message body.');
  await expect(explain).toContainText('PRI: 14');
  await expect(explain).toContainText('Host: PA-FW01');
  await expect(explain).toContainText('Palo Alto Networks PAN-OS TRAFFIC ordered CSV');
  await expect(explain).toContainText('Engine path:');
  await expect(explain).toContainText('source values preserved');
  await expect(explain).toContainText('Native Fluentd and Stellar target import verification remain separate evidence gates.');
});

test('Map Fields exposes mapping name, value, coverage and catalog evidence',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(PAN);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:15_000});
  await review.click();
  const map=page.getByRole('button',{name:'Map Fields',exact:true});
  await expect(map).toBeEnabled({timeout:10_000});
  await map.click();

  const suggestions=page.getByLabel('Recommended field matches');
  const evidence=suggestions.locator('details.normalization-match-evidence').first();
  await expect(evidence).toBeVisible();
  await evidence.getByText('Why this match?').click();
  await expect(evidence).toContainText('Name evidence');
  await expect(evidence).toContainText('Value evidence');
  await expect(evidence).toContainText('Event coverage');
  await expect(evidence).toContainText('Catalog evidence');
  await expect(evidence).toContainText('Stellar field dictionary 7.0.xs');
});

test('mixed explicit families are isolated into an automatic parser set',async({page})=>{
  const {createHash}=await import('node:crypto');
  const source='TRAFFIC_EVT\nTHREAT_EVT';
  const lines=source.split('\n');
  const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
  await page.route('**/api/v1/multipass/preview-batch',async route=>{
    const body=route.request().postDataJSON() as {raw:string};
    expect(body.raw).toBe(source);
    const firstBytes=Buffer.byteLength(lines[0]!);
    const separatorStart=firstBytes;
    const secondStart=firstBytes+1;
    const makePreview=(raw:string,type:string,syntax:string)=>({
      contract:'parser-studio.multipass-source-preview.v0.1',
      status:'SOURCE_PARSED',syntax,sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),
      fields:{generic:{fields:{type}}},spans:[],residuals:[],issues:[],
      nativeVerified:false,targetVerified:false,
    });
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
      contract:'parser-studio.multipass-source-batch-preview.v0.1',
      sourceSha256:sha(source),sourceBytes:Buffer.byteLength(source),eventCount:2,
      events:[
        {index:0,startByte:0,endByte:firstBytes,
          preview:makePreview(lines[0]!,'TRAFFIC','SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV')},
        {index:1,startByte:secondStart,endByte:Buffer.byteLength(source),
          preview:makePreview(lines[1]!,'THREAT','SECURITY_SYSLOG_ENVELOPE+PANOS_THREAT_CSV')},
      ],
      separators:[{startByte:separatorStart,endByte:secondStart,kind:'WHITESPACE'}],
      nativeVerified:false,targetVerified:false,
    })});
  });

  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs'}).click();

  const parserSet=page.getByLabel('Automatic parser set');
  await expect(parserSet).toBeVisible();
  await expect(parserSet).toContainText('Multiple event families detected — create a parser set');
  await expect(parserSet).toContainText('found 2 distinct families');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();

  await parserSet.getByRole('button',{name:'Analyze parser-set family TRAFFIC'}).click();
  await expect(page.getByLabel('Separate log group context'))
    .toContainText('Palo Alto Networks · TRAFFIC · 1 events');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue('TRAFFIC_EVT');

  await page.getByRole('button',{name:'Return to all 2 logs'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
});

test('Create Parser can run bounded syntax-equivalent robustness checks without changing the source',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(PAN);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:15_000});
  await review.click();
  const map=page.getByRole('button',{name:'Map Fields',exact:true});
  await expect(map).toBeEnabled({timeout:10_000});
  await map.click();
  const create=page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'});
  await expect(create).toBeEnabled({timeout:10_000});
  await create.click();

  const checks=page.getByLabel('Synthetic robustness checks');
  await expect(checks).toBeVisible();
  const run=checks.getByRole('button',{name:/Run \d+ Synthetic Robustness Check/});
  await expect(run).toBeEnabled();
  await run.click();
  const result=page.getByLabel('Synthetic robustness check results');
  await expect(result).toContainText(/\d+\/\d+ syntax-equivalent checks? preserved the current normalized output/,
    {timeout:15_000});
  await expect(result).toContainText('Equivalent CSV quoting · Passed');
  await page.getByLabel('Create Parser stage').getByRole('button',{name:'Map Fields',exact:true}).click();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Back to Review Fields'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Back to Logs'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(PAN);
});
