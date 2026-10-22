import {test,expect} from '@playwright/test';

const source=[
  JSON.stringify({log:'user=김민수\n',stream:'stdout',time:'2026-10-19T08:20:00Z'}),
  JSON.stringify({log:'denied\n',stream:'stderr',time:'2026-10-19T08:20:01Z'}),
].join('\n')+'\n';

test('original Docker source PARTIAL cannot become a downloadable parser through Analyze Logs',async({page})=>{
  const originalEvents:Array<{status:string;issues:string[]}>=[];
  page.on('response',async response=>{
    if(response.url().endsWith('/api/v1/multipass/preview-batch')&&response.ok()){
      const data=await response.json();
      for(const entry of data.events)originalEvents.push(entry.preview);
    }
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect.poll(()=>originalEvents.length,{timeout:18000}).toBe(2);
  expect(originalEvents.map(x=>x.status)).toEqual(['PARTIAL','PARTIAL']);
  expect(originalEvents.every(x=>x.issues.includes('FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER')))
    .toBe(true);
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeDisabled();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
  await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
});

test('Review Fields remains locked before Analyze Logs on original Docker source',async({page})=>{
  let sourceSent=false;
  page.on('request',req=>{
    if(req.url().endsWith('/api/v1/multipass/preview-batch'))sourceSent=true;
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeDisabled();
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeEnabled();
  await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
  expect(sourceSent).toBe(false);
});

test('normal Analyze Logs review remains available for supported ordinary JSON',async({page})=>{
  const ordinary='{"event_type":"threat","src_ip":"192.0.2.1","action":"deny"}';
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(ordinary);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await expect(page.getByLabel('Parser draft not ready')).toHaveCount(0);
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
});

for(const scenario of [
  {
    label:'Linux audit serial stream',
    text:'type=SYSCALL msg=audit(1760870000.123:12): syscall=59\n'+
      'type=PATH msg=audit(1760870000.123:12): name="/tmp/한글"\n',
  },
  {
    label:'Kubernetes CRI original wire messages',
    text:'2026-10-19T08:20:00Z stdout P 안녕\n'+
      '2026-10-19T08:20:01Z stdout F 하세요\n',
  },
  {
    label:'W3C original schema-dependent stream',
    text:'#Fields: date time c-ip cs-method sc-status\n'+
      '2026-10-19 08:20:00 192.0.2.1 GET 403\n',
  },
  {
    label:'Zeek original declared TSV stream',
    text:'#separator \\x09\n#fields\tts\tuid\tid.orig_h\n'+
      '1760870000.123\tCN1\t192.0.2.1\n',
  },
  {
    label:'RFC6587 octet-counted JSON',
    text:String(new TextEncoder().encode('{"event_type":"threat"}').length)+
      ' {"event_type":"threat"}',
  },
  {
    label:'RFC7464 original JSON text sequence',
    text:'\x1e{"event_type":"threat"}\n\x1e{"event_type":"user"}\n',
  },
  {
    label:'systemd journal text-export framing',
    text:'MESSAGE=login\nPRIORITY=5\n\nMESSAGE=denied\nPRIORITY=6\n',
  },
]){
  test('guided source-only block: '+scenario.label,async({page})=>{
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(scenario.text);
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(page.getByLabel('Beginner analysis summary'))
      .toBeVisible({timeout:20000});
    const review=page.getByRole('button',{name:'Review Fields',exact:true});
    await expect(review).toBeDisabled();
    await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
    await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(scenario.text);
  });
}
