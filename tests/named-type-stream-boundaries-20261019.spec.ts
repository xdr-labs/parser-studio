import {createHash} from 'node:crypto';
import {test,expect,type Page} from '@playwright/test';

const criOut=[
  '2026-10-19T08:20:00Z stdout P 김민',
  '2026-10-19T08:20:01Z stdout F 수',
].join('\n')+'\n';
const criErr='2026-10-19T08:20:02Z stderr F denied\n';
const dockerOut=JSON.stringify({
  log:'user=김민수\n',stream:'stdout',time:'2026-10-19T08:20:00Z',
})+'\n';
const dockerErr=JSON.stringify({
  log:'denied\n',stream:'stderr',time:'2026-10-19T08:20:01Z',
})+'\n';

async function named(page:Page,groups:readonly {name:string;source:string}[]){
  await page.goto('/');
  await page.getByRole('button',{name:'Add Another Log Type'}).click();
  for(let i=0;i<groups.length;i++){
    if(i>1)await page.getByLabel('Named log type samples')
      .getByRole('button',{name:'Add Another Log Type'}).click();
    await page.getByLabel('Log type name '+(i+1)).fill(groups[i]!.name);
    await page.getByLabel('Log type sample '+(i+1)).fill(groups[i]!.source);
    await expect(page.getByLabel('Log type sample '+(i+1))).toHaveValue(groups[i]!.source);
  }
}
async function analyze(page:Page,raw:string){
  const batches:Array<Record<string,unknown>>=[];
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('response',async response=>{
    if(response.url().endsWith('/api/v1/multipass/preview-batch')&&response.ok())
      batches.push(await response.json() as Record<string,unknown>);
  });
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect.poll(()=>batches.length,{timeout:20000}).toBe(1);
  const batch=batches[0]!;
  expect(batch.sourceBytes).toBe(Buffer.byteLength(raw,'utf8'));
  expect(batch.sourceSha256).toBe(createHash('sha256').update(raw).digest('hex'));
  expect(errors).toEqual([]);
  return batch;
}

for(const testcase of [
  {name:'CRI P/F stdout and standalone stderr',first:criOut,second:criErr,
    syntax:'CRI_PARTIAL_FINAL_GROUP'},
  {name:'Docker JSON-file stdout and stderr',first:dockerOut,second:dockerErr,
    syntax:'DOCKER_JSON_FILE'},
]){
  test(testcase.name+' retain exactly two logical source events',async({page})=>{
    await named(page,[
      {name:'stdout',source:testcase.first},
      {name:'stderr',source:testcase.second},
    ]);
    const original=testcase.first+testcase.second;
    const result=await analyze(page,original);
    expect(result.eventCount).toBe(2);
    const frames=result.events as Array<{
      startByte:number;endByte:number;
      preview:{status:string;syntax:string;nativeVerified:boolean;targetVerified:boolean};
    }>;
    expect(frames.map(row=>row.preview.status)).toEqual(['PARTIAL','PARTIAL']);
    expect(frames.map(row=>row.preview.syntax))
      .toEqual([testcase.syntax,testcase.syntax]);
    expect(frames.map(row=>row.startByte))
      .toEqual([0,Buffer.byteLength(testcase.first,'utf8')]);
    for(const frame of frames){
      expect(frame.preview.nativeVerified).toBe(false);
      expect(frame.preview.targetVerified).toBe(false);
    }
    const panel=page.getByLabel('Named log type samples');
    await expect(panel).toContainText('stdout: 1 event · 0 parsed · 1 partial');
    await expect(panel).toContainText('stderr: 1 event · 0 parsed · 1 partial');
    await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  });
}
test('a CRI logical event spanning named group boundaries cannot be assigned or exported',async({page})=>{
  const first='2026-10-19T08:20:00Z stdout P 김민\n';
  const second='2026-10-19T08:20:01Z stdout F 수\n';
  await named(page,[{name:'First fragment',source:first},
    {name:'Second fragment',source:second}]);
  const result=await analyze(page,first+second);
  expect(result.eventCount).toBe(1);
  const panel=page.getByLabel('Named log type samples');
  await expect(panel).toContainText('1 analyzed event(s) did not fit wholly within a named sample');
  await expect(panel).toContainText('An event crossed a group boundary');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
});
test('JSON event types each ending in LF still complete the reviewed single-parser DRAFT',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Conditional parser downloads require the exact-HEAD authoring backend.');
  const sources=[
    {name:'Threat',source:'{"event_type":"threat","src_ip":"192.0.2.20","action":"deny"}\n'},
    {name:'User',source:'{"event_type":"user","username":"김민수","action":"login"}\n'},
    {name:'Asset',source:'{"event_type":"asset","hostname":"fw01","action":"found"}\n'},
  ];
  await named(page,sources);
  const result=await analyze(page,sources.map(row=>row.source).join(''));
  expect(result.eventCount).toBe(3);
  await page.getByLabel('Add Logs stage')
    .getByRole('button',{name:'Review Fields',exact:true}).click();
  const review=page.getByLabel('Review Fields stage');
  await expect(review).toBeVisible();
  const router=review.getByLabel('Configure one parser for event types');
  if(!(await router.evaluate(el=>(el as HTMLDetailsElement).open)))
    await router.locator('summary').first().click();
  await expect(router.getByLabel('Proposed event type rules')).toContainText('3 reviewed types');
  await router.getByLabel('Approve explicit family routing changes').check();
  await router.getByRole('button',{name:'Apply reviewed event types to this parser'}).click();
  await review.getByRole('button',{name:'Map Fields'}).click();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await page.getByLabel('Create Parser Files').click();
  const files=page.getByLabel('Generated parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:25000});
  const task=page.waitForEvent('download');
  await files.getByRole('button',{name:/customized_demo_firewall$/}).click();
  const downloaded=await task;
  expect(downloaded.suggestedFilename()).toBe('customized_demo_firewall');
  const stream=await downloaded.createReadStream();
  const chunks:Buffer[]=[];
  for await(const chunk of stream)chunks.push(Buffer.from(chunk));
  const ruby=Buffer.concat(chunks).toString('utf8');
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(ruby)?.[1];
  expect(encoded).toBeTruthy();
  const config=JSON.parse(Buffer.from(encoded!,'base64').toString('utf8'));
  expect(config.normalization.eventProfiles.variants.map((x:{name:string})=>x.name))
    .toEqual(['threat','user','asset']);
  expect(JSON.stringify(config)).not.toContain('김민수');
});

test('a browser-saved named snapshot from the old separator algorithm remains restorable without altering original samples',async({page})=>{
  const threat='{"event_type":"threat","src_ip":"192.0.2.20"}\n';
  const user='{"event_type":"user","username":"김민수"}\n';
  await named(page,[{name:'Threat',source:threat},{name:'User',source:user}]);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Older separator version');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history.getByLabel('Saved local versions')).toContainText('Older separator version');
  // Simulate a correctly hashed historical IndexedDB record. The old
  // application inserted an LF between named groups even after a trailing LF.
  await page.evaluate(async()=>{
    const db=await new Promise<IDBDatabase>((resolve,reject)=>{
      const req=indexedDB.open('parser-studio-user-experiments-v1',1);
      req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
    });
    try{
      const rows=await new Promise<Array<Record<string,unknown>>>((resolve,reject)=>{
        const req=db.transaction('versions','readonly').objectStore('versions').getAll();
        req.onsuccess=()=>resolve(req.result as Array<Record<string,unknown>>);
        req.onerror=()=>reject(req.error);
      });
      const row=rows.find(item=>item.label==='Older separator version');
      if(!row||!Array.isArray(row.logTypes))throw Error('Saved original missing');
      const groups=row.logTypes as Array<{sample:string}>;
      row.source=groups.map(item=>item.sample).join('\n');
      const data=JSON.stringify([
        row.contract,row.id,row.label,row.createdAt,row.datasetName,
        row.source,row.draft,row.logTypes,
      ]);
      const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(data));
      row.sha256=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
      await new Promise<void>((resolve,reject)=>{
        const tx=db.transaction('versions','readwrite');
        tx.objectStore('versions').put(row);
        tx.oncomplete=()=>resolve();tx.onerror=()=>reject(tx.error);
      });
    }finally{db.close();}
  });
  await page.reload();
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const saved=page.getByLabel('Local Versions workspace');
  await expect(saved.getByLabel('Saved local versions')).toContainText('Older separator version');
  page.on('dialog',dialog=>dialog.accept());
  await saved.getByText('Older separator version',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Log type name 1')).toHaveValue('Threat');
  await expect(page.getByLabel('Log type name 2')).toHaveValue('User');
  await expect(page.getByLabel('Log type sample 1')).toHaveValue(threat);
  await expect(page.getByLabel('Log type sample 2')).toHaveValue(user);
  await expect(saved.getByRole('status')).toContainText('redundant separators');
  await expect(saved.getByRole('status')).toContainText('saved snapshot and each original log type are unchanged');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Named log type samples')).toContainText('Threat: 1 event');
  await expect(page.getByLabel('Named log type samples')).toContainText('User: 1 event');
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2 of 2');
  // The historic stored artifact remains byte-exact and checksum-valid;
  // only the newly restored in-memory working source omits generated LF.
  await expect(saved.getByLabel('Saved local versions')).toContainText('Older separator version');
});
