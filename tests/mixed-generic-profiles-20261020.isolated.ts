import {test,expect,type Page,type TestInfo} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {writeFile} from 'node:fs/promises';
import type {BackendParserProject} from '../src/guided/backendAdapter';

// Three synthetic browser journeys use the actual same-origin authoring and
// source-preview services. The configured origin may be isolated or public.
const fixture=JSON.parse(readFileSync(new URL('./fixtures/mixed-generic-profiles-20261020.json',import.meta.url),'utf8')) as {
  profile:string;syslog:string;leef:string;malformedLeef:string;
};
const profile='syslog_prefix_kv_leef2_implicit_tab_v1';
const expectedPaths=[
  'syslog.pri','syslog.month','syslog.day','syslog.time','syslog.hostname','syslog.time_policy',
  'generic.prefix','generic.message_raw',
  'generic.kv.src','generic.kv.action','generic.kv.user','generic.kv.note',
  'leef_header.version','leef_header.vendor','leef_header.product','leef_header.product_version','leef_header.event_id',
  'leef_extension.user','leef_extension.src','leef_extension.dst','leef_extension.action','leef_extension.message',
];
const expectedSyslog={
  syslog:{pri:'134',month:'Oct',day:'20',time:'08:23:59',hostname:'edge01',time_policy:'YEAR_AND_ZONE_UNKNOWN'},
  generic:{mode:'syslog_prefix_kv',prefix:'Security event observed ',
    message_raw:fixture.syslog.slice('<134>Oct 20 08:23:59 edge01 '.length),source_raw:fixture.syslog,
    kv:{src:'192.0.2.10',action:'deny',user:'담당자 홍 길동',note:'  padded value  '}},
};
const expectedLeef={
  leef_header:{version:'2.0',vendor:'  Example Vendor  ',product:'Security Suite',product_version:'1.0',event_id:'web block'},
  leef_extension:{user:'  김 민수  ',src:'192.0.2.20',dst:'198.51.100.9',action:'blocked',message:'  café 東京  '},
  generic:{mode:'leef2_implicit_tab',source_raw:fixture.leef},
};
type EventSnapshot={raw:string;fields:Record<string,unknown>;normalized:Record<string,unknown>};
type SavedVersion={label:string;source:string;sha256:string;draft:{format:string;genericStructuralProfile?:string;
  mappings:Array<{source:string;target:string;type:string}>}};
const sha256=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');

function watchBrowser(page:Page,info:TestInfo){
  const baseURL=info.project.use.baseURL;
  if(typeof baseURL!=='string')throw new Error('The mixed-profile browser suite requires one configured origin');
  const origin=new URL(baseURL).origin;
  const browserErrors:string[]=[];
  const serverFailures:string[]=[];
  const offOriginRequests:string[]=[];
  const downloads:string[]=[];
  const apiRequests:Array<{path:string;method:string}>=[];
  const apiResponses:Array<{path:string;method:string;status:number}>=[];
  page.on('pageerror',error=>browserErrors.push(error.message));
  page.on('download',download=>downloads.push(download.suggestedFilename()));
  page.on('request',request=>{
    if(!/^https?:/.test(request.url()))return;
    const url=new URL(request.url());
    if(url.origin!==origin)offOriginRequests.push(url.origin);
    else if(url.pathname.startsWith('/api/'))apiRequests.push({path:url.pathname,method:request.method()});
  });
  page.on('response',response=>{
    const url=new URL(response.url());
    if(url.origin!==origin||!url.pathname.startsWith('/api/'))return;
    apiResponses.push({path:url.pathname,method:response.request().method(),status:response.status()});
    if(response.status()>=500)serverFailures.push(response.status()+' '+url.pathname);
  });
  return {origin,browserErrors,serverFailures,offOriginRequests,downloads,apiRequests,apiResponses};
}
function assertBrowserHealthy(observed:ReturnType<typeof watchBrowser>){
  expect(observed.browserErrors).toEqual([]);
  expect(observed.serverFailures).toEqual([]);
  expect(observed.offOriginRequests).toEqual([]);
}
function fieldAt(record:unknown,path:string):unknown{
  let value=record;
  for(const part of path.split('.')){
    if(!value||typeof value!=='object'||!Object.prototype.hasOwnProperty.call(value,part))return undefined;
    value=(value as Record<string,unknown>)[part];
  }
  return value;
}
function expectedFields(raw:string){
  if(raw===fixture.syslog)return expectedSyslog;
  if(raw===fixture.leef)return expectedLeef;
  throw new Error('Unexpected synthetic source event');
}

async function analyzeComplete(page:Page,raw:string){
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('2 of 2 log events structurally parsed',{timeout:30000});
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled({timeout:30000});
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
}

async function inspectBothEvents(page:Page,ordered:string[]):Promise<EventSnapshot[]>{
  const review=page.getByLabel('Review Fields stage');
  await expect(review).toBeVisible({timeout:30000});
  const inspector=review.getByLabel('Browser-only event inspector');
  const snapshots:EventSnapshot[]=[];
  for(const [index,raw] of ordered.entries()){
    await review.getByLabel('Auto Parser review event').selectOption({index});
    // textContent compares literal spaces and UTF-8; a text matcher may collapse them.
    await expect.poll(()=>inspector.locator('pre').nth(0).textContent()).toBe(raw);
    const fields=JSON.parse((await inspector.locator('pre').nth(1).textContent())!) as Record<string,unknown>;
    const normalized=JSON.parse((await inspector.locator('pre').nth(2).textContent())!) as Record<string,unknown>;
    expect(fields).toEqual(expectedFields(raw));
    expect(normalized.parserstudio_source).toEqual(expectedFields(raw));
    snapshots.push({raw,fields,normalized});
  }
  return snapshots;
}

function assertCompleteProject(project:BackendParserProject,snapshots:EventSnapshot[]){
  expect(project.extraction).toEqual({format:'generic_structural',genericStructuralProfile:profile});
  const {topFields,nsFields,vendorFields}=project.normalization;
  const sources=[...Object.keys(topFields),...Object.keys(nsFields),...Object.keys(vendorFields)];
  expect(sources).toHaveLength(expectedPaths.length);
  expect(new Set(sources)).toEqual(new Set(expectedPaths));
  const targets=[...Object.values(topFields),...Object.values(nsFields)].map(field=>field.normalized_name);
  targets.push(...Object.values(vendorFields).map(field=>project.vendor+'.'+field.normalized_name));
  expect(new Set(targets).size).toBe(targets.length);
  for(const key of ['src','action','user']){
    for(const source of ['generic.kv.'+key,'leef_extension.'+key])
      expect(vendorFields[source],source+' must retain its own vendor destination')
        .toMatchObject({normalized_name:source,data_type:'string'});
  }
  for(const snapshot of snapshots){
    for(const [mappings,output] of [
      [topFields,snapshot.normalized],[nsFields,snapshot.normalized],
      [vendorFields,snapshot.normalized[project.vendor]],
    ] as const){
      for(const [source,field] of Object.entries(mappings)){
        const original=fieldAt(snapshot.fields,source);
        if(original===undefined||field.data_type!=='string')continue;
        expect(fieldAt(output,field.normalized_name),source+' keeps its original string value').toBe(original);
      }
    }
  }
}

async function createAndDownload(page:Page,info:TestInfo,ordered:string[]){
  const raw=ordered.join('\n');
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  const snapshots=await inspectBothEvents(page,ordered);
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields',exact:true}).click();
  const mapping=page.getByLabel('Map Fields stage');
  // Mixed event families legitimately carry per-family field absence notes.
  // Only blocking mapping problems should prevent DRAFT creation.
  await expect(mapping.getByLabel('Field mapping summary'))
    .toContainText(/Must fix before continuing\s*0/);
  await mapping.getByRole('button',{name:'Create Parser',exact:true}).click();
  const create=page.getByLabel('Create Parser Files');
  await expect(create).toBeEnabled();
  await create.click();
  const generated=page.getByLabel('Generated parser files');
  await expect(generated).toContainText('Parser files created successfully',{timeout:30000});
  await expect(generated).toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
  await expect(page.getByLabel('Auto Parser test evidence')).toContainText('2 sample events passed browser checks');
  const files:Record<string,string>={};
  for(const filename of ['customized_demo_firewall','customized_demo_firewall.conf']){
    const pending=page.waitForEvent('download');
    await generated.getByRole('button',{name:filename,exact:true}).click();
    const download=await pending;
    expect(download.suggestedFilename()).toBe(filename);
    const stream=await download.createReadStream();
    if(!stream)throw new Error('The actual generated download stream is unavailable');
    const chunks:Buffer[]=[];
    for await(const chunk of stream)chunks.push(Buffer.from(chunk));
    files[filename]=Buffer.concat(chunks).toString('utf8');
    expect(files[filename]!.length).toBeGreaterThan(0);
    await download.saveAs(info.outputPath(filename));
  }
  const encoded=/Base64.strict_decode64\('([^']+)'\)/.exec(files.customized_demo_firewall!)?.[1];
  expect(encoded).toBeTruthy();
  if(!encoded)throw new Error('The actual Ruby download lacks its embedded Project');
  const project=JSON.parse(Buffer.from(encoded,'base64').toString('utf8')) as BackendParserProject;
  assertCompleteProject(project,snapshots);
  const artifacts=Object.entries(files).map(([filename,content])=>({filename,sha256:sha256(content),bytes:Buffer.byteLength(content,'utf8')}));
  await writeFile(info.outputPath('mixed-source-and-project.json'),JSON.stringify({
    raw,sourceSha256:sha256(raw),project,snapshots,artifacts,
  },null,2));
  await page.screenshot({path:info.outputPath('mixed-parser-downloads.png'),fullPage:true});
  await page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button',{name:/Add Logs/}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  return {project,artifacts,sourceSha256:sha256(raw)};
}

async function savedVersions(page:Page):Promise<SavedVersion[]>{
  return page.evaluate(async()=>{
    const db=await new Promise<IDBDatabase>((resolve,reject)=>{
      const request=indexedDB.open('parser-studio-user-experiments-v1',1);
      request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);
    });
    try{
      return await new Promise<SavedVersion[]>((resolve,reject)=>{
        const tx=db.transaction('versions','readonly');
        const request=tx.objectStore('versions').getAll();
        request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);
      });
    }finally{db.close();}
  });
}

async function attachEvidence(info:TestInfo,observed:ReturnType<typeof watchBrowser>,details:Record<string,unknown>){
  assertBrowserHealthy(observed);
  await info.attach('mixed-profile-browser-evidence',{contentType:'application/json',body:JSON.stringify({
    contract:'parser-studio.mixed-generic-profile-browser.v1',profile,
    mockedResponses:false,liveTargetVerified:false,...observed,...details,
  },null,2)});
}

test.beforeEach(()=>{
  expect(fixture.profile).toBe(profile);
  // Five keys would already qualify for V15 and would not exercise the new combination.
  const syslogKeys=[...fixture.syslog.matchAll(/(?:^|[ \t])([A-Za-z_][A-Za-z0-9_-]*)=/g)].map(match=>match[1]);
  expect(syslogKeys).toEqual(['src','action','user','note']);
  expect(syslogKeys).toHaveLength(4);
});

test('Syslog then implicit-TAB LEEF completes review and both actual parser downloads with the full source union',async({page},info)=>{
  test.setTimeout(120000);
  const observed=watchBrowser(page,info);
  const ordered=[fixture.syslog,fixture.leef];
  await page.goto('/');
  await analyzeComplete(page,ordered.join('\n'));
  const result=await createAndDownload(page,info,ordered);
  expect(observed.downloads).toEqual(['customized_demo_firewall','customized_demo_firewall.conf']);
  expect(observed.apiResponses).toEqual(expect.arrayContaining([
    {path:'/api/v1/parser-pairs/capabilities',method:'GET',status:200},
  ]));
  expect(observed.apiResponses.some(response=>response.path.startsWith('/api/v1/parser-pairs/')&&
    response.method==='POST'&&response.status===200)).toBe(true);
  await attachEvidence(info,observed,{order:'syslog-then-leef',...result});
});

test('LEEF then Syslog survives local save, reload and restore before both actual parser downloads',async({page},info)=>{
  test.setTimeout(120000);
  const observed=watchBrowser(page,info);
  const ordered=[fixture.leef,fixture.syslog];
  const raw=ordered.join('\n');
  const label='Mixed profile reverse order with padded UTF-8 values';
  await page.goto('/');
  await analyzeComplete(page,raw);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill(label);
  await history.getByRole('button',{name:'Save Version',exact:true}).click();
  await expect(history.getByLabel('Saved local versions')).toContainText(label);
  await expect(history.getByRole('status')).toContainText('Saved in this browser only');
  const saved=(await savedVersions(page)).find(version=>version.label===label);
  expect(saved?.source).toBe(raw);
  expect(saved?.draft).toMatchObject({format:'generic_structural',genericStructuralProfile:profile});
  expect(saved?.sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(new Set(saved?.draft.mappings.map(mapping=>mapping.source))).toEqual(new Set(expectedPaths));
  await page.getByLabel('Auto Parser raw logs').fill(fixture.syslog);
  await page.reload();
  await expect(page.getByLabel('Auto Parser raw logs')).not.toHaveValue(raw);
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const restoredHistory=page.getByLabel('Local Versions workspace');
  await expect(restoredHistory.getByLabel('Saved local versions')).toContainText(label);
  page.on('dialog',dialog=>dialog.accept());
  await restoredHistory.getByLabel('Saved local versions').getByText(label,{exact:true})
    .locator('..').locator('..').getByRole('button',{name:'Restore',exact:true}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  await expect(restoredHistory.getByRole('status')).toContainText('Re-run Analyze Logs before generating parser files.');
  expect((await savedVersions(page)).find(version=>version.label===label)).toEqual(saved);
  // Re-save the restored working state before analysis can reconstruct a draft.
  // This checks that restore itself retained the scalar profile and mappings.
  const restoredLabel='Restored mixed profile and padded values';
  await restoredHistory.getByLabel('Local version name').fill(restoredLabel);
  await restoredHistory.getByRole('button',{name:'Save Version',exact:true}).click();
  await expect(restoredHistory.getByLabel('Saved local versions')).toContainText(restoredLabel);
  const restored=(await savedVersions(page)).find(version=>version.label===restoredLabel);
  expect(restored?.source).toBe(raw);
  expect(restored?.draft).toEqual(saved?.draft);
  await restoredHistory.getByRole('button',{name:'Close Versions',exact:true}).click();
  await analyzeComplete(page,raw);
  const result=await createAndDownload(page,info,ordered);
  expect(observed.downloads).toEqual(['customized_demo_firewall','customized_demo_firewall.conf']);
  await attachEvidence(info,observed,{order:'leef-then-syslog',savedVersionSha256:saved?.sha256,
    restoredVersionSha256:restored?.sha256,...result});
});

test('duplicate-key LEEF remains partial with valid Syslog and cannot reach a false-complete download',async({page},info)=>{
  test.setTimeout(90000);
  const observed=watchBrowser(page,info);
  const raw=fixture.syslog+'\n'+fixture.malformedLeef;
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toBeVisible({timeout:30000});
  const problem=page.getByLabel('Parse problem inspector');
  await expect(problem).toBeVisible();
  // Source recovery and compiler readiness are separate checks. If multiple
  // events need a parser-rule review, select the malformed original explicitly.
  const chooseProblem=problem.getByLabel('Problem event');
  if(await chooseProblem.count()){
    const malformed=chooseProblem.locator('option').filter({hasText:/^Event 2 ·/});
    await expect(malformed).toHaveCount(1);
    const value=await malformed.getAttribute('value');
    if(value===null)throw new Error('The malformed event review option has no value');
    await chooseProblem.selectOption(value);
  }
  await expect(problem).toContainText('Original event 2');
  await expect.poll(()=>problem.locator('pre').first().textContent()).toBe(fixture.malformedLeef);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  await page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button',{name:/Create Parser/}).click();
  await expect(page.getByLabel('Add Logs stage')).toBeVisible();
  await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
  await expect(page.getByLabel('Create Parser Files')).toHaveCount(0);
  await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
  await expect(summary).not.toContainText('2 of 2 log events structurally parsed');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  expect(observed.downloads).toEqual([]);
  expect(observed.apiRequests.filter(request=>request.method==='POST'&&
    request.path.startsWith('/api/v1/parser-pairs/'))).toEqual([]);
  await page.screenshot({path:info.outputPath('malformed-leef-remains-in-review.png'),fullPage:true});
  await attachEvidence(info,observed,{order:'syslog-then-malformed-leef',raw,sourceSha256:sha256(raw),
    summary:await summary.textContent(),reviewBlocked:true});
});
