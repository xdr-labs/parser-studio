import {test,expect,type Page} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {createDraft} from '../src/model';
import {toBackendProject} from '../src/guided/backendAdapter';
import {sampleProject} from '../backend/test/fixture';

const SHA=/^[a-f0-9]{64}$/;
const sha=(data:string|Uint8Array)=>createHash('sha256').update(data).digest('hex');
const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

async function analyzeAndReview(page:Page){
  // Current two-path product exposes one analysis action, not a separate
  // advanced-mode shortcut. All original parser/backend assertions stay in
  // the calling test; this helper only performs the actual novice workflow.
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
}

async function enterCreateParser(page:Page){
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
}
async function returnToReviewFields(page:Page){
  await page.getByLabel('Create Parser stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Back to Review Fields'}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
}

async function verifyGeneratedDraftPair(
  page:Page,responsePromise:Promise<import('@playwright/test').Response>,
){
  const response=await responsePromise;
  expect(response.status()).toBe(200);
  const pair=await response.json() as {
    manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean;fileHashes:Record<string,string>};
    files:Array<{name:string;sha256:string;content:string}>;
  };
  expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
  expect(pair.files).toHaveLength(2);
  expect(pair.files.filter(file=>file.name.endsWith('.conf'))).toHaveLength(1);
  for(const file of pair.files){
    expect(sha(file.content)).toBe(file.sha256);
    expect(pair.manifest.fileHashes[file.name]).toBe(file.sha256);
  }
  await expect(page.getByLabel('Generated parser files'))
    .toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
  // Removed on purpose: parser-building step editor/review is no longer
  // available to bypass the ordinary DRAFT capability and sample checks.
  await expect(page.getByLabel('Parser-building steps review')).toHaveCount(0);
  return pair;
}

test.describe('actual Chromium UI ↔ exact same-HEAD authoring backend; target APIs isolated',()=>{
  test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1',
    'Real integration requires an exact backend HEAD checkout and localhost isolation.');

  test('same-head backend cannot export unsupported Ruby2.4 Regex or Syslog Regex',async({request})=>{
    const caps=await request.get('/api/v1/parser-pairs/capabilities');
    expect(caps.status()).toBe(200);
    const capability=await caps.json();
    expect(capability.downloads.targetRuntimeProfile).toMatchObject({
      profile:'stellar70-observed-ruby24',ruby:'2.4.9',
      regexPreviewSupported:true,regexExportSupported:false,
      targetImportVerified:false,
    });
    for(const extraction of [
      {format:'regex' as const,pattern:'^(?<action>ALLOW)$'},
      {format:'syslog_rfc5424' as const,syslogBodyFormat:'regex' as const,
        pattern:'^(?<action>ALLOW)$'},
    ]){
      const project=sampleProject();
      project.extraction=extraction;
      const checked=await request.post('/api/v1/parser-pairs/validate',{data:project});
      expect(checked.status()).toBe(200);
      expect((await checked.json()).targetExportSupported).toBe(false);
      const refused=await request.post('/api/v1/parser-pairs/generate',{data:project});
      expect(refused.status()).toBe(422);
      expect((await refused.json()).error).toBe('TARGET_RUNTIME_REGEX_UNSUPPORTED');
    }
  });

  test('same-head public backend refuses legacy name-only mapping API',async({request})=>{
    const response=await request.get('/api/v1/parser-pairs/capabilities');
    expect(response.status()).toBe(200);
    const cap=await response.json();
    expect(cap.authoring.deterministicNameOnlyMappingHttpAvailable).toBe(false);

    // Historical http.ts implements optional diagnostics, but the shipping
    // mainline authoring server deliberately does not expose this endpoint.
    // Do not expand a dead-code finding into a new public attack surface.
    for(const payload of [
      {fieldNames:['source-port','destination-port','src_ip'],
        existingDestinations:['srcip.vendor']},
      {fieldNames:['translated.source-port']},
      {fieldNames:['x.__proto__']},
    ]){
      const blocked=await request.post('/api/v1/parser-pairs/mapping-suggestions',{
        data:payload,
      });
      expect(blocked.status()).toBe(404);
      expect(await blocked.json()).toEqual({
        error:'AUTHORING_ONLY_ROUTE_NOT_AVAILABLE',
      });
    }
  });

  test('real same-origin schema, capabilities and independent default-deny authorizations',async({request})=>{
    const schema=await request.get('/api/v1/parser-pairs/schema');
    expect(schema.status()).toBe(200);
    const body=await schema.json();
    expect(body.title).toContain('ParserProject v0.1');
    expect(body.properties.extraction.properties.format.enum).toContain('json');

    const capability=await request.get('/api/v1/parser-pairs/capabilities');
    expect(capability.status()).toBe(200);
    const cap=await capability.json();
    expect(cap.downloads.exactArtifactRevision).toBe(true);
    // Old pinned compiler profiles offered a separately injected revision
    // capability. The current browser-only Local Versions path does not.
    // Neither configuration authorizes an owned HTTP revision read by default.
    if(cap.downloads.ownedOfflineRevisionHttpAvailableWhenInjected===true)
      expect(cap.downloads.revisionRestorePreviewNeverWritesTarget).toBe(true);
    else expect(cap.downloads.ownedOfflineRevisionHttpAvailableWhenInjected).toBeUndefined();
    expect(cap.authoring.multiline).toBe(false);
    expect(cap.verification.engineVerified).toBe(false);
    expect(cap.verification.targetImportVerified).toBe(false);
    expect(cap.verification.nativeCapabilityManifestEnabledByDefault).not.toBe(true);

    const guarded=[
      '/api/v1/parser-pairs/native-capability-manifest',
      '/api/v1/parser-pairs/revisions/list?projectId=draft-demo_firewall',
      '/api/v1/parser-pairs/target/apply/status?artifactRevisionId='+'a'.repeat(64),
      '/api/v1/test-lab/sessions/evidence-summary?runId=test_run_'+'b'.repeat(32),
    ];
    for(const path of guarded){
      const denied=await request.get(path);
      // A configured-but-disabled endpoint returns 403. A removed backend
      // feature has no route (404). Neither may authorize private reads.
      expect([403,404],path).toContain(denied.status());
      const result=await denied.text();
      expect(result).not.toContain('apiKey');
      expect(result).not.toContain('PRIVATE_CUSTOMER_VALUE');
      if(denied.status()===403)
        expect(result).toMatch(/DENIED|DISABLED/);
    }
  });

  test('same synthetic sample: Auto Parser -> live backend validate/generate -> ZIP and SHA downloads',async({page})=>{
    const calls:string[]=[];
    page.on('request',req=>{
      const path=new URL(req.url()).pathname;
      if(req.method()==='POST'&&path.startsWith('/api/v1/parser-pairs/')){
        calls.push(path.split('/').at(-1)!);
        for(const value of ['198.51.100.10','203.0.113.5'])
          expect(req.postData()??'').not.toContain(value);
      }
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('2/2 events analyzed locally');
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await enterCreateParser(page);
    const generation=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    const raw=await generation;
    expect(raw.status()).toBe(200);
    const pair=await raw.json();
    expect(pair.manifest).toMatchObject({
      status:'DRAFT',engineVerified:false,targetImportVerified:false,
      projectId:'draft-demo_firewall',projectRevision:1,
    });
    expect(pair.files).toHaveLength(2);
    for(const f of pair.files){
      expect(f.sha256).toMatch(SHA);
      expect(sha(f.content)).toBe(f.sha256);
      expect(pair.manifest.fileHashes[f.name]).toBe(f.sha256);
      const download=page.waitForEvent('download');
      await page.getByLabel('Generated parser files')
        .getByRole('button',{name:f.name,exact:true}).click();
      expect(sha(await readFile(await (await download).path()))).toBe(f.sha256);
    }
    expect(pair.files[0].content).toContain('port 6801');
    expect(pair.files[1].content).toContain('STELLAR_PARSE_BEGIN');
    const packageResponse=page.waitForResponse(r=>
      r.url().endsWith('/parser-pairs/package')&&r.request().method()==='POST');
    const packageDownload=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download Parser Package'}).click();
    const zip=await packageResponse;
    expect(zip.status()).toBe(200);
    const bytes=await readFile(await (await packageDownload).path());
    expect(bytes.subarray(0,4).toString('hex')).toBe('504b0304');
    expect(sha(bytes)).toBe(zip.headers()['x-parser-zip-sha256']);
    // Analyze Logs may validate the same draft again during final generation.
    // Every call must still be an allowed compiler operation; package is last.
    expect(calls.at(-1)).toBe('package');
    expect(calls.every(action=>['validate','generate','package'].includes(action))).toBe(true);
    expect(calls.filter(action=>action==='validate').length).toBeGreaterThanOrEqual(1);
    expect(calls.filter(action=>action==='generate').length).toBeGreaterThanOrEqual(1);
    await returnToReviewFields(page);
    await page.getByRole('button',{name:'Back to Logs'}).click();
    await page.getByLabel('Auto Parser raw logs').fill(sample+'\n{"action":"deny"}');
    await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
  });

  test('invalid projects, malformed HTTP and foreign owner reads cannot fake an artifact PASS',async({request})=>{
    const draft=createDraft();draft.format='json';
    const project=toBackendProject(draft);
    expect(project.ok).toBe(true);
    if(!project.ok)return;
    const bad={...project.project,slug:'../../bad'};
    const invalid=await request.post('/api/v1/parser-pairs/validate',{data:bad});
    expect(invalid.status()).toBe(422);
    expect((await invalid.json()).ok).toBe(false);
    const blocked=await request.post('/api/v1/parser-pairs/generate',{data:bad});
    expect(blocked.status()).toBe(422);
    expect((await blocked.json()).files).toBeUndefined();
    const wrongType=await request.post('/api/v1/parser-pairs/generate',{
      data:'raw_customer_log=SECRET',headers:{'Content-Type':'text/plain'},
    });
    expect(wrongType.status()).toBe(415);
    const foreign=await request.get('/api/v1/parser-pairs/revisions/download?artifactRevisionId='+'c'.repeat(64));
    // Current authoring can omit the old server-side revision route (404);
    // the separately pinned historical backend may deny it (403).
    expect([403,404]).toContain(foreign.status());
    expect(await foreign.text()).not.toContain('PRIVATE_CUSTOMER_VALUE');
  });

  test('tampered real backend generated SHA is rejected in Auto Parser without deployment',async({page})=>{
    let attempts=0;
    await page.route('**/api/v1/parser-pairs/generate',async route=>{
      const original=await route.fetch();
      expect(original.status()).toBe(200);
      const pair=await original.json();
      attempts++;
      pair.files[0].sha256='0'.repeat(64);
      await route.fulfill({response:original,contentType:'application/json',body:JSON.stringify(pair)});
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
 await analyzeAndReview(page);
    await enterCreateParser(page);
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Auto Parser test evidence'))
      .toContainText('Parser creation stopped');
    await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
    expect(attempts).toBe(1);
  });

  test('AP2 novice flow compiles a real backend DRAFT pair without choosing parser syntax',async({page})=>{
    const actions:string[]=[];
    const sample=[
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
    ].join('\n');
    page.on('request',request=>{
      const path=new URL(request.url()).pathname;
      if(request.method()==='POST'&&path.startsWith('/api/v1/parser-pairs/')){
        actions.push(path.split('/').at(-1)!);
        const body=request.postData()||'';
        expect(body).not.toContain('198.51.100.10');
        expect(body).not.toContain('203.0.113.5');
        expect(body).not.toContain('apiKey');
      }
    });
    await page.goto('/');
    await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
    await page.getByLabel('Auto Parser raw logs').fill(sample);
    await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"src_ip\"');
    await enterCreateParser(page);
    await expect(page.getByLabel('Create Parser stage')).toBeVisible();
    const generated=page.waitForResponse(r=>r.url().endsWith('/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    const pair=await verifyGeneratedDraftPair(page,generated);
    const ruby=pair.files.find(file=>!file.name.endsWith('.conf'));
    expect(ruby?.content).toContain('STELLAR_PARSE_BEGIN');
    expect(ruby?.content).not.toContain('198.51.100.10');
    expect(ruby?.content).not.toContain('203.0.113.5');
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    await expect(page.getByRole('button',{name:'Review Staged Recipe'})).toHaveCount(0);
    await expect(page.getByRole('button',{name:'Run private parser-file compatibility check'})).toHaveCount(0);
    for(const filename of ['customized_demo_firewall.conf','customized_demo_firewall']){
      const download=page.waitForEvent('download');
      await page.getByLabel('Generated parser files').getByRole('button',{name:filename,exact:true}).click();
      const result=await download;
      expect(result.suggestedFilename()).toBe(filename);
      const bytes=await readFile(await result.path());
      expect(bytes.byteLength).toBeGreaterThan(0);
    }
    expect(actions).toContain('validate');
    expect(actions).toContain('generate');
    expect(actions.every(action=>['validate','generate'].includes(action))).toBe(true);
    await returnToReviewFields(page);
    await page.getByRole('button',{name:'Back to Logs'}).click();
    await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(sample);
    await page.getByLabel('Auto Parser raw logs').fill(sample+'\n{"action":"allow","src_ip":"192.0.2.8","dst_port":80}');
    // Locked steps remain clickable so beginners can learn what is missing;
    // they cannot bypass review or expose stale generated output.
    const locked=page.getByRole('navigation',{name:'Auto Parser steps'})
      .getByRole('button',{name:/Create Parser — locked until/});
    await expect(locked).toHaveClass(/locked/);
    await expect(page.getByLabel('Create Parser stage')).toHaveCount(0);
    await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
  });


  test('mixed RFC5424 wrapped CEF and LEEF + standalone JSON compile against the exact Native-qualified backend',async({page})=>{
    const sample=[
      '{"src_ip":"192.0.2.10","dst_port":443,"action":"deny"}',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^dstPort=80^act=allow',
    ].join('\n');
    const actualBodies:string[]=[];
    page.on('request',req=>{
      const p=new URL(req.url()).pathname;
      if(req.method()==='POST'&&p.startsWith('/api/v1/parser-pairs/')){
        const body=req.postData()??'';
        actualBodies.push(body);
        for(const secret of ['192.0.2.10','192.0.2.11','203.0.113.8'])
          expect(body).not.toContain(secret);
      }
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('3/3 events analyzed locally');
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await page.getByLabel('Auto Parser review event').selectOption({index:1});
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"src\"');
    await enterCreateParser(page);
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    const pairCheck=await verifyGeneratedDraftPair(page,generated);
    const rubyCheck=pairCheck.files.find(file=>!file.name.endsWith('.conf'));
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_BEGIN');
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_END');
    await expect(page.getByRole('button',{name:'Review Staged Recipe'})).toHaveCount(0);
    expect(actualBodies.length).toBeGreaterThanOrEqual(4);
  });

  test('P0 strict mixed RFC3164 TAG KV plus standalone JSON/KV compiles exact pinned backend without timestamp guessing',async({page})=>{
    const source=[
      '{"src_ip":"192.0.2.10","action":"deny"}',
      'src_ip=198.51.100.8 action=allow',
      '<34>Oct  9 14:15:16 edge fw[122]: src_ip=192.0.2.17 action=deny',
    ].join('\n');
    const payloads:string[]=[];
    page.on('request',r=>{
      if(r.method()==='POST'&&new URL(r.url()).pathname.startsWith('/api/v1/parser-pairs/')){
        const payload=r.postData()??'';
        payloads.push(payload);
        for(const sensitive of ['192.0.2.10','198.51.100.8','192.0.2.17'])
          expect(payload).not.toContain(sensitive);
      }
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(source);
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('3/3 events analyzed locally');
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await page.getByLabel('Auto Parser review event').selectOption({index:2});
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"src_ip\"');
    await expect(page.getByLabel('Review Fields stage')).toContainText("This log's header does not include a year or timezone");
    await enterCreateParser(page);
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    const pairCheck=await verifyGeneratedDraftPair(page,generated);
    const rubyCheck=pairCheck.files.find(file=>!file.name.endsWith('.conf'));
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_BEGIN');
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_END');
    await expect(page.getByRole('button',{name:'Review Staged Recipe'})).toHaveCount(0);
    const reviewedRequests=payloads
      .map(body=>JSON.parse(body) as {recipe?:{stages?:Array<{op:string;families?:string[]}>}})
      .filter(body=>body.recipe?.stages?.length);
    expect(reviewedRequests.length).toBeGreaterThanOrEqual(2);
    expect(reviewedRequests[0]?.recipe?.stages?.find(stage=>
      stage.op==='dispatch_family')?.families).toEqual(['json','kv','rfc3164_kv']);
    expect(payloads.length).toBeGreaterThanOrEqual(4);
  });

  test('P0 strict RFC5424 JSON/KV wrapped + standalone JSON/KV mixed compiles exact Native-qualified backend',async({page})=>{
    const source=[
      '{"src_ip":"192.0.2.10","action":"deny"}',
      'src_ip=198.51.100.8 action=allow',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - {"src_ip":"192.0.2.19","action":"deny"}',
      '<165>1 2026-10-12T01:02:03Z edge fw 122 ID - src_ip=203.0.113.4 action=allow',
    ].join('\n');
    const payloads:string[]=[];
    page.on('request',r=>{
      if(r.method()==='POST'&&new URL(r.url()).pathname.startsWith('/api/v1/parser-pairs/')){
        const json=r.postData()??'';
        payloads.push(json);
        for(const raw of ['192.0.2.10','198.51.100.8','192.0.2.19','203.0.113.4'])
          expect(json).not.toContain(raw);
      }
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(source);
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('4/4 events analyzed locally');
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await page.getByLabel('Auto Parser review event').selectOption({index:2});
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"src_ip\"');
    await enterCreateParser(page);
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    const pairCheck=await verifyGeneratedDraftPair(page,generated);
    const rubyCheck=pairCheck.files.find(file=>!file.name.endsWith('.conf'));
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_BEGIN');
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_END');
    await expect(page.getByRole('button',{name:'Review Staged Recipe'})).toHaveCount(0);
    const actual=payloads.map(body=>JSON.parse(body) as {
      recipe?:{stages?:Array<{op:string;families?:string[]}>}}).filter(x=>x.recipe?.stages?.length);
    expect(actual.length).toBeGreaterThanOrEqual(2);
    expect(actual[0]?.recipe?.stages?.find(x=>x.op==='dispatch_family')?.families)
      .toEqual(['json','kv','rfc5424_json','rfc5424_kv']);
    expect(payloads.length).toBeGreaterThanOrEqual(4);
  });

  test('P0 strict RFC3164 wrapped CEF/LEEF + standalone JSON/KV compiles actual Native-qualified backend with yearless policy',async({page})=>{
    const source=[
      '{"src_ip":"192.0.2.10","action":"deny"}',
      'src_ip=198.51.100.8 action=allow',
      '<165>Oct 12 02:03:04 edge fw[122]: CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.11 dpt=443 act=deny',
      '<165>Nov 12 02:03:04 edge fw[122]: LEEF:1.0|Synthetic|FW|1|501|src=203.0.113.8\tdstPort=80\tact=allow',
    ].join('\n');
    const bodies:string[]=[];
    page.on('request',req=>{
      if(req.method()==='POST'&&new URL(req.url()).pathname.startsWith('/api/v1/parser-pairs/')){
        const text=req.postData()??'';
        bodies.push(text);
        for(const secret of ['192.0.2.10','198.51.100.8','192.0.2.11','203.0.113.8'])
          expect(text).not.toContain(secret);
      }
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(source);
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('4/4 events analyzed locally');
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await page.getByLabel('Auto Parser review event').selectOption({index:2});
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"src\"');
    await expect(page.getByLabel('Review Fields stage'))
      .toContainText("This log's header does not include a year or timezone");
    await enterCreateParser(page);
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    const pairCheck=await verifyGeneratedDraftPair(page,generated);
    const rubyCheck=pairCheck.files.find(file=>!file.name.endsWith('.conf'));
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_BEGIN');
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_END');
    await expect(page.getByRole('button',{name:'Review Staged Recipe'})).toHaveCount(0);
    const requests=bodies.map(body=>JSON.parse(body) as {
      recipe?:{stages?:Array<{op:string;families?:string[]}>}}).filter(x=>x.recipe?.stages?.length);
    expect(requests.length).toBeGreaterThanOrEqual(2);
    expect(requests[0]?.recipe?.stages?.find(x=>x.op==='dispatch_family')?.families)
      .toEqual(['json','kv','rfc3164_cef','rfc3164_leef']);
    expect(bodies.length).toBeGreaterThanOrEqual(4);
  });

  test('P0 novice confirms strict LF LF framed TCP Java exceptions and generates exact backend DRAFT files',async({page,request})=>{
    const sample=[
      'java.lang.IllegalStateException: Synthetic failure',
      '\tat com.example.Service.run(Service.java:42)',
      '\tat com.example.App.main(App.java:5)',
      'Caused by: java.io.IOException: simulated',
      '\tat com.example.Store.read(Store.java:12)',
      '\t... 2 more',
      '',
      'java.lang.RuntimeException: another failure',
      '\tat demo.Worker.go(Worker.java:9)',
    ].join('\n');
    const bodyLog:string[]=[];
    page.on('request',req=>{
      if(req.method()==='POST'&&new URL(req.url()).pathname.startsWith('/api/v1/parser-pairs/')){
        const body=req.postData()??'';
        bodyLog.push(body);
        for(const secret of ['Synthetic failure','Service.java:42','Store.java:12','another failure'])
          expect(body).not.toContain(secret);
      }
    });
    const unsupported=await request.get('/api/v1/parser-pairs/capabilities');
    expect(unsupported.status()).toBe(200);
    const server=await unsupported.json();
    expect(server.authoring.javaBlankLineTcpFraming).toBe(true);
    expect(server.authoring.javaStackTraceGrammar).toBe('EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1');
    expect(server.authoring.multiline).toBe(false);
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
    await expect(page.getByLabel('Explicit Java TCP framing confirmation')).toBeVisible();
    await page.getByRole('button',{name:'I Confirm TCP Java Events Are Separated by LF LF'}).click();
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('2/2 events analyzed locally');
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"exception_class\"');
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"frame_count\"');
    await enterCreateParser(page);
    const generated=page.waitForResponse(r=>
      r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    const pairCheck=await verifyGeneratedDraftPair(page,generated);
    const rubyCheck=pairCheck.files.find(file=>!file.name.endsWith('.conf'));
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_BEGIN');
    expect(rubyCheck?.content).toContain('STELLAR_PARSE_END');
    await expect(page.getByRole('button',{name:'Review Staged Recipe'})).toHaveCount(0);
    const req=bodyLog.map(x=>JSON.parse(x) as {recipe?:{
      sourceFormat:string;stages:Array<{op:string;boundary?:string}>};
      receiver?:{tcpFraming:string;protocols:string[]}}).filter(x=>x.recipe?.stages?.length);
    expect(req.length).toBeGreaterThanOrEqual(2);
    expect(req[0]?.recipe?.sourceFormat).toBe('java_stacktrace');
    expect(req[0]?.recipe?.stages.slice(0,2)).toEqual([
      {op:'split_event',boundary:'blank-line'},{op:'parse_java_stacktrace'}]);
    const authoring=bodyLog.map(x=>JSON.parse(x) as {
      receiver?:{tcpFraming:string;protocols:string[]}})
      .find(x=>x.receiver?.tcpFraming==='blank_line_java');
    expect(authoring?.receiver?.protocols).toEqual(['tcp']);
    expect(bodyLog.length).toBeGreaterThanOrEqual(4);
  });

  test('ChatGPT Assisted: visible source warning -> manual original-log prompt -> reviewed exact DRAFT pair',async({page})=>{
    const source=[
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
    ].join('\n');
    const posts:string[]=[];
    page.on('request',req=>{
      const path=new URL(req.url()).pathname;
      if(req.method()==='POST'&&path.startsWith('/api/v1/parser-pairs/')){
        const body=req.postData()??'';
        posts.push(path);
        // Original customer logs belong only in the manually copied prompt.
        expect(body).not.toContain('198.51.100.10');
        expect(body).not.toContain('203.0.113.5');
      }
    });
    await page.goto('/?workspace=chatgpt');
    await page.getByLabel('ChatGPT local sample logs').fill(source);
    await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
    await expect(page.getByRole('alert')
      .filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
    const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
    await expect(prepare).toBeEnabled({timeout:20000});
    await prepare.click();
    const textarea=page.getByLabel('ChatGPT copyable prompt');
    await expect(textarea).toBeVisible({timeout:20000});
    const prompt=await textarea.inputValue();
    expect(prompt).toMatch(/----- BEGIN ORIGINAL LOG SOURCE \[[a-f0-9]{20}\] -----/);
    expect(prompt).toContain(source);
    expect(prompt).toMatch(/----- END ORIGINAL LOG SOURCE \[[a-f0-9]{20}\] -----/);
    const prefix='----- BEGIN VALIDATED BASELINE RECIPE -----\n';
    const suffix='\n----- END VALIDATED BASELINE RECIPE -----';
    const start=prompt.indexOf(prefix),end=prompt.indexOf(suffix,start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const recipe=JSON.parse(prompt.slice(start+prefix.length,end));
    expect(recipe.compilerMode).toBe('REVIEW_ONLY');
    expect(recipe.nativeVerified).toBe(false);
    await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe));
    await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
    await expect(page.getByLabel('ChatGPT result ready for testing'))
      .toContainText('ChatGPT result accepted for testing');
    const compiled=page.waitForResponse(r=>
      r.url().includes('/recipe/v0.2/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
    expect((await compiled).status()).toBe(200);
    const created=page.getByLabel('ChatGPT created parser files');
    await expect(created).toContainText('Parser files created successfully');
    await expect(created.locator('details'))
      .toContainText('Two parser files passed integrity checks before download.');
    await expect(created.getByRole('button',{name:/Download/})).toHaveCount(2);
    expect(posts.filter(path=>path.endsWith('/generate')).length).toBeGreaterThanOrEqual(2);
  });

  test('generated Auto Parser results retain only local versions, never a target or sensor operation',async({page})=>{
    const source=[
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
    ].join('\n');
    const writes:string[]=[];
    page.on('request',req=>{
      if(req.method()==='POST')writes.push(new URL(req.url()).pathname);
    });
    await page.goto('/');
    await expect(page.getByLabel('Authorized test and Interflow verification')).toHaveCount(0);
    await page.getByLabel('Auto Parser raw logs').fill(source);
 await analyzeAndReview(page);
    await enterCreateParser(page);
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    // Current owner-approved downloadable-parser scope deliberately excludes
    // remote Test Lab, backend revision history, sensor and Interflow controls.
    await expect(page.getByLabel('Offline parser revision history')).toHaveCount(0);
    await expect(page.getByLabel('Authorized test and Interflow verification')).toHaveCount(0);
    await page.getByRole('button',{name:'Local Versions',exact:true}).click();
    const local=page.getByLabel('Local Versions workspace');
    await expect(local).toBeVisible();
    await local.getByLabel('Local version name').fill('Compiled draft checkpoint');
    await local.getByRole('button',{name:'Save Version'}).click();
    await expect(local.getByLabel('Saved local versions')).toContainText('Compiled draft checkpoint');
    expect(writes.some(path=>path.includes('/sessions/start')||
      path.includes('/interflow/search')||path.includes('/target/apply'))).toBe(false);
  });

  test('Auto Parser mixed CSV compiles reviewed DRAFT Ruby and CONF without replay or source egress',async({page})=>{
    const source=[
      '{"src_ip":"192.0.2.10","action":"deny","dst_port":443}',
      'src_ip=198.51.100.8 action=allow dst_port=443',
      '192.0.2.17;deny;22',
      '"203.0.113.19";allow;8443',
    ].join('\n');
    const outgoing:Array<{path:string;body:string}>=[];
    page.on('request',req=>{
      const path=new URL(req.url()).pathname;
      if(req.method()==='POST'&&path.startsWith('/api/v1/parser-pairs/')){
        const body=req.postData()??'';
        outgoing.push({path,body});
        for(const address of ['192.0.2.10','198.51.100.8',
                              '192.0.2.17','203.0.113.19'])
          expect(body).not.toContain(address);
      }
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(source);
    await expect(page.getByLabel('Automatic event accounting'))
      .toContainText('4/4 events analyzed locally');
    await expect(page.getByLabel('Review CSV column names')).toBeVisible();
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
    await expect(review).toBeDisabled();
    await page.getByLabel('Reviewed CSV column names').fill('src_ip,action,dst_port');
    await page.getByLabel('Reviewed CSV data separator').selectOption(';');
    await expect(review).toBeDisabled();
    await page.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(review).toBeEnabled({timeout:20000});
    await review.click();
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await expect(page.getByLabel('Browser-only event inspector')).toContainText('\"src_ip\"');
    await enterCreateParser(page);
    const pairResponse=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    const generated=await pairResponse;
    expect(generated.status()).toBe(200);
    const pair=await generated.json();
    expect(pair.files).toHaveLength(2);
    expect(pair.manifest).toMatchObject({
      status:'DRAFT',engineVerified:false,targetImportVerified:false,
    });
    for(const f of pair.files)expect(sha(f.content)).toBe(f.sha256);
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    // The removed advanced replay tool must not be surfaced as an alternate
    // parser/sensor path. The generated DRAFT remains downloadable only.
    await expect(page.getByLabel('Local synthetic replay preview')).toBeHidden();
    await expect(page.getByLabel('Local synthetic replay output')).toHaveCount(0);
    const projectPayloads=outgoing.filter(x=>x.path.endsWith('/generate'))
      .map(x=>JSON.parse(x.body) as {
        extraction?:{format:string;mixedFormats?:string[];
          csvColumns?:string[];csvDelimiter?:string};
      }).filter(x=>x.extraction?.format==='mixed');
    expect(projectPayloads.length).toBeGreaterThanOrEqual(1);
    expect(projectPayloads[0]!.extraction).toMatchObject({
      format:'mixed',mixedFormats:['csv','json','kv'],
      csvColumns:['src_ip','action','dst_port'],csvDelimiter:';',
    });
    expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
    await expect(page.getByLabel('Parser-building steps review')).toHaveCount(0);
    expect(pair.files.some((file:{content:string})=>file.content.includes('STELLAR_PARSE_BEGIN'))).toBe(true);
    const requests=outgoing.map(x=>JSON.parse(x.body) as {
      recipe?:{stages?:Array<{op:string;families?:string[]}>}
    }).filter(x=>x.recipe?.stages?.length);
    expect(requests.length).toBeGreaterThanOrEqual(2);
    expect(requests[0]!.recipe!.stages!.find(s=>s.op==='dispatch_family')?.families)
      .toEqual(['csv','json','kv']);
    expect(outgoing.some(x=>x.path.includes('/target/apply')||
      x.path.includes('/sessions/start')||x.path.includes('/interflow'))).toBe(false);
  });

  test('migrated legacy ZIP: a tampered real backend SHA blocks Auto Parser ZIP download without losing DRAFT pair',async({page})=>{
    let archiveRequests=0;
    const downloaded:string[]=[];
    page.on('download',entry=>downloaded.push(entry.suggestedFilename()));
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
 await analyzeAndReview(page);
    await enterCreateParser(page);
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    await page.route('**/api/v1/parser-pairs/package',async route=>{
      archiveRequests++;
      const requestBody=route.request().postData()??'';
      expect(requestBody).not.toContain('198.51.100.10');
      expect(requestBody).not.toContain('203.0.113.5');
      expect(requestBody).not.toContain('apiKey');
      const real=await route.fetch();
      expect(real.status()).toBe(200);
      const original=real.headers();
      expect(original['x-parser-zip-sha256']).toMatch(SHA);
      await route.fulfill({response:real,headers:{
        ...original,'x-parser-zip-sha256':'0'.repeat(64),
      }});
    });
    await page.getByRole('button',{name:'Download Parser Package'}).click();
    await expect(page.getByRole('alert')).toContainText('ZIP verification failed');
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    await expect(page.getByLabel('Generated parser files'))
      .not.toContainText('ZIP SHA-256:');
    expect(downloaded).toEqual([]);
    expect(archiveRequests).toBe(1);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });

  test('migrated legacy ZIP: missing package capability fails closed before any backend ZIP POST',async({page})=>{
    let archiveRequests=0;
    await page.route('**/api/v1/parser-pairs/package',route=>{
      archiveRequests++;return route.abort();
    });
    await page.route('**/api/v1/parser-pairs/capabilities',async route=>{
      const original=await route.fetch();
      expect(original.status()).toBe(200);
      const capabilities=await original.json() as Record<string,unknown>;
      expect(capabilities.downloads).toBeDefined();
      delete capabilities.downloads;
      await route.fulfill({response:original,contentType:'application/json',
        body:JSON.stringify(capabilities)});
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
 await analyzeAndReview(page);
    await enterCreateParser(page);
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    await page.getByRole('button',{name:'Download Parser Package'}).click();
    await expect(page.getByRole('alert')).toContainText('ZIP verification failed');
    expect(archiveRequests).toBe(0);
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
  });


  test('migrated legacy field safety: invalid in-place Auto mapping disables generation and can be repaired without Wizard',async({page})=>{
    const operations:string[]=[];
    page.on('request',req=>{
      if(req.method()==='POST'&&new URL(req.url()).pathname.startsWith('/api/v1/parser-pairs/'))
        operations.push(new URL(req.url()).pathname);
    });
    await page.goto('/?workspace=guided');
    await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
    await expect(page.getByRole('main',{name:'No-code Parser Guided Builder'})).toHaveCount(0);
    await page.getByLabel('Auto Parser raw logs').fill(sample);
 await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
    const map=page.getByLabel('Map Fields stage');
    const target=map.getByLabel('Stellar field 0');
    const original=await target.inputValue();
    await target.fill('invalid..target');
    await map.getByRole('button',{name:'Create Parser'}).click();
    await expect(page.getByLabel('Create Parser stage')).toBeVisible();
    await expect(page.getByRole('button',{name:'Create Parser Files'}))
      .toBeDisabled();
    await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
    expect(operations).toEqual([]);
    await page.getByLabel('Create Parser stage').getByRole('button',{name:'Map Fields'}).click();
    await page.getByLabel('Map Fields stage').getByLabel('Stellar field 0').fill(original);
    await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
    await expect(page.getByRole('button',{name:'Create Parser Files'}))
      .toBeEnabled();
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    expect(operations.filter(path=>path.endsWith('/generate'))).toEqual([
      '/api/v1/parser-pairs/generate',
      '/api/v1/parser-pairs/recipe/v0.2/generate',
    ]);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });


  test('migrated legacy mapping safety: overlapping normalized destinations cannot reach backend until repaired in place',async({page})=>{
    const outgoing:string[]=[];
    page.on('request',req=>{
      if(req.method()==='POST'&&new URL(req.url()).pathname.startsWith('/api/v1/parser-pairs/')){
        outgoing.push(new URL(req.url()).pathname);
        const request=req.postData()??'';
        expect(request).not.toContain('198.51.100.10');
        expect(request).not.toContain('203.0.113.5');
      }
    });
    await page.goto('/?workspace=expert');
    await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
    await page.getByLabel('Auto Parser raw logs').fill(sample);
 await analyzeAndReview(page);
    await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
    const map=page.getByLabel('Map Fields stage');
    const first=await map.getByLabel('Stellar field 0').inputValue();
    const second=map.getByLabel('Stellar field 1');
    const original=await second.inputValue();
    expect(first).not.toBe(original);
    await second.fill(first+'.child');
    await expect(map).toBeVisible();
    await expect(map.getByLabel('Field mapping checks')).toContainText('Two fields use the same Stellar destination');
    await expect(map.getByRole('button',{name:'Create Parser'})).toBeDisabled();
    await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
    expect(outgoing).toEqual([]);
    await map.getByLabel('Stellar field 1').fill(original);
    await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
    await expect(map.getByRole('button',{name:'Create Parser'})).toBeEnabled();
    await map.getByRole('button',{name:'Create Parser'}).click();
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    expect(outgoing.filter(path=>path.endsWith('/generate'))).toEqual([
      '/api/v1/parser-pairs/generate',
      '/api/v1/parser-pairs/recipe/v0.2/generate',
    ]);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });


  // OWNER-REMOVED: preserve previous authorization scenario for potential future scope,
  // but exclude it from current beta PASS; current negative boundaries live in evidence-recovery.spec.ts.
  test.skip('migrated owner-scoped history: real backend 403 and forged foreign revision metadata never leak into Auto result',async({page})=>{
    const unsafe:string[]=[];
    page.on('request',req=>{
      const path=new URL(req.url()).pathname;
      if(req.method()==='POST'&&
         (path.includes('/target/apply')||path.includes('/sessions/start')||
          path.includes('/interflow/')||path.includes('/revisions/register')))
        unsafe.push(path);
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
 await analyzeAndReview(page);
    await enterCreateParser(page);
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    const history=page.getByLabel('Offline parser revision history');
    await history.locator('summary').click();
    await expect(history.getByRole('button',{name:'Load My Revision List'}))
      .toBeVisible();
    await history.getByRole('button',{name:'Load My Revision List'}).click();
    await expect(history.getByRole('alert'))
      .toContainText('access denied or unavailable (HTTP 403)');
    await expect(history.getByLabel('Verified offline revision list')).toHaveCount(0);
    const secret='PRIVATE_LEGACY_REVISION_LOG_NEVER_ECHO';
    let foreignResponses=0;
    await page.route(/\/api\/v1\/parser-pairs\/revisions\/list\?/,route=>{
      foreignResponses++;
      const requested=new URL(route.request().url());
      expect(requested.searchParams.get('projectId')).toBe('draft-demo_firewall');
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({contract:'offline-revision-history.v0.1',
          persistent:false,deploymentPerformed:false,
          revisions:[{projectId:'unrelated-owner',rawLog:secret}]})});
    });
    await history.getByRole('button',{name:'Load My Revision List'}).click();
    await expect(history.getByRole('alert'))
      .toContainText('Unexpected offline revision response fields.');
    await expect(history.getByLabel('Verified offline revision list')).toHaveCount(0);
    await expect(history.getByRole('button',{name:'Re-download Verified ZIP'}))
      .toHaveCount(0);
    expect(await history.innerText()).not.toContain(secret);
    expect(foreignResponses).toBe(1);
    expect(unsafe).toEqual([]);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });




  // OWNER-REMOVED: preserve previous authorization scenario for potential future scope,
  // but exclude it from current beta PASS; current negative boundaries live in evidence-recovery.spec.ts.
  test.skip('migrated recovery: reload needs a manual owned run GET, and Stop survives both paths without Start',async({page})=>{
    const runId='test_run_'+'a'.repeat(32);
    const status={
      runId,state:'RUNNING',sentCount:2,nextSequence:2,replayMode:'single',
      sampleFamilyCount:1,ratePerSecond:1,maxEvents:100,
      leaseExpiresAt:new Date(Date.now()-60_000).toISOString(),
      lastSentAt:null,errorCode:null,parserLifecycleNotModified:true,
      realSensorVerified:false,runtimeParsingVerified:false,sensorIngestVerified:false,
    };
    const requests:string[]=[];
    await page.route('**/api/v1/test-lab/**',route=>{
      const uri=new URL(route.request().url());
      requests.push(uri.pathname);
      if(uri.pathname==='/api/v1/test-lab/sessions/status'){
        expect(route.request().method()).toBe('GET');
        expect(uri.searchParams.get('runId')).toBe(runId);
        expect(route.request().postData()).toBeNull();
        return route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify(status)});
      }
      if(uri.pathname==='/api/v1/test-lab/sessions/stop'){
        expect(route.request().method()).toBe('POST');
        expect(route.request().postDataJSON()).toEqual({runId});
        return route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify({...status,state:'STOPPED'})});
      }
      throw Error('No other Test Lab operations are allowed in the recovery test');
    });
    await page.goto('/?workspace=chatgpt');
    await page.reload();
    await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser',exact:true})).toBeVisible();
    await expect(page.getByLabel('Active Test Lab session indicator')).toHaveCount(0);
    expect(requests).toEqual([]);
    await page.getByRole('button',{name:'Tools & Diagnostics'}).click();
    const panel=page.getByLabel('Authorized Test Lab session recovery');
    await panel.locator('summary').click();
    const button=panel.getByRole('button',{name:'Look Up My Authorized Run'});
    await expect(button).toBeDisabled();
    await panel.getByLabel('Existing authorized Test Lab run ID').fill(runId);
    await expect(button).toBeEnabled();
    await button.click();
    await expect(page.getByLabel('Active Test Lab session indicator')).toContainText('RUNNING');
    await expect(panel.getByLabel('Recovered Test Lab result'))
      .toContainText('lease deadline has passed');
    await expect(page.getByLabel('Active Test Lab session indicator'))
      .toContainText('Sensor ingest NOT VERIFIED');
    await expect(button).toBeDisabled();
    await page.getByRole('complementary',{name:'Parser Studio navigation'})
      .getByRole('button',{name:'Auto Parser',exact:true}).click();
    await expect(page.getByLabel('Active Test Lab session indicator')).toBeVisible();
    await page.getByRole('complementary',{name:'Parser Studio navigation'})
      .getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
    await page.getByLabel('Active Test Lab session indicator')
      .getByRole('button',{name:'Stop Server Session Now'}).click();
    await expect(page.getByLabel('Active Test Lab session indicator')).toHaveCount(0);
    await expect(panel.getByLabel('Authorized terminal Test Lab session')).toContainText('STOPPED');
    expect(requests).toEqual([
      '/api/v1/test-lab/sessions/status',
      '/api/v1/test-lab/sessions/stop',
    ]);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });

  // OWNER-REMOVED: preserve previous authorization scenario for potential future scope,
  // but exclude it from current beta PASS; current negative boundaries live in evidence-recovery.spec.ts.
  test.skip('migrated owner denial: invalid, foreign, and forged run replies never restore a session or leak raw data',async({page})=>{
    const runId='test_run_'+'b'.repeat(32);
    // Exact pinned backend denies an unknown tenant session by default.
    const original=await page.request.get(
      '/api/v1/test-lab/sessions/status?runId='+runId);
    expect(original.status()).toBe(403);
    const calls:string[]=[];
    const valid={
      runId,state:'RUNNING',sentCount:0,nextSequence:0,replayMode:'single',
      sampleFamilyCount:1,ratePerSecond:1,maxEvents:100,
      leaseExpiresAt:new Date(Date.now()+900_000).toISOString(),lastSentAt:null,errorCode:null,
      parserLifecycleNotModified:true,realSensorVerified:false,
      runtimeParsingVerified:false,sensorIngestVerified:false,
    };
    let attempt=0;
    await page.route('**/api/v1/test-lab/**',route=>{
      const uri=new URL(route.request().url());
      calls.push(uri.pathname);
      if(uri.pathname!=='/api/v1/test-lab/sessions/status')
        throw Error('Unauthorized recovery attempted a target write');
      expect(route.request().method()).toBe('GET');
      expect(uri.searchParams.get('runId')).toBe(runId);
      if(++attempt===1)return route.fulfill({status:403,contentType:'application/json',
        body:JSON.stringify({error:'FOREIGN_OWNER',rawLog:'PRIVATE_RUN_VALUE_NEVER_ECHO'})});
      if(attempt===2)return route.fulfill({status:404,contentType:'application/json',
        body:JSON.stringify({error:'MISSING_OR_EXPIRED'})});
      if(attempt===3)return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({...valid,rawLog:'PRIVATE_RUN_VALUE_NEVER_ECHO',
          sensorIngestVerified:true})});
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({...valid,runId:'test_run_'+'f'.repeat(32)})});
    });
    await page.goto('/');
    await page.getByRole('button',{name:'Tools & Diagnostics'}).click();
    const panel=page.getByLabel('Authorized Test Lab session recovery');
    await panel.locator('summary').click();
    const input=panel.getByLabel('Existing authorized Test Lab run ID');
    const recover=panel.getByRole('button',{name:'Look Up My Authorized Run'});
    await input.fill('test_run_wrong');
    await expect(recover).toBeDisabled();
    expect(calls).toEqual([]);
    await input.fill(runId);
    for(let i=0;i<4;i++){
      await recover.click();
      await expect(panel.getByRole('alert'))
        .toContainText('Ownership was not verified');
      await expect(page.getByLabel('Active Test Lab session indicator')).toHaveCount(0);
      await expect(panel.getByLabel('Recovered Test Lab result')).toHaveCount(0);
      expect(await panel.innerText()).not.toContain('PRIVATE_RUN_VALUE_NEVER_ECHO');
    }
    expect(calls).toHaveLength(4);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });

  // OWNER-REMOVED: preserve previous authorization scenario for potential future scope,
  // but exclude it from current beta PASS; current negative boundaries live in evidence-recovery.spec.ts.
  test.skip('migrated recovery race: editing a run ID while lookup is pending cannot restore a stale session',async({page})=>{
    const first='test_run_'+'d'.repeat(32);
    const second='test_run_'+'e'.repeat(32);
    const requests:string[]=[];
    await page.route('**/api/v1/test-lab/**',async route=>{
      const url=new URL(route.request().url());
      expect(url.pathname).toBe('/api/v1/test-lab/sessions/status');
      requests.push(url.searchParams.get('runId')??'');
      await new Promise(resolve=>setTimeout(resolve,220));
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({
          runId:first,state:'RUNNING',sentCount:0,nextSequence:0,
          replayMode:'single',sampleFamilyCount:1,ratePerSecond:1,maxEvents:100,
          leaseExpiresAt:new Date(Date.now()+900_000).toISOString(),
          lastSentAt:null,errorCode:null,parserLifecycleNotModified:true,
          realSensorVerified:false,runtimeParsingVerified:false,sensorIngestVerified:false,
        })});
    });
    await page.goto('/');
    await page.getByRole('button',{name:'Tools & Diagnostics'}).click();
    const panel=page.getByLabel('Authorized Test Lab session recovery');
    await panel.locator('summary').click();
    const input=panel.getByLabel('Existing authorized Test Lab run ID');
    await input.fill(first);
    await panel.getByRole('button',{name:'Look Up My Authorized Run'}).click();
    await expect.poll(()=>requests.length).toBe(1);
    await input.fill(second);
    await page.waitForTimeout(300);
    await expect(page.getByLabel('Active Test Lab session indicator')).toHaveCount(0);
    await expect(panel.getByLabel('Recovered Test Lab result')).toHaveCount(0);
    await expect(panel.getByRole('button',{name:'Look Up My Authorized Run'})).toBeEnabled();
    expect(requests).toEqual([first]);
  });

  // OWNER-REMOVED: preserve previous authorization scenario for potential future scope,
  // but exclude it from current beta PASS; current negative boundaries live in evidence-recovery.spec.ts.
  test.skip('migrated expired status: a verified terminal run cannot offer Stop, Resume, or sensor transmission',async({page})=>{
    const runId='test_run_'+'c'.repeat(32);
    const calls:string[]=[];
    await page.route('**/api/v1/test-lab/**',route=>{
      const path=new URL(route.request().url()).pathname;
      calls.push(path);
      expect(path).toBe('/api/v1/test-lab/sessions/status');
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({
          runId,state:'EXPIRED',sentCount:0,nextSequence:0,replayMode:'single',
          sampleFamilyCount:1,ratePerSecond:1,maxEvents:100,
          leaseExpiresAt:new Date(Date.now()-900_000).toISOString(),lastSentAt:null,errorCode:null,
          parserLifecycleNotModified:true,realSensorVerified:false,
          runtimeParsingVerified:false,sensorIngestVerified:false,
        })});
    });
    await page.goto('/?workspace=chatgpt');
    await page.getByRole('button',{name:'Tools & Diagnostics'}).click();
    const panel=page.getByLabel('Authorized Test Lab session recovery');
    await panel.locator('summary').click();
    await panel.getByLabel('Existing authorized Test Lab run ID').fill(runId);
    await panel.getByRole('button',{name:'Look Up My Authorized Run'}).click();
    await expect(panel.getByLabel('Authorized terminal Test Lab session'))
      .toContainText('EXPIRED');
    await expect(panel.getByLabel('Recovered Test Lab result')).toContainText('finished run');
    await expect(page.getByLabel('Active Test Lab session indicator')).toHaveCount(0);
    await expect(page.getByRole('button',{name:'Stop Server Session Now'})).toHaveCount(0);
    expect(calls).toEqual(['/api/v1/test-lab/sessions/status']);
  });

  // OWNER-REMOVED: preserve previous authorization scenario for potential future scope,
  // but exclude it from current beta PASS; current negative boundaries live in evidence-recovery.spec.ts.
  test.skip('migrated Test Lab and Interflow: independent authorizations reject forged readback, never send a real packet',async({page})=>{
    const runId='test_run_'+'a'.repeat(32);
    const mockStatus={
      runId,state:'RUNNING',sentCount:0,nextSequence:0,replayMode:'single',
      sampleFamilyCount:1,ratePerSecond:1,maxEvents:100,
      leaseExpiresAt:new Date(Date.now()+45_000).toISOString(),lastSentAt:null,errorCode:null,
      parserLifecycleNotModified:true,realSensorVerified:false,
      runtimeParsingVerified:false,sensorIngestVerified:false,
    };
    const grants={
      liveSensorSenderEnabled:true,trustedSinkSessionControlAvailable:true,
      sessionControlRequiresBackendAuthorization:true,
      serverInjectedUdpTcpSinkAvailable:true,sinkRequiresIpLiteralAllowlist:true,
      sinkRequiresPerDeliveryPolicyAndAudit:true,
      sessionRenewalRequiresSeparateApproval:true,sessionDurableAcrossRestart:false,
      sessionMaxRatePerSecond:5,sessionMaxLeaseMs:900000,
      sessionMaxAdditionalEventsPerRenewal:3000,sessionMaxCumulativeEvents:300000,
      sensorIngestVerified:false,runtimeParsingVerified:false,
      interflowReadClientAvailable:true,interflowBoundedPollingAvailable:true,
      interflowMaxPollAttempts:6,interflowMaxPollWindowMs:15000,
      interflowCursorVerified:false,interflowSearchPermissionsVerified:false,
      interflowRealTargetVerified:false,
    };
    const targetCalls:string[]=[];
    let syntheticStarts=0,reads=0,stopDenials=0,rateRequests=0,renewRequests=0;
    let responseKind:'denied'|'forged'|'safe'='denied';
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
 await analyzeAndReview(page);
    await enterCreateParser(page);
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');

    // Interception is installed only AFTER actual backend compilation. This is
    // a browser-only synthetic authorization fixture, not a tenant/sensor grant.
    await page.route('**/api/v1/parser-pairs/capabilities',async route=>{
      const real=await route.fetch();
      const cap=await real.json() as {testLab?:Record<string,unknown>};
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({...cap,testLab:{...cap.testLab,...grants}})});
    });
    await page.route('**/api/v1/test-lab/**',route=>{
      const path=new URL(route.request().url()).pathname;
      targetCalls.push(path);
      if(path==='/api/v1/test-lab/sessions/start'){
        syntheticStarts++;
        expect(route.request().method()).toBe('POST');
        const body=route.request().postData()??'';
        expect(body).toContain('owner-approved-test-001');
        expect(body).toContain('example.invalid/synthetic');
        expect(body).not.toContain('198.51.100.10');
        expect(body).not.toContain('203.0.113.5');
        expect(body).not.toContain('sensorIp');
        expect(body).not.toContain('dpUrl');
        return route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify(mockStatus)});
      }
      if(path==='/api/v1/test-lab/sessions/rate'){
        rateRequests++;
        expect(route.request().method()).toBe('POST');
        const submitted=route.request().postDataJSON() as Record<string,unknown>;
        expect(submitted).toMatchObject({runId,ratePerSecond:2});
        expect(Object.keys(submitted).sort()).toEqual(['approvalId','ratePerSecond','runId']);
        const raw=route.request().postData()??'';
        for(const forbidden of ['198.51.100.10','203.0.113.5','apiKey','sensorIp','dpUrl']){
          expect(raw).not.toContain(forbidden);
        }
        if(rateRequests===1)return route.fulfill({status:403,
          contentType:'application/json',body:JSON.stringify({error:'RATE_DENIED'})});
        expect(submitted.approvalId).toBe('independent-rate-2');
        return route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify({...mockStatus,ratePerSecond:2})});
      }
      if(path==='/api/v1/test-lab/sessions/renew'){
        renewRequests++;
        expect(route.request().method()).toBe('POST');
        const submitted=route.request().postDataJSON() as Record<string,unknown>;
        expect(Object.keys(submitted).sort()).toEqual([
          'additionalEvents','approvalId','leaseMs','runId']);
        expect(submitted).toMatchObject({runId,leaseMs:60000,additionalEvents:20});
        const raw=route.request().postData()??'';
        for(const forbidden of ['198.51.100.10','203.0.113.5','apiKey','sensorIp','dpUrl']){
          expect(raw).not.toContain(forbidden);
        }
        if(renewRequests===1)return route.fulfill({status:403,
          contentType:'application/json',body:JSON.stringify({error:'RENEWAL_DENIED'})});
        expect(submitted.approvalId).toBe('independent-quota-2');
        return route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify({...mockStatus,ratePerSecond:2,maxEvents:120,
            leaseExpiresAt:new Date(Date.now()+60_000).toISOString()})});
      }
      if(path==='/api/v1/test-lab/interflow/search'){
        reads++;
        expect(route.request().method()).toBe('POST');
        const body=route.request().postDataJSON() as {
          runId:string;index:string;expectedFields:Record<string,string>;limit:number;
        };
        expect(body).toMatchObject({runId,index:'syslog',limit:20,
          expectedFields:{action:'allow'}});
        if(responseKind==='denied')return route.fulfill({status:403,
          contentType:'application/json',body:JSON.stringify({error:'NO_TENANT_GRANT'})});
        if(responseKind==='forged')return route.fulfill({status:200,
          contentType:'application/json',
          body:JSON.stringify({
            state:'MATCHED_RESPONSE_FIELDS',matchCount:1,
            fields:[{field:'action',status:'MATCH',raw:'PRIVATE_VENDOR_VALUE_NEVER_ECHO'}],
            sensorReceivedVerified:true,endToEndVerified:true,
            runtimeParsingVerified:true,targetImportVerified:true,
            rawLog:'PRIVATE_VENDOR_VALUE_NEVER_ECHO',
          })});
        return route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify({
            state:'NO_MATCH',matchCount:0,
            fields:[{field:'action',status:'MISSING'}],
            sensorReceivedVerified:false,endToEndVerified:false,
            runtimeParsingVerified:false,targetImportVerified:false,
          })});
      }
      if(path==='/api/v1/test-lab/sessions/stop'){
        expect(route.request().postDataJSON()).toEqual({runId});
        if(stopDenials++===0)return route.fulfill({status:403,
          contentType:'application/json',
          body:JSON.stringify({error:'STOP_BACKEND_DENIED'})});
        return route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify({...mockStatus,state:'STOPPED'})});
      }
      return route.fulfill({status:403,contentType:'application/json',
        body:JSON.stringify({error:'TEST_ROUTE_DEFAULT_DENY'})});
    });
    const tools=page.getByLabel('Authorized test and Interflow verification');
    await tools.locator('summary').first().click();
    await expect(tools.getByLabel('Interflow field comparison after approved replay')).toHaveCount(0);
    await tools.getByRole('button',{name:'Check Sensor Test Authorization'}).click();
    const launch=tools.getByRole('button',{name:'Start Approved Synthetic Session'});
    await expect(launch).toBeDisabled();
    await tools.getByLabel('Sensor replay approval reference').fill('owner-approved-test-001');
    await expect(launch).toBeDisabled();
    await tools.getByLabel('Confirm independent sensor test approval').check();
    await expect(launch).toBeEnabled();
    await launch.click();
    await expect(tools.getByLabel('Verified synthetic session status')).toContainText('RUNNING');
    await expect(tools.getByLabel('Verified synthetic session status')).toContainText('Sensor ingest NOT VERIFIED');
    expect(syntheticStarts).toBe(1);
    const limits=tools.getByLabel('Approved Test Lab quota and rate controls');
    await limits.locator('summary').click();
    const updateRate=limits.getByRole('button',{name:'Change Approved Replay Rate'});
    const extend=limits.getByRole('button',{name:'Request Approved 60s / 20 Events'});
    await expect(updateRate).toBeDisabled();
    await expect(extend).toBeDisabled();
    await limits.getByLabel('Replay rate change approval reference')
      .fill('independent-rate-denied');
    await expect(updateRate).toBeEnabled();
    await updateRate.click();
    await expect(tools.getByRole('alert')).toContainText('Replay rate adjustment denied');
    await expect(tools.getByLabel('Verified synthetic session status'))
      .toContainText('0/100');
    await limits.getByLabel('Replay rate change approval reference')
      .fill('independent-rate-2');
    await updateRate.click();
    await expect(limits.getByLabel('Verified Test Lab limit change'))
      .toContainText('Quota and lease remain unchanged');
    expect(rateRequests).toBe(2);
    await limits.getByLabel('Quota renewal approval reference')
      .fill('independent-quota-denied');
    await extend.click();
    await expect(tools.getByRole('alert')).toContainText('Quota extension denied');
    await expect(tools.getByLabel('Verified synthetic session status'))
      .toContainText('0/100');
    await limits.getByLabel('Quota renewal approval reference')
      .fill('independent-quota-2');
    await extend.click();
    await expect(limits.getByLabel('Verified Test Lab limit change'))
      .toContainText('exactly 20 additional events');
    await expect(tools.getByLabel('Verified synthetic session status'))
      .toContainText('0/120');
    expect(renewRequests).toBe(2);
    const comparison=tools.getByLabel('Interflow field comparison after approved replay');
    await comparison.locator('summary').click();
    const read=comparison.getByRole('button',{name:'Read Authorized Interflow Comparison'});
    await expect(read).toBeDisabled();
    expect(reads).toBe(0);
    await comparison.getByLabel('Confirm independent Interflow read authorization').check();
    await read.click();
    await expect(comparison.getByRole('alert')).toContainText('No E2E result is claimed');
    responseKind='forged';
    await read.click();
    await expect(comparison.getByRole('alert')).toContainText('No E2E result is claimed');
    await expect(comparison.getByRole('status')).toHaveCount(0);
    expect(await comparison.innerText()).not.toContain('PRIVATE_VENDOR_VALUE_NEVER_ECHO');
    responseKind='safe';
    await read.click();
    await expect(comparison.getByRole('status')).toContainText('NO_MATCH');
    await expect(comparison.getByRole('status')).toContainText('end-to-end NOT VERIFIED');
    expect(reads).toBe(3);
    await expect(page.getByLabel('Active Test Lab session indicator'))
      .toContainText('Changing screens does not stop server delivery');
    await page.getByRole('complementary',{name:'Parser Studio navigation'})
      .getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
    await expect(page.getByLabel('Authorized test and Interflow verification')).toHaveCount(0);
    await expect(page.getByLabel('Active Test Lab session indicator'))
      .toContainText('RUNNING');
    await page.getByLabel('Active Test Lab session indicator')
      .getByRole('button',{name:'Stop Server Session Now'}).click();
    await expect(page.getByLabel('Active Test Lab session indicator'))
      .toContainText('Backend Stop is unconfirmed');
    await expect(page.getByLabel('Active Test Lab session indicator'))
      .toContainText('RUNNING');
    await page.getByLabel('Active Test Lab session indicator')
      .getByRole('button',{name:'Stop Server Session Now'}).click();
    await expect(page.getByLabel('Active Test Lab session indicator')).toHaveCount(0);
    expect(targetCalls).toEqual([
      '/api/v1/test-lab/sessions/start',
      '/api/v1/test-lab/sessions/rate',
      '/api/v1/test-lab/sessions/rate',
      '/api/v1/test-lab/sessions/renew',
      '/api/v1/test-lab/sessions/renew',
      '/api/v1/test-lab/interflow/search',
      '/api/v1/test-lab/interflow/search',
      '/api/v1/test-lab/interflow/search',
      '/api/v1/test-lab/sessions/stop',
      '/api/v1/test-lab/sessions/stop',
    ]);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });

  test('removed local replay cannot send events or resurrect drafts during navigation',async({page})=>{
    const replaySource=sample.replace('198.51.100.10','10.0.0.10')
      .replace('203.0.113.5','10.0.0.11');
    const calls:string[]=[];
    page.on('request',request=>{
      const path=new URL(request.url()).pathname;
      if(path.startsWith('/api/v1/')&&request.method()==='POST')calls.push(path);
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(replaySource);
    await analyzeAndReview(page);
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await enterCreateParser(page);
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    await expect(page.getByLabel('Generated parser files'))
      .toContainText('Parser files created successfully');
    const accepted=[...calls];
    // The removed advanced replay control cannot be used to send or to
    // generate a fake native/device verification result.
    await expect(page.getByLabel('Local synthetic replay preview')).toBeHidden();
    await expect(page.getByRole('button',{name:'Start Local Preview'})).toHaveCount(0);
    await expect(page.getByLabel('Local synthetic replay output')).toHaveCount(0);
    // Normal local Multi-Pass analysis uses a loopback preview-batch POST.
    // It is not a sensor, device, or external transport operation.
    expect(accepted.every(path=>path.startsWith('/api/v1/parser-pairs/')||
      path==='/api/v1/multipass/preview-batch')).toBe(true);
    const generatedCount=accepted.filter(path=>path.endsWith('/generate')).length;
    await returnToReviewFields(page);
    await page.getByRole('button',{name:'Back to Logs'}).click();
    await page.getByLabel('Auto Parser raw logs').fill(replaySource+'\n{"action":"allow"}');
    await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
    // Editing source may cause local reanalysis, but cannot regenerate stale
    // DRAFT files or initiate target/sensor operations.
    expect(calls.filter(path=>path.endsWith('/generate')).length).toBe(generatedCount);
    expect(calls.some(path=>path.includes('/target/apply')||
      path.includes('/sessions/start')||path.includes('/interflow'))).toBe(false);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });

});
