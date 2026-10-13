import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {createDraft} from '../src/model';
import {toBackendProject} from '../src/guided/backendAdapter';

const SHA=/^[a-f0-9]{64}$/;
const sha=(data:string|Uint8Array)=>createHash('sha256').update(data).digest('hex');
const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

test.describe('actual Chromium UI ↔ exact pinned loopback backend, no mocked API',()=>{
  test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1',
    'Real integration requires an exact backend HEAD checkout and localhost isolation.');

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
    expect(cap.downloads.ownedOfflineRevisionHttpAvailableWhenInjected).toBe(true);
    expect(cap.downloads.revisionRestorePreviewNeverWritesTarget).toBe(true);
    expect(cap.authoring.multiline).toBe(false);
    expect(cap.verification.engineVerified).toBe(false);
    expect(cap.verification.targetImportVerified).toBe(false);
    expect(cap.verification.nativeCapabilityManifestEnabledByDefault).toBe(false);

    const guarded=[
      '/api/v1/parser-pairs/native-capability-manifest',
      '/api/v1/parser-pairs/revisions/list?projectId=draft-demo_firewall',
      '/api/v1/parser-pairs/target/apply/status?artifactRevisionId='+'a'.repeat(64),
      '/api/v1/test-lab/sessions/evidence-summary?runId=test_run_'+'b'.repeat(32),
    ];
    for(const path of guarded){
      const denied=await request.get(path);
      expect(denied.status(),path).toBe(403);
      const result=await denied.json();
      expect(result.error).toMatch(/DENIED|DISABLED/);
      expect(JSON.stringify(result)).not.toContain('apiKey');
      expect(JSON.stringify(result)).not.toContain('private');
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await expect(page.getByLabel('Review Results stage')).toBeVisible();
    await page.getByLabel('Review Results stage')
      .getByRole('button',{name:/Test & Generate/}).click();
    const generation=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
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
      await page.getByLabel('Generated Auto Parser DRAFT pair')
        .getByRole('button',{name:f.name,exact:true}).click();
      expect(sha(await readFile(await (await download).path()))).toBe(f.sha256);
    }
    expect(pair.files[0].content).toContain('port 7501');
    expect(pair.files[1].content).toContain('STELLAR_PARSE_BEGIN');
    const packageResponse=page.waitForResponse(r=>
      r.url().endsWith('/parser-pairs/package')&&r.request().method()==='POST');
    const packageDownload=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download Verified DRAFT ZIP'}).click();
    const zip=await packageResponse;
    expect(zip.status()).toBe(200);
    const bytes=await readFile(await (await packageDownload).path());
    expect(bytes.subarray(0,4).toString('hex')).toBe('504b0304');
    expect(sha(bytes)).toBe(zip.headers()['x-parser-zip-sha256']);
    expect(calls).toEqual(['validate','generate','package']);
    await page.getByLabel('Test and Generate stage')
      .getByRole('button',{name:'Review Results'}).click();
    await page.getByRole('button',{name:'Back to Logs'}).click();
    await page.getByLabel('Auto Parser raw logs').fill(sample+'\n{"action":"deny"}');
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair')).toHaveCount(0);
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
    expect(foreign.status()).toBe(403);
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await page.getByLabel('Review Results stage')
      .getByRole('button',{name:/Test & Generate/}).click();
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
    await expect(page.getByLabel('Auto Parser test evidence'))
      .toContainText('Generation Not Verified');
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair')).toHaveCount(0);
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await expect(page.getByLabel('Review Results stage')).toBeVisible();
    await expect(page.getByLabel('Suggested field mappings')).toContainText('src_ip');
    await page.getByLabel('Review Results stage').getByRole('button',{name:/Test & Generate/}).click();
    await expect(page.getByLabel('Test and Generate stage')).toBeVisible();
    const generated=page.waitForResponse(r=>r.url().endsWith('/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair')).toContainText('Two DRAFT files verified');
    await page.getByLabel('ParserRecipe v0.2 review').locator('summary').click();
    await page.getByRole('button',{name:'Review Staged Recipe'}).click();
    const reviewed=page.getByLabel('Review-only staged recipe');
    await expect(reviewed).toContainText('REVIEW_ONLY');
    await expect(reviewed).toContainText('v0.2 restricted compilation needs backend capability verification');
    const recipeGenerated=page.waitForResponse(r=>r.url().includes('/recipe/v0.2/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Validate and Compile Strict v0.2 DRAFT Pair'}).click();
    expect((await recipeGenerated).status()).toBe(200);
    const nativeBounded=page.getByLabel('v0.2 exact compiler evidence');
    await expect(nativeBounded).toContainText('v0.1 pair SHA MATCHED');
    await expect(nativeBounded).toContainText('Native user parser NOT VERIFIED');
    await expect(nativeBounded).not.toContainText('198.51.100.10');
    await expect(reviewed).toContainText('parse_json');
    await expect(reviewed).not.toContainText('198.51.100.10');
    await expect(reviewed).not.toContainText('203.0.113.5');
    for(const filename of ['customized_demo_firewall.conf','customized_demo_firewall']){
      const download=page.waitForEvent('download');
      await page.getByLabel('Generated Auto Parser DRAFT pair').getByRole('button',{name:filename,exact:true}).click();
      const result=await download;
      expect(result.suggestedFilename()).toBe(filename);
      const bytes=await readFile(await result.path());
      expect(bytes.byteLength).toBeGreaterThan(0);
    }
    expect(actions).toEqual(['validate','generate','validate','generate']);
    await page.getByLabel('Test and Generate stage').getByRole('button',{name:'Review Results'}).click();
    await page.getByRole('button',{name:'Back to Logs'}).click();
    await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(sample);
    await page.getByLabel('Auto Parser raw logs').fill(sample+'\n{"action":"allow","src_ip":"192.0.2.8","dst_port":80}');
    await expect(page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button',{name:/Test & Generate/})).toBeDisabled();
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await expect(page.getByLabel('Review Results stage')).toBeVisible();
    await expect(page.getByLabel('Suggested field mappings')).toContainText('body.src');
    await page.getByLabel('Review Results stage')
      .getByRole('button',{name:/Test & Generate/}).click();
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair'))
      .toContainText('Two DRAFT files verified');
    await page.getByLabel('ParserRecipe v0.2 review').locator('summary').click();
    await page.getByRole('button',{name:'Review Staged Recipe'}).click();
    await expect(page.getByLabel('Review-only staged recipe')).toContainText('dispatch_family');
    const staged=page.waitForResponse(r=>r.url().includes('/recipe/v0.2/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Validate and Compile Strict v0.2 DRAFT Pair'}).click();
    expect((await staged).status()).toBe(200);
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('v0.1 pair SHA MATCHED');
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('Native user parser NOT VERIFIED');
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await expect(page.getByLabel('Review Results stage')).toBeVisible();
    await expect(page.getByLabel('Suggested field mappings')).toContainText('body.src_ip');
    await expect(page.getByLabel('Review Results stage')).toContainText('RFC3164 header has no year or timezone');
    await page.getByLabel('Review Results stage')
      .getByRole('button',{name:/Test & Generate/}).click();
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair'))
      .toContainText('Two DRAFT files verified');
    await page.getByLabel('ParserRecipe v0.2 review').locator('summary').click();
    await page.getByRole('button',{name:'Review Staged Recipe'}).click();
    await expect(page.getByLabel('Review-only staged recipe')).toContainText('REVIEW_ONLY');
    const staged=page.waitForResponse(r=>r.url().includes('/recipe/v0.2/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Validate and Compile Strict v0.2 DRAFT Pair'}).click();
    expect((await staged).status()).toBe(200);
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('v0.1 pair SHA MATCHED');
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('Native user parser NOT VERIFIED');
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await expect(page.getByLabel('Review Results stage')).toBeVisible();
    await expect(page.getByLabel('Suggested field mappings')).toContainText('body.src_ip');
    await page.getByLabel('Review Results stage')
      .getByRole('button',{name:/Test & Generate/}).click();
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair'))
      .toContainText('Two DRAFT files verified');
    await page.getByLabel('ParserRecipe v0.2 review').locator('summary').click();
    await page.getByRole('button',{name:'Review Staged Recipe'}).click();
    await expect(page.getByLabel('Review-only staged recipe')).toContainText('REVIEW_ONLY');
    const staged=page.waitForResponse(r=>r.url().includes('/recipe/v0.2/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Validate and Compile Strict v0.2 DRAFT Pair'}).click();
    expect((await staged).status()).toBe(200);
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('v0.1 pair SHA MATCHED');
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('Native user parser NOT VERIFIED');
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await expect(page.getByLabel('Review Results stage')).toBeVisible();
    await expect(page.getByLabel('Suggested field mappings')).toContainText('body.src');
    await expect(page.getByLabel('Review Results stage'))
      .toContainText('RFC3164 header has no year or timezone');
    await page.getByLabel('Review Results stage')
      .getByRole('button',{name:/Test & Generate/}).click();
    const generated=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair'))
      .toContainText('Two DRAFT files verified');
    await page.getByLabel('ParserRecipe v0.2 review').locator('summary').click();
    await page.getByRole('button',{name:'Review Staged Recipe'}).click();
    await expect(page.getByLabel('Review-only staged recipe')).toContainText('REVIEW_ONLY');
    const staged=page.waitForResponse(r=>r.url().includes('/recipe/v0.2/generate')&&
      r.request().method()==='POST');
    await page.getByRole('button',{name:'Validate and Compile Strict v0.2 DRAFT Pair'}).click();
    expect((await staged).status()).toBe(200);
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('v0.1 pair SHA MATCHED');
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('Native user parser NOT VERIFIED');
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
    await page.getByRole('button',{name:'Review Detected Results'}).click();
    await expect(page.getByLabel('Review Results stage')).toBeVisible();
    await expect(page.getByLabel('Suggested field mappings'))
      .toContainText('exception_class');
    await expect(page.getByLabel('Suggested field mappings'))
      .toContainText('frame_count');
    await page.getByLabel('Review Results stage')
      .getByRole('button',{name:/Test & Generate/}).click();
    const generated=page.waitForResponse(r=>
      r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Run Tests & Generate DRAFT Files'}).click();
    expect((await generated).status()).toBe(200);
    await expect(page.getByLabel('Generated Auto Parser DRAFT pair'))
      .toContainText('Two DRAFT files verified');
    await page.getByLabel('ParserRecipe v0.2 review').locator('summary').click();
    await page.getByRole('button',{name:'Review Staged Recipe'}).click();
    await expect(page.getByLabel('Review-only staged recipe')).toContainText('REVIEW_ONLY');
    const staged=page.waitForResponse(r=>
      r.url().includes('/recipe/v0.2/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Validate and Compile Strict v0.2 DRAFT Pair'}).click();
    expect((await staged).status()).toBe(200);
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('v0.1 pair SHA MATCHED');
    await expect(page.getByLabel('v0.2 exact compiler evidence'))
      .toContainText('Native user parser NOT VERIFIED');
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

  test('ChatGPT Assisted: explicit redaction -> canonical pasted JSON -> actual backend v0.1/v0.2 SHA matched pair',async({page})=>{
    const masked='{"action":"deny","src_ip":"[REDACTED_IP]"}';
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
        expect(body).not.toContain('198.51.100.10');
        expect(body).not.toContain('203.0.113.5');
        expect(body).not.toContain(masked);
      }
    });
    await page.goto('/?workspace=chatgpt');
    await page.getByLabel('ChatGPT local sample logs').fill(source);
    await page.getByLabel('ChatGPT redacted examples').fill(masked);
    await page.getByLabel('Confirm redacted example review').check();
    await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
    const textarea=page.getByLabel('ChatGPT copyable prompt');
    await expect(textarea).toContainText('Use this structurally valid current JSON recipe');
    const prompt=await textarea.inputValue();
    expect(prompt).toContain(masked);
    expect(prompt).not.toContain('198.51.100.10');
    expect(prompt).not.toContain('203.0.113.5');
    const prefix='Use this structurally valid current JSON recipe as your baseline.\n';
    const suffix='\nReturn only your JSON recipe, with nativeVerified and targetVerified false.';
    const start=prompt.indexOf(prefix),end=prompt.indexOf(suffix,start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const recipe=JSON.parse(prompt.slice(start+prefix.length,end));
    expect(recipe.compilerMode).toBe('REVIEW_ONLY');
    expect(recipe.nativeVerified).toBe(false);
    await page.getByLabel('ChatGPT pasted recipe').fill(JSON.stringify(recipe));
    await page.getByRole('button',{name:'Validate AI Result'}).click();
    await expect(page.getByLabel('ChatGPT validated recipe')).toContainText('REVIEW ONLY');
    const compiled=page.waitForResponse(r=>
      r.url().includes('/recipe/v0.2/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Approve & Generate Ruby + CONF DRAFT Files'}).click();
    expect((await compiled).status()).toBe(200);
    await expect(page.getByLabel('ChatGPT generated DRAFT pair'))
      .toContainText('Two SHA-verified DRAFT files');
    const files=page.getByLabel('ChatGPT generated DRAFT pair').getByRole('button',{name:/Download/});
    await expect(files).toHaveCount(2);
    expect(posts.filter(x=>x.endsWith('/generate')).length).toBeGreaterThanOrEqual(2);
  });

});
