import {test,expect,type Page} from '@playwright/test';
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

  test('same synthetic sample: UI preview → typed project → real validate/generate → Ruby/CONF/ZIP SHA → exact reinspection',async({page,request})=>{
    const payloads:Record<string,unknown>={};
    const apiCalls:string[]=[];
    page.on('request',req=>{
      const path=new URL(req.url()).pathname;
      if(req.method()==='POST'&&['validate','generate','package','inspect'].some(x=>path.endsWith('/'+x))){
        apiCalls.push(path.split('/').at(-1)!);
        if(path.endsWith('/validate')||path.endsWith('/generate'))payloads[path.split('/').at(-1)!]=req.postDataJSON();
        expect(req.url()).toContain('127.0.0.1:');
        expect(req.headers()['authorization']).toBeUndefined();
      }
    });

    await page.goto('/?workspace=guided');
    await page.getByLabel('Guided raw sample logs').fill(sample);
    await page.getByRole('button',{name:/2\. Extract Fields/}).click();
    await page.getByRole('button',{name:'JSON',exact:true}).click();
    await page.getByRole('button',{name:/3\. Map Fields/}).click();
    await page.locator('.guided-schema-guide summary').click();
    await page.getByRole('button',{name:'Fetch Backend Schema (GET)'}).click();
    await expect(page.getByLabel('Verified backend schema summary')).toContainText('ParserProject');

    await page.getByRole('button',{name:/5\. Test & Fix/}).click();
    await page.getByRole('button',{name:'Run Full Browser Test'}).click();
    await expect(page.locator('.guided-test-metrics')).toContainText('Input Events');
    await expect(page.locator('.guided-test-metrics')).toContainText('2');
    await page.getByRole('button',{name:/6\. Generate Files/}).click();
    await expect(page.getByRole('button',{name:'Generate 2 Parser Files (Backend Required)'})).toBeDisabled();
    const validResponse=page.waitForResponse(r=>r.url().endsWith('/validate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Validate Backend Input'}).click();
    expect((await validResponse).status()).toBe(200);
    await expect(page.getByText('Schema PASS · Engine Unverified')).toBeVisible();
    expect(payloads.validate).toMatchObject({
      schemaRevision:'0.1',revision:1,extraction:{format:'json'},
    });
    const json=JSON.stringify(payloads.validate);
    expect(json).not.toContain('198.51.100.10');
    expect(json).not.toContain('203.0.113.5');
    expect(json).not.toContain('"src_ip":"198.51.100.10"');
    expect(json).not.toContain('apiKey');

    const generated=page.waitForResponse(r=>r.url().endsWith('/generate')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Generate 2 Parser Files (DRAFT)'}).click();
    const real=await generated;
    expect(real.status()).toBe(200);
    const pair=await real.json();
    expect(payloads.generate).toEqual(payloads.validate);
    expect(pair.contract).toBe('host-customized-pair.v0.1');
    expect(pair.files).toHaveLength(2);
    expect(pair.manifest).toMatchObject({
      status:'DRAFT',engineVerified:false,targetImportVerified:false,
      projectId:'draft-demo_firewall',projectRevision:1,
    });
    expect(pair.files.map((x:{name:string})=>x.name)).toEqual([
      'customized_demo_firewall.conf','customized_demo_firewall',
    ]);
    const byName:Record<string,string>={};
    for(const file of pair.files){
      expect(file.sha256).toMatch(SHA);
      expect(sha(file.content)).toBe(file.sha256);
      expect(Buffer.byteLength(file.content)).toBe(file.bytes);
      expect(pair.manifest.fileHashes[file.name]).toBe(file.sha256);
      byName[file.name]=file.content;
    }
    await expect(page.getByLabel('Generated draft parser pair')).toContainText('SHA-256 Verified');
    for(const file of pair.files){
      const downloaded=page.waitForEvent('download');
      await page.getByRole('button',{name:file.name,exact:true}).click();
      const item=await downloaded;
      expect(item.suggestedFilename()).toBe(file.name);
      expect(sha(await readFile(await item.path()))).toBe(file.sha256);
    }
    expect(byName['customized_demo_firewall.conf']).toContain('port 7501');
    expect(byName['customized_demo_firewall']).toContain('STELLAR_PARSE_BEGIN');

    const zipResponse=page.waitForResponse(r=>r.url().endsWith('/package')&&r.request().method()==='POST');
    const zipDownload=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download DRAFT ZIP Package'}).click();
    const archive=await zipResponse;
    const downloadedZip=await zipDownload;
    expect(archive.status()).toBe(200);
    expect(downloadedZip.suggestedFilename()).toBe('customized_demo_firewall-r1.zip');
    const zipBuffer=await readFile(await downloadedZip.path());
    expect(zipBuffer.subarray(0,4).toString('hex')).toBe('504b0304');
    expect(sha(zipBuffer)).toBe(archive.headers()['x-parser-zip-sha256']);
    expect(archive.headers()['x-parser-listener-port']).toBe('7501');
    expect(archive.headers()['x-parser-artifact-revision']).toMatch(SHA);
    await expect(page.getByLabel('Draft ZIP integrity receipt')).toContainText('SHA-256 Verified');
    // Reopen via the actual backend API and verify exact compiler reproduction,
    // not a browser-only mock or a raw Ruby import.
    await page.locator('.guided-pair-inspect summary').click();
    await page.getByLabel('Inspect pair CONF').setInputFiles({
      name:'customized_demo_firewall.conf',mimeType:'text/plain',
      buffer:Buffer.from(byName['customized_demo_firewall.conf']),
    });
    await page.getByLabel('Inspect pair Ruby fragment').setInputFiles({
      name:'customized_demo_firewall',mimeType:'text/plain',
      buffer:Buffer.from(byName['customized_demo_firewall']),
    });
    const inspectResponse=page.waitForResponse(r=>r.url().endsWith('/inspect')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Inspect Selected Pair (Read-only)'}).click();
    expect((await inspectResponse).status()).toBe(200);
    await expect(page.getByLabel('Parser pair inspection results')).toContainText('Byte-for-byte Generator Match');
    expect(apiCalls).toEqual(['validate','generate','package','inspect']);

    await page.getByRole('button',{name:/1\. Import Logs/}).click();
    await page.getByLabel('Guided raw sample logs').fill(sample+'\n{"action":"allow","src_ip":"192.0.2.7","dst_port":80}');
    await page.getByRole('button',{name:/6\. Generate Files/}).click();
    await expect(page.getByLabel('Generated draft parser pair')).toHaveCount(0);
    await expect(page.getByRole('button',{name:'Generate 2 Parser Files (Backend Required)'})).toBeDisabled();
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

  test('tampered REAL backend generated response is refused by the UI, without a file or deployment',async({page})=>{
    let realCalls=0;
    await page.route('**/api/v1/parser-pairs/generate',async route=>{
      const original=await route.fetch();
      expect(original.status()).toBe(200);
      realCalls++;
      const pair=await original.json();
      pair.files[0].sha256='0'.repeat(64);
      await route.fulfill({response:original,contentType:'application/json',body:JSON.stringify(pair)});
    });
    await page.goto('/?workspace=guided');
    await page.getByLabel('Guided raw sample logs').fill(sample);
    await page.getByRole('button',{name:/2\. Extract Fields/}).click();
    await page.getByRole('button',{name:'JSON',exact:true}).click();
    await page.getByRole('button',{name:/5\. Test & Fix/}).click();
    await page.getByRole('button',{name:'Run Full Browser Test'}).click();
    await page.getByRole('button',{name:/6\. Generate Files/}).click();
    await page.getByRole('button',{name:'Validate Backend Input'}).click();
    await expect(page.getByText('Schema PASS · Engine Unverified')).toBeVisible();
    await page.getByRole('button',{name:'Generate 2 Parser Files (DRAFT)'}).click();
    await expect(page.getByRole('alert').last()).toContainText('SHA-256');
    await expect(page.getByLabel('Generated draft parser pair')).toHaveCount(0);
    expect(realCalls).toBe(1);
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
    for(const filename of ['customized_demo_firewall.conf','customized_demo_firewall']){
      const download=page.waitForEvent('download');
      await page.getByLabel('Generated Auto Parser DRAFT pair').getByRole('button',{name:filename,exact:true}).click();
      const result=await download;
      expect(result.suggestedFilename()).toBe(filename);
      const bytes=await readFile(await result.path());
      expect(bytes.byteLength).toBeGreaterThan(0);
    }
    expect(actions).toEqual(['validate','generate']);
    await page.getByLabel('Test and Generate stage').getByRole('button',{name:'Review Results'}).click();
    await page.getByRole('button',{name:'Back to Logs'}).click();
    await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(sample);
    await page.getByLabel('Auto Parser raw logs').fill(sample+'\n{"action":"allow","src_ip":"192.0.2.8","dst_port":80}');
    await expect(page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button',{name:/Test & Generate/})).toBeDisabled();
  });

});
