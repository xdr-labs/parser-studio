import {test,expect} from '@playwright/test';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';

const root=resolve('tests/fixtures/docs-practice-20261104');
const evidence=process.env.PARSER_STUDIO_DOC_AUTHORING_EVIDENCE_FILE ||
  resolve('test-results/docs-practice-full-authoring-20261104.jsonl');
const matrix=[
  {file:'01-juniper-srx.log',vendor:'Juniper',product:'SRX',relay:false},
  {file:'04-fortigate-traffic.log',vendor:'Fortinet',product:'FortiGate',relay:false},
  {file:'04-fortigate-threat.log',vendor:'Fortinet',product:'FortiGate',relay:false},
  {file:'05-relay-forwarded.log',vendor:'Fortinet',product:'FortiGate',relay:true},
  {file:'05-relay-holdout.log',vendor:'Fortinet',product:'FortiGate',relay:true},
  {file:'06-panos-traffic-issue.log',vendor:'Palo Alto',product:'PAN-OS',relay:false},
] as const;
test.skip((process.env.PARSER_STUDIO_BROWSER_BACKEND!=='1'||process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1'),
  'Requires a pinned real local backend, not a capability mock.');
for(const item of matrix){
  test('documentation full DRAFT authoring '+item.file,async({page})=>{
    test.setTimeout(80000);
    const raw=readFileSync(resolve(root,item.file),'utf8');
    const jsErrors:string[]=[];
    page.on('pageerror',e=>jsErrors.push(e.message));
    const generated:string[]=[];
    page.on('response',r=>{
      if(r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST')
        generated.push(r.status()+'');
    });
    await page.goto('/');
    await page.getByLabel('Parser manufacturer').fill(item.vendor);
    await page.getByLabel('Parser product',{exact:true}).fill(item.product);
    await page.getByLabel('Auto Parser raw logs').fill(raw.trimEnd());
    if(item.relay){
      const declaration=page.locator('details[aria-label="Review declared relay hosts"]');
      await declaration.locator('summary').click();
      await declaration.getByLabel('Declared relay hostname list').fill('relay01');
      await expect(declaration.getByRole('button',{name:'Apply declared relay profile'})).toBeEnabled();
      await declaration.getByRole('button',{name:'Apply declared relay profile'}).click();
    }
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const review=page.getByRole('button',{name:'Review Fields',exact:true});
    await expect(review).toBeEnabled({timeout:25000});
    await review.click();
    await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
    const map=page.getByLabel('Map Fields stage');
    await expect(map).toBeVisible();
    const mappings=await map.locator('.normalization-map-row').evaluateAll(rows=>rows.map(row=>{
      const source=row.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null;
      const target=row.querySelector('input[aria-label^="Stellar field "],input[aria-label^="Vendor field "]') as HTMLInputElement|null;
      return {source:source?.value||'',target:target?.value||'',official:row.classList.contains('verified')};
    }));
    const check=(source:string,target:string,official:boolean)=>{
      const candidate=mappings.find(r=>r.source===source||r.source==='parserstudio_source.'+source);
      expect(candidate,'missing source '+source).toBeDefined();
      if(official)expect(candidate).toMatchObject({target,official:true});
      else expect(candidate!.official,'vendor source '+source+' must not become standard').toBe(false);
    };
    if(item.file==='01-juniper-srx.log'){
      check('syslog_sd.element_1.params.source-address','srcip',true);
      check('syslog_sd.element_1.params.destination-address','dstip',true);
      check('syslog_sd.element_1.params.protocol-id','proto',true);
      check('syslog_sd.element_1.params.policy-name','rule.name',true);
      check('syslog_sd.element_1.params.nat-source-address','',false);
    }
    if(item.file.startsWith('04-')||item.file.startsWith('05-')){
      check('srcip','srcip',true);
      check('dstip','dstip',true);
      check('policyid','fw_policy_id',true);
      check('type','',false);
      if(item.file.includes('traffic')||item.file.includes('forwarded')){
        check('duration','',false);
      }
    }
    if(item.file.startsWith('06-')){
      check('syslog.severity','',false);
      check('generic.fields.type','',false);
      check('generic.fields.src','srcip',true);
      check('generic.fields.dst','dstip',true);
    }
    const buildButton=map.getByRole('button',{name:'Create Parser',exact:true});
    await expect(buildButton).toBeEnabled();
    await buildButton.click();
    await expect(page.getByLabel('Create Parser stage')).toBeVisible();
    const response=page.waitForResponse(r=>
      r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST',
      {timeout:35000});
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    const result=await response;
    const status=result.status();
    const record:Record<string,unknown>={file:item.file,backendStatus:status,
      fieldMappings:mappings.filter(row=>row.official),generated,jsErrors};
    if(status===200){
      const pair=await result.json() as {manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean},
        files:Array<{name:string;sha256:string;content:string}>};
      expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
      expect(pair.files).toHaveLength(2);
      for(const f of pair.files){
        expect(createHash('sha256').update(f.content).digest('hex')).toBe(f.sha256);
      }
      record.files=pair.files.map(f=>({name:f.name,sha256:f.sha256}));
      await expect(page.getByLabel('Generated parser files')).toBeVisible();
    }else{
      record.error=(await result.text()).slice(0,600);
    }
    writeFileSync(evidence,JSON.stringify(record)+'\n',{flag:'a'});
    console.log('DOC_AUTHORING_RESULT '+JSON.stringify(record).slice(0,850));
    expect(jsErrors).toEqual([]);
    expect(status,'Authoring should create a DRAFT pair from '+item.file).toBe(200);
  });
}