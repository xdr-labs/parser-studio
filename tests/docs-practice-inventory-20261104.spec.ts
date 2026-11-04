import {test,expect} from '@playwright/test';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';

const fixtureRoot=resolve('tests/fixtures/docs-practice-20261104');
const evidenceFile=process.env.PARSER_STUDIO_DOC_EVIDENCE_FILE ||
  resolve('test-results/docs-practice-inventory-20261104.jsonl');
const fixtures=[
  {file:'01-juniper-srx.log',kind:'complete',producer:'Juniper'},
  {file:'02-sophos-xg.log',kind:'partial',producer:'Sophos'},
  {file:'03-snort-alert.log',kind:'unknown',producer:'Snort'},
  {file:'03-snort-holdout.log',kind:'unknown',producer:'Snort'},
  {file:'04-fortigate-traffic.log',kind:'complete',producer:'Fortinet'},
  {file:'04-fortigate-threat.log',kind:'complete',producer:'Fortinet'},
  {file:'05-relay-original.log',kind:'complete',producer:'Fortinet'},
  {file:'05-relay-forwarded.log',kind:'relay',producer:'Fortinet'},
  {file:'05-relay-holdout-original.log',kind:'complete',producer:'Fortinet'},
  {file:'05-relay-holdout.log',kind:'relay',producer:'Fortinet'},
  {file:'06-panos-traffic-issue.log',kind:'review',producer:'Palo Alto'},
  {file:'07-elasticsearch-java-error.log',kind:'multiline',producer:'Elastic'},
] as const;
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
function inputs(text:string){return text.replace(/\n$/, '');}
function save(obj:Record<string,unknown>){
  writeFileSync(evidenceFile,JSON.stringify(obj)+'\n',{flag:'a'});
}
test.describe('actual published Parser Studio documentation practice corpus',()=>{
  test.skip((process.env.PARSER_STUDIO_BROWSER_BACKEND!=='1'||process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1'),
    'Requires the exact-pinned local full authoring backend.');
  for(const item of fixtures){
    test(item.file+' real Chromium novice analysis and field mapping inventory',async({page})=>{
      test.setTimeout(80000);
      const text=inputs(readFileSync(resolve(fixtureRoot,item.file),'utf8'));
      const errors:string[]=[];
      const httpFailures:number[]=[];
      page.on('pageerror',e=>errors.push(e.message));
      page.on('response',r=>{
        if(r.url().includes('/api/')&&r.status()>=500)httpFailures.push(r.status());
      });
      await page.goto('/');
      await page.getByLabel('Parser manufacturer').fill(item.producer);
      await page.getByLabel('Parser product',{exact:true}).fill(item.producer+' documented scenario');
      await page.getByLabel('Auto Parser raw logs').fill(text);
      if(item.kind==='relay'){
        const relay=page.locator('details[aria-label="Review declared relay hosts"]');
        await relay.locator('summary').click();
        await relay.getByLabel('Declared relay hostname list').fill('relay01');
        await relay.getByRole('button',{name:'Apply declared relay profile'}).click();
        await expect(relay.getByLabel('Active declared relays')).toContainText('relay01');
      }
      const scan=page.getByLabel('Automatic event accounting');
      const button=page.getByRole('button',{name:'Analyze Logs',exact:true});
      await button.click();
      await expect(button).toBeEnabled({timeout:45000});
      await page.waitForTimeout(500);
      const review=page.getByRole('button',{name:'Review Fields',exact:true});
      const ready=await review.isEnabled();
      const status=await scan.innerText();
      const notes=(await page.locator('[role="alert"]').allInnerTexts()).slice(0,3).map(t=>t.slice(0,250));
      let fieldCount:number|null=null,officialCount:number|null=null,vendorCount:number|null=null;
      let mappings:Array<{source:string;target:string;group:string}>=[];
      let stage='Add Logs';
      if(ready){
        await review.click();
        stage='Review Fields';
        await expect(page.getByLabel('Review Fields stage')).toBeVisible();
        const mapBtn=page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'});
        await mapBtn.click();
        const map=page.getByLabel('Map Fields stage');
        await expect(map).toBeVisible();
        stage='Map Fields';
        const result=await map.locator('article.normalization-map-row').evaluateAll(nodes=>nodes.map(node=>{
          const source=node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null;
          const target=node.querySelector('input[aria-label^="Stellar field "],input[aria-label^="Vendor field "]') as HTMLInputElement|null;
          return {source:source?.value||'',target:target?.value||'',
            group:node.classList.contains('verified')?'official':node.classList.contains('custom')?'vendor':'review'};
        }));
        mappings=result;
        fieldCount=await map.getByLabel('Field mapping summary').locator('div').first().locator('strong').textContent().then(v=>Number(v));
        officialCount=result.filter(row=>row.group==='official').length;
        vendorCount=result.filter(row=>row.group==='vendor').length;
        if(item.file==='06-panos-traffic-issue.log'){
          // Three non-data structural bookkeeping paths are intentionally
          // excluded; the 97 source-backed values must all survive.
          expect(fieldCount).toBe(100);
          expect(result).toHaveLength(97);
        }
        if(item.file==='01-juniper-srx.log'){
          const mapped=(suffix:string)=>result.find(x=>x.source==='syslog_sd.element_1.params.'+suffix);
          expect(mapped('source-address')).toMatchObject({target:'srcip',group:'official'});
          expect(mapped('destination-address')).toMatchObject({target:'dstip',group:'official'});
          expect(mapped('policy-name')).toMatchObject({target:'rule.name',group:'official'});
          expect(mapped('protocol-id')).toMatchObject({target:'proto',group:'official'});
          expect(mapped('nat-source-address')?.group).toBe('vendor');
          expect(mapped('service-name')?.group).toBe('vendor');
        }
      }
      const result={file:item.file,kind:item.kind,bytes:Buffer.byteLength(text),
        sha256:hash(readFileSync(resolve(fixtureRoot,item.file),'utf8')),
        status:status.slice(0,220),stage,ready,fieldCount,officialCount,vendorCount,
        destinations:mappings.filter(m=>m.group==='official').map(m=>m.target),
        officialMappings:mappings.filter(m=>m.group==='official'),
        notes,errors,httpFailures};
      save(result);
      console.log('DOC_PRACTICE_RESULT '+JSON.stringify(result));
      expect(errors).toEqual([]);
      expect(httpFailures).toEqual([]);
    });
  }
});